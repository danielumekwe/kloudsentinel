#!/usr/local/cpanel/3rdparty/bin/perl
# KloudSentinel WHM plugin entry point.
#
# This is a thin, stateless reverse proxy — it holds no session state of
# its own. WHM's cpsrvd only ever invokes this script after a WHM login has
# already passed its own authentication + ACL check (this plugin is
# registered with acls=kloudsentinel in kloudsentinel.conf, so only WHM
# accounts explicitly granted that ACL reach this file at all). REMOTE_USER
# is therefore trustworthy: it is the WHM-authenticated username, set by
# cpsrvd itself, not by anything this script or the browser controls.
#
# Sentinel's API/worker are bound to 127.0.0.1 only (never reachable from
# outside this host) — this script is the only bridge between a WHM
# browser session and that internal service. See
# docs/architecture/decisions/0002-whm-plugin-internal-only-backend.md.
use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;
use Digest::SHA qw(hmac_sha256_hex);
use JSON::PP qw(decode_json);

my $SENTINEL_ENV_FILE = '/etc/sentinel/sentinel.env';
my $SESSION_COOKIE_NAME = 'sentinel_session';

sub load_sentinel_env {
    my %env;
    open(my $fh, '<', $SENTINEL_ENV_FILE) or return %env;
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*#/ || $line !~ /=/;
        my ($key, $value) = split(/=/, $line, 2);
        $env{$key} = $value;
    }
    close($fh);
    return %env;
}

sub fail {
    my ($status, $message) = @_;
    print "Status: $status\r\n";
    print "Content-Type: text/plain\r\n\r\n";
    print "KloudSentinel plugin error: $message\n";
    exit 0;
}

my %sentinel_env = load_sentinel_env();
my $shared_secret = $sentinel_env{SENTINEL_WHM_PLUGIN_SHARED_SECRET} || '';
my $backend_base_url = $sentinel_env{SENTINEL_API_BASE_URL} || 'http://127.0.0.1:8443';

my $remote_user = $ENV{REMOTE_USER} || '';
fail('403 Forbidden', 'no authenticated WHM user (REMOTE_USER is empty)') if $remote_user eq '';
fail('500 Internal Server Error', 'SENTINEL_WHM_PLUGIN_SHARED_SECRET is not configured — re-run install.sh')
    if $shared_secret eq '';

my $ua = LWP::UserAgent->new(timeout => 30);

# Every cookie the browser already has for this WHM host, forwarded
# through as-is — this is how the browser's ordinary sentinel_session
# cookie (once set) reaches the backend on every subsequent click, with no
# state kept in this CGI process between invocations.
my $incoming_cookie = $ENV{HTTP_COOKIE} || '';
my ($session_cookie_value) = $incoming_cookie =~ /(?:^|;\s*)\Q$SESSION_COOKIE_NAME\E=([^;]+)/;

my @new_cookie_headers;
if (!defined $session_cookie_value) {
    # No bridged session yet (first visit, or the previous one expired
    # client-side) — mint one by calling Sentinel's internal-only
    # /dashboard/whm-session endpoint, HMAC-signed so Sentinel can trust
    # this call genuinely came from this CGI script and not some other
    # process on the box that happens to reach 127.0.0.1.
    my $timestamp = time();
    my $signature = hmac_sha256_hex("$remote_user:$timestamp", $shared_secret);

    my $bridge_request = HTTP::Request->new(POST => "$backend_base_url/dashboard/whm-session");
    $bridge_request->header('X-Sentinel-WHM-User'      => $remote_user);
    $bridge_request->header('X-Sentinel-WHM-Timestamp' => $timestamp);
    $bridge_request->header('X-Sentinel-WHM-Signature' => $signature);

    my $bridge_response = $ua->request($bridge_request);
    fail('502 Bad Gateway', 'could not establish a Sentinel session: ' . $bridge_response->status_line)
        unless $bridge_response->is_success;

    my $bridge_data = decode_json($bridge_response->decoded_content);
    $session_cookie_value = $bridge_data->{session_token};
    push @new_cookie_headers, "$SESSION_COOKIE_NAME=$session_cookie_value; Path=/; HttpOnly";
}

# Standard CGI PATH_INFO: for a request to
# /cgi/kloudsentinel/index.cgi/threats, PATH_INFO is "/threats" — this is
# how every dashboard sub-page maps through this one registered CGI entry.
my $path_info = $ENV{PATH_INFO} || '';
my $query_string = $ENV{QUERY_STRING} || '';
my $target_url = "$backend_base_url/dashboard$path_info";
$target_url .= "?$query_string" if $query_string ne '';

my $method = $ENV{REQUEST_METHOD} || 'GET';
my $proxied_request = HTTP::Request->new($method => $target_url);
$proxied_request->header('Cookie' => "$SESSION_COOKIE_NAME=$session_cookie_value");
if ($ENV{CONTENT_TYPE}) {
    $proxied_request->header('Content-Type' => $ENV{CONTENT_TYPE});
}
if ($method eq 'POST' || $method eq 'PUT') {
    my $content_length = $ENV{CONTENT_LENGTH} || 0;
    my $body = '';
    read(STDIN, $body, $content_length) if $content_length > 0;
    $proxied_request->content($body);
}

my $response = $ua->request($proxied_request);

print 'Status: ' . $response->code . ' ' . $response->message . "\r\n";
for my $header_name ($response->header_field_names) {
    # Hop-by-hop headers are for the LWP<->backend leg only; everything
    # else (including any Set-Cookie the backend itself issued, e.g. on
    # logout) is passed straight through to the browser.
    next if $header_name =~ /^(?:Connection|Transfer-Encoding|Content-Length)$/i;
    for my $value ($response->header($header_name)) {
        print "$header_name: $value\r\n";
    }
}
for my $cookie_header (@new_cookie_headers) {
    print "Set-Cookie: $cookie_header\r\n";
}
print "\r\n";
print $response->content;

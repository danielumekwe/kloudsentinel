// No framework, no build step — just a confirmation prompt for the one
// irreversible action the dashboard exposes (permanently deleting a
// quarantined file). Every other action (restore, acknowledge, run scan,
// logout) is a plain form POST that needs no JavaScript at all.
document.addEventListener("submit", (event) => {
  const form = event.target;
  const message = form.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

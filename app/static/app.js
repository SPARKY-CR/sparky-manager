/* vpn-panel — small vanilla JS. Core flows work without JS;
   this only adds copy-to-clipboard, delete confirmation and
   show/hide password. No framework, no fetch. */
(function () {
  "use strict";

  // Copy buttons: <button data-copy="text to copy">
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy") || "";
      var done = function () {
        var original = btn.textContent;
        btn.textContent = btn.getAttribute("data-copied-label") || "✓";
        setTimeout(function () { btn.textContent = original; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
      } else {
        fallbackCopy(text);
        done();
      }
    });
  });

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* clipboard unavailable */ }
    document.body.removeChild(ta);
  }

  // Delete confirmation: <form data-confirm="message">
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  // Show/hide password: <button data-toggle-password="input-id">
  document.querySelectorAll("[data-toggle-password]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.getAttribute("data-toggle-password"));
      if (!input) return;
      if (!btn.dataset.originalLabel) btn.dataset.originalLabel = btn.textContent;
      var showing = input.type === "text";
      input.type = showing ? "password" : "text";
      btn.textContent = showing ? btn.dataset.originalLabel : "•••";
    });
  });
})();

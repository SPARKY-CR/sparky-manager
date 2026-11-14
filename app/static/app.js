/* sparky-manager — small vanilla JS. Core flows work without JS;
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

  // Add-inbound form: an empty port means "auto-generate" — send 0
  // so the server picks a free port instead of failing validation.
  var inboundForm = document.getElementById("add-inbound-form");
  if (inboundForm) {
    inboundForm.addEventListener("submit", function () {
      var port = document.getElementById("inbound-port");
      if (port && port.value === "") port.value = "0";
    });
  }

  // Inbounds table filter: search by tag, filter by protocol/status.
  // All client-side; the table rows carry data-tag / data-protocol /
  // data-status attributes. Without JS the full table just shows.
  var inboundSearch = document.getElementById("inbound-search");
  var inboundTable = document.getElementById("inbounds-table");
  if (inboundSearch && inboundTable) {
    var protoFilter = document.getElementById("filter-protocol");
    var statusFilter = document.getElementById("filter-status");
    var emptyRow = document.getElementById("filter-empty");
    var applyInboundFilter = function () {
      var q = inboundSearch.value.trim().toLowerCase();
      var proto = protoFilter ? protoFilter.value : "";
      var status = statusFilter ? statusFilter.value : "";
      var visible = 0;
      inboundTable.querySelectorAll("tbody tr[data-tag]").forEach(function (row) {
        var ok = (!q || row.getAttribute("data-tag").indexOf(q) !== -1)
          && (!proto || row.getAttribute("data-protocol") === proto)
          && (!status || row.getAttribute("data-status") === status);
        row.hidden = !ok;
        if (ok) visible += 1;
      });
      if (emptyRow) emptyRow.hidden = visible !== 0;
    };
    inboundSearch.addEventListener("input", applyInboundFilter);
    if (protoFilter) protoFilter.addEventListener("change", applyInboundFilter);
    if (statusFilter) statusFilter.addEventListener("change", applyInboundFilter);
  }

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

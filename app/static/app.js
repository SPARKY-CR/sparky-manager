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

  // Same, but per submit button: <button type="submit"
  // data-confirm="message"> — used by the bulk-delete button, whose
  // form has other (harmless) actions that need no confirmation.
  document.querySelectorAll("button[data-confirm]").forEach(function (btn) {
    btn.addEventListener("click", function (event) {
      var message = btn.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  // Bulk select-all: the header checkbox toggles every row checkbox
  // in the users table. Without JS the admin checks rows by hand.
  var selectAll = document.getElementById("select-all-users");
  if (selectAll) {
    selectAll.addEventListener("change", function () {
      document.querySelectorAll("input[name=\"user_ids\"]").forEach(function (box) {
        box.checked = selectAll.checked;
      });
    });
  }

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

  // Inbound editor: show only the sections that apply to the chosen
  // security / transport. Progressive enhancement only — without JS
  // every section stays visible and the form still submits.
  var editForm = document.getElementById("edit-inbound-form");
  if (editForm) {
    var security = document.getElementById("edit-security");
    var network = document.getElementById("edit-network");
    var realitySection = document.getElementById("section-reality");
    var tlsSection = document.getElementById("section-tls");
    var applyEditVisibility = function () {
      var sec = security ? security.value : "";
      if (realitySection) realitySection.hidden = sec !== "reality";
      // The TLS section is also shown (without the security select)
      // for the always-TLS protocols — there security is absent and
      // the section must stay visible.
      if (tlsSection && security) tlsSection.hidden = sec !== "tls";
      var net = network ? network.value : "tcp";
      var show = function (id, visible) {
        var el = document.getElementById(id);
        if (el) el.hidden = !visible;
      };
      show("field-path", net === "ws" || net === "xhttp" || net === "httpupgrade");
      show("field-host", net === "ws" || net === "httpupgrade");
      show("field-service-name", net === "grpc");
      show("field-mode", net === "xhttp");
    };
    if (security) security.addEventListener("change", applyEditVisibility);
    if (network) network.addEventListener("change", applyEditVisibility);
    applyEditVisibility();
  }

  // Sidebar collapse (desktop, Phase 4): icons-only sidebar,
  // persisted in localStorage. Without JS the sidebar stays
  // expanded — the toggle is an enhancement, not a requirement.
  var shell = document.querySelector(".app-shell");
  var collapseBtn = document.getElementById("sidebar-collapse");
  if (shell && collapseBtn) {
    var setCollapsed = function (collapsed) {
      shell.classList.toggle("sidebar-collapsed", collapsed);
      var label = collapsed
        ? collapseBtn.getAttribute("data-expand-label")
        : collapseBtn.getAttribute("data-collapse-label");
      if (label) {
        collapseBtn.setAttribute("title", label);
        collapseBtn.setAttribute("aria-label", label);
      }
      try {
        window.localStorage.setItem(
          "sparky-sidebar-collapsed", collapsed ? "1" : "0");
      } catch (e) { /* storage unavailable — session-only state */ }
    };
    try {
      if (window.localStorage.getItem("sparky-sidebar-collapsed") === "1") {
        setCollapsed(true);
      }
    } catch (e) { /* storage unavailable */ }
    collapseBtn.addEventListener("click", function () {
      setCollapsed(!shell.classList.contains("sidebar-collapsed"));
    });
  }

  // Mobile drawer (Phase 4): the drawer also opens via :target
  // (the hamburger links to #sidebar), so it works without JS.
  // With JS, the class-based state adds overlay/Escape closing and
  // keeps the URL hash clean.
  var drawerOpen = document.getElementById("drawer-open");
  var drawerClose = document.getElementById("drawer-close");
  var drawerOverlay = document.getElementById("drawer-overlay");
  var setDrawer = function (open) {
    document.body.classList.toggle("drawer-open", open);
    if (drawerOpen) drawerOpen.setAttribute("aria-expanded", open ? "true" : "false");
  };
  if (drawerOpen) {
    drawerOpen.addEventListener("click", function (event) {
      event.preventDefault();
      setDrawer(true);
    });
  }
  var closeDrawer = function (event) {
    if (event) event.preventDefault();
    setDrawer(false);
  };
  if (drawerClose) drawerClose.addEventListener("click", closeDrawer);
  if (drawerOverlay) drawerOverlay.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") setDrawer(false);
  });

  // Settings tabs (Phase 4): the tab links are real links
  // (?section=…) so they work without JS (server renders the
  // active panel). With JS, switching happens in place and the
  // URL is updated for bookmarkability.
  var tabs = document.querySelector(".tabs");
  if (tabs) {
    var links = tabs.querySelectorAll(".tab-link");
    var panels = tabs.querySelectorAll(".tab-panel");
    var activate = function (section) {
      links.forEach(function (link) {
        var on = link.getAttribute("data-section") === section;
        link.classList.toggle("active", on);
        link.setAttribute("aria-selected", on ? "true" : "false");
      });
      panels.forEach(function (panel) {
        panel.hidden = panel.getAttribute("data-panel") !== section;
      });
    };
    links.forEach(function (link) {
      link.addEventListener("click", function (event) {
        var section = link.getAttribute("data-section");
        if (!section) return;
        event.preventDefault();
        activate(section);
        try {
          var url = new URL(window.location.href);
          url.searchParams.set("section", section);
          window.history.replaceState(null, "", url.toString());
        } catch (e) { /* URL API unavailable — tab still switched */ }
      });
    });
  }
})();

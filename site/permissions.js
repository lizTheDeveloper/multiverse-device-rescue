(function () {
  "use strict";

  var OS_LABELS = {
    macos: "macOS",
    windows: "Windows",
    linux: "Linux"
  };

  var container = document.getElementById("permissions-content");
  var tabs = document.querySelectorAll(".os-tab");
  var data = null;
  var activeOs = "macos";

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  }

  function renderOs(osKey) {
    if (!container) return;

    if (!data) {
      container.innerHTML = '<p class="error">Sorry — the walkthrough couldn\'t be loaded right now.</p>';
      return;
    }

    var steps = data[osKey];
    if (!steps || !steps.length) {
      container.innerHTML =
        '<p class="empty">No walkthrough steps for ' + escapeHtml(OS_LABELS[osKey] || osKey) + " yet.</p>";
      return;
    }

    var html = '<ol class="permission-steps">';
    steps.forEach(function (step) {
      html += '<li class="permission-step">';
      html += '<h3 class="permission-step-title">' + escapeHtml(step.title) + "</h3>";
      html += '<p class="permission-step-body">' + escapeHtml(step.body) + "</p>";
      if (step.setting_url && step.action_label) {
        html +=
          '<a class="permission-step-action" href="' +
          escapeHtml(step.setting_url) +
          '">' +
          escapeHtml(step.action_label) +
          "</a>";
      }
      html += "</li>";
    });
    html += "</ol>";

    container.innerHTML = html;
  }

  function setActiveOs(osKey) {
    activeOs = osKey;
    tabs.forEach(function (tab) {
      var isActive = tab.getAttribute("data-os") === osKey;
      tab.classList.toggle("is-active", isActive);
      tab.setAttribute("aria-selected", isActive ? "true" : "false");
    });
    renderOs(osKey);
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      setActiveOs(tab.getAttribute("data-os"));
    });
  });

  fetch("permissions-content.json")
    .then(function (res) {
      if (!res.ok) throw new Error("Failed to load permissions-content.json");
      return res.json();
    })
    .then(function (json) {
      data = json;
      setActiveOs(activeOs);
    })
    .catch(function () {
      data = null;
      renderOs(activeOs);
    });
})();

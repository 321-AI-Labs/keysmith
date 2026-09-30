"""The complete static dashboard shell: one DOCUMENT constant (hand-
written HTML, inline CSS design tokens, inline vanilla JavaScript).

Laws this module obeys:

* ZERO data. The document is byte-identical for every client on every
  server: no config, no spend, no token, no URLs are baked in. Panels
  fill at runtime from the JSON API routes, so nothing is emitted here
  that redaction would need to chase.
* EVERY user-visible string comes from ui_strings (naming law): the HTML
  carries ``data-t`` hooks and the JavaScript reads the one JSON blob
  embedded from ``ui_strings.PAGE_TEXT``. No prose lives in tags or JS.
* Fully offline (charter scope item 6): no external requests of any
  kind, no CDN, no web fonts; system font stack only. This is machine-
  checked by tests (no ``http``-prefixed attribute values, no
  ``src=``/``href=`` resource loads beyond in-page anchors).
* Vanilla JS only; dynamic values render via textContent, never
  innerHTML, so config-derived strings (trusted input, but still) are
  inserted as text, not markup.
* ASCII only, no em dashes (polish bar).
"""

from __future__ import annotations

import json

from . import ui_strings

_T = ui_strings.PAGE_TEXT

_CSS = """
:root {
  --bg: #0f1115;
  --bg-raised: #171a21;
  --bg-inset: #12141a;
  --border: #2a2f3c;
  --border-soft: #222733;
  --text: #e8eaf0;
  --muted: #9aa3b5;
  --accent: #7aa2f7;
  --accent-strong: #8fb2ff;
  --ok: #9ece6a;
  --warn: #e0af68;
  --danger: #f7768e;
  --mono: ui-monospace, "Cascadia Mono", Consolas, "Courier New", monospace;
  --radius: 10px;
  --radius-small: 6px;
  --shadow: 0 8px 28px rgba(0, 0, 0, 0.45);
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html, body { margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 15px;
  line-height: 1.55;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
a { color: var(--accent); }
.skip-link {
  position: absolute; left: -9999px; top: 0;
  background: var(--bg-raised); color: var(--text);
  padding: 8px 14px; border-radius: 0 0 var(--radius-small) 0; z-index: 30;
}
.skip-link:focus { left: 0; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 3px; }
header.top {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 14px 22px; border-bottom: 1px solid var(--border-soft);
  background: var(--bg-inset);
  position: sticky; top: 0; z-index: 10;
}
.brand { display: flex; align-items: baseline; gap: 10px; }
.brand-name { font-size: 20px; font-weight: 700; letter-spacing: 0.4px; }
.brand-sub { color: var(--muted); font-size: 13px; }
.header-right { display: flex; align-items: center; gap: 10px; }
.chip {
  display: inline-block; padding: 2px 10px; font-size: 12px; border-radius: 999px;
  border: 1px solid var(--border); color: var(--muted); background: var(--bg-raised);
}
.chip.ok { color: var(--ok); border-color: rgba(158, 206, 106, 0.45); }
.chip.warn { color: var(--warn); border-color: rgba(224, 175, 104, 0.45); }
.chip.bad { color: var(--danger); border-color: rgba(247, 118, 142, 0.45); }
main { flex: 1; width: 100%; max-width: 1060px; margin: 0 auto; padding: 22px; }
footer { padding: 18px 22px; border-top: 1px solid var(--border-soft); }
.fine { color: var(--muted); font-size: 12.5px; }
.lead { color: var(--muted); margin: 4px 0 0 0; }
.note { color: var(--muted); font-size: 12.5px; margin: 2px 0 0 0; }
h1 { font-size: 22px; margin: 0 0 4px 0; }
h2 { font-size: 19px; margin: 0; }
h3 { font-size: 15.5px; margin: 0 0 8px 0; }
.login-wrap { display: flex; justify-content: center; padding-top: 8vh; }
.login-card {
  background: var(--bg-raised); border: 1px solid var(--border);
  border-radius: var(--radius); box-shadow: var(--shadow);
  padding: 26px 28px; width: 100%; max-width: 460px;
}
.login-card form { display: flex; flex-direction: column; gap: 10px; margin-top: 14px; }
label { font-size: 13.5px; color: var(--muted); display: block; }
input[type="text"], input[type="password"], select, textarea {
  width: 100%; background: var(--bg-inset); color: var(--text);
  border: 1px solid var(--border); border-radius: var(--radius-small);
  padding: 9px 11px; font-size: 14.5px; font-family: inherit;
}
input:focus-visible, select:focus-visible, textarea:focus-visible, button:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 1px;
}
textarea { font-family: var(--mono); font-size: 13px; min-height: 74px; resize: vertical; }
.btn {
  background: var(--bg-raised); color: var(--text);
  border: 1px solid var(--border); border-radius: var(--radius-small);
  padding: 8px 16px; font-size: 14px; font-family: inherit; cursor: pointer;
}
.btn:hover { border-color: var(--accent); }
.btn.primary { background: var(--accent); border-color: var(--accent); color: #0c0f16; font-weight: 600; }
.btn.primary:hover { background: var(--accent-strong); }
.btn.ghost { background: transparent; }
.btn.danger { color: var(--danger); }
.btn.small { padding: 4px 10px; font-size: 12.5px; }
.btn[disabled] { opacity: 0.55; cursor: not-allowed; }
.form-error { color: var(--danger); font-size: 13.5px; margin: 10px 0 0 0; }
.form-ok { color: var(--ok); font-size: 13.5px; margin: 10px 0 0 0; }
.tabs { display: flex; gap: 6px; border-bottom: 1px solid var(--border-soft); margin-bottom: 18px; flex-wrap: wrap; }
.tab {
  background: transparent; border: 1px solid transparent; border-bottom: none;
  color: var(--muted); padding: 9px 16px; font-size: 14.5px; font-family: inherit;
  cursor: pointer; border-radius: var(--radius-small) var(--radius-small) 0 0;
}
.tab[aria-selected="true"] {
  color: var(--text); background: var(--bg-raised); border-color: var(--border-soft);
  border-bottom: 2px solid var(--accent);
}
.tab:hover { color: var(--text); }
.panel { padding: 4px 0 18px 0; }
.panel-head { margin-bottom: 14px; }
.panel-state {
  border: 1px dashed var(--border); border-radius: var(--radius);
  padding: 26px 20px; text-align: center; color: var(--muted); margin-top: 8px;
}
.panel-state.error { color: var(--danger); border-color: rgba(247, 118, 142, 0.5); }
.panel-state .btn { margin-top: 10px; }
.counts { color: var(--muted); font-size: 13.5px; margin: 6px 0 0 0; }
.card {
  background: var(--bg-raised); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 18px 20px; margin-bottom: 14px;
}
.card .mono, code.mono, pre.mono { font-family: var(--mono); }
.kv { display: grid; grid-template-columns: 170px 1fr; gap: 4px 14px; margin: 10px 0; }
.kv dt { color: var(--muted); font-size: 13px; }
.kv dd { margin: 0; font-size: 14px; overflow-wrap: anywhere; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border-soft); }
th { color: var(--muted); font-weight: 600; font-size: 12.5px; white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: none; }
td.mono, .mono { font-family: var(--mono); font-size: 12.8px; }
.status-chip { margin-left: 8px; }
.keys-list { display: flex; flex-direction: column; gap: 5px; }
.key-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.summary-grid {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin-bottom: 16px;
}
.summary-card {
  background: var(--bg-raised); border: 1px solid var(--border);
  border-radius: var(--radius); padding: 12px 14px;
}
.summary-card .value { font-size: 20px; font-weight: 700; font-variant-numeric: tabular-nums; }
.summary-card .label { color: var(--muted); font-size: 12px; }
.controls { display: flex; gap: 12px; align-items: end; flex-wrap: wrap; margin: 4px 0 12px 0; }
.controls .field { display: flex; flex-direction: column; gap: 4px; }
.controls input, .controls select { width: 220px; }
.table-wrap { overflow-x: auto; }
pre.curl {
  background: var(--bg-inset); border: 1px solid var(--border);
  border-radius: var(--radius-small); padding: 12px 14px;
  font-family: var(--mono); font-size: 12.3px; white-space: pre-wrap; overflow-wrap: anywhere;
  margin: 6px 0;
}
.endpoint-line {
  display: flex; align-items: center; gap: 10px; background: var(--bg-inset);
  border: 1px solid var(--border); border-radius: var(--radius-small);
  padding: 9px 12px; margin: 6px 0;
}
.endpoint-line code { font-size: 12.8px; overflow-wrap: anywhere; }
.endpoint-line .btn { margin-left: auto; }
fieldset.provider {
  border: 1px solid var(--border); border-radius: var(--radius);
  padding: 14px 16px; margin: 0 0 16px 0;
  display: grid; grid-template-columns: 1fr 1fr; gap: 12px 16px;
}
fieldset.provider legend { color: var(--muted); font-size: 13px; padding: 0 6px; }
fieldset.provider .span-2 { grid-column: 1 / -1; }
.field-label { font-size: 13px; color: var(--muted); display: block; margin-bottom: 4px; }
.field-help { font-size: 12px; color: var(--muted); margin-top: 3px; }
.provider-head { grid-column: 1 / -1; display: flex; align-items: end; gap: 12px; flex-wrap: wrap; }
.provider-head .field-grow { flex: 1; min-width: 180px; }
.result-box { margin-top: 14px; }
.result-box ul { margin: 8px 0 0 0; padding-left: 20px; }
.result-box li { color: var(--danger); font-size: 13.5px; }
.result-box.ok-message { color: var(--ok); font-size: 13.5px; }
.sr-only {
  position: absolute; width: 1px; height: 1px; margin: -1px;
  clip: rect(0 0 0 0); clip-path: inset(50%); overflow: hidden; white-space: nowrap;
}
.warn-banner {
  border: 1px solid rgba(224, 175, 104, 0.5); color: var(--warn);
  border-radius: var(--radius); padding: 12px 14px; margin-bottom: 14px; font-size: 13.5px;
}
@media (max-width: 720px) {
  fieldset.provider { grid-template-columns: 1fr; }
  .kv { grid-template-columns: 1fr; }
}
"""

# Static skeleton. Every visible text node is a data-t hook filled from
# ui_strings.PAGE_TEXT at page init, so this markup itself carries no
# prose (naming law). data-t-placeholder / data-t-title fill attributes.
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title data-t="documentTitle">keysmith</title>
<style>__CSS__</style>
</head>
<body>
<a class="skip-link" href="#main" data-t="skipToContent"></a>
<header class="top">
  <div class="brand">
    <span class="brand-name">keysmith</span>
    <span class="brand-sub" data-t="headerSubtitle"></span>
  </div>
  <div class="header-right">
    <span id="live-chip" class="chip" data-t="liveChip"></span>
    <button id="logout" class="btn ghost small" type="button" data-t="logoutButton" data-t-title="logoutHint"></button>
  </div>
</header>
<main id="main">

<section id="login" class="login-wrap" aria-labelledby="login-heading">
  <div class="login-card">
    <h1 id="login-heading" data-t="loginHeading"></h1>
    <p class="lead" data-t="loginLead"></p>
    <form id="login-form" novalidate>
      <div>
        <label for="login-token" data-t="loginLabel"></label>
        <input id="login-token" type="password" autocomplete="off" spellcheck="false" data-t-placeholder="loginPlaceholder">
      </div>
      <button id="login-submit" type="submit" class="btn primary" data-t="loginButton"></button>
    </form>
    <p id="login-error" class="form-error" role="alert" hidden></p>
    <p class="fine" data-t="loginMemoryNote"></p>
  </div>
</section>

<div id="app" hidden>
  <nav class="tabs" role="tablist" aria-label="keysmith">
    <button class="tab" role="tab" type="button" id="tab-status" aria-controls="panel-status" aria-selected="true" data-t="navStatus"></button>
    <button class="tab" role="tab" type="button" id="tab-spend" aria-controls="panel-spend" aria-selected="false" tabindex="-1" data-t="navSpend"></button>
    <button class="tab" role="tab" type="button" id="tab-connect" aria-controls="panel-connect" aria-selected="false" tabindex="-1" data-t="navConnect"></button>
    <button class="tab" role="tab" type="button" id="tab-setup" aria-controls="panel-setup" aria-selected="false" tabindex="-1" data-t="navSetup"></button>
  </nav>

  <section id="panel-status" class="panel" role="tabpanel" aria-labelledby="tab-status" tabindex="0">
    <div class="panel-head">
      <h2 data-t="statusHeading"></h2>
      <p class="lead" data-t="statusLead"></p>
      <p class="note" data-t="updatesNote"></p>
    </div>
    <p id="status-counts" class="counts"></p>
    <div id="status-state" class="panel-state" hidden></div>
    <div id="status-body"></div>
  </section>

  <section id="panel-spend" class="panel" role="tabpanel" aria-labelledby="tab-spend" tabindex="0" hidden>
    <div class="panel-head">
      <h2 data-t="spendHeading"></h2>
      <p class="lead" data-t="spendLead"></p>
      <p class="note" data-t="updatesNote"></p>
    </div>
    <div id="spend-state" class="panel-state" hidden></div>
    <div id="spend-body">
      <div id="spend-summary" class="summary-grid"></div>
      <div class="controls">
        <div class="field">
          <label for="spend-filter" data-t="spendFilterLabel"></label>
          <input id="spend-filter" type="text" data-t-placeholder="spendFilterPlaceholder">
        </div>
        <div class="field">
          <label for="spend-status-filter" data-t="spendStatusFilterLabel"></label>
          <select id="spend-status-filter">
            <option value="all" data-t="spendStatusAll"></option>
            <option value="ok" data-t="spendStatusOk"></option>
            <option value="failed" data-t="spendStatusFailed"></option>
          </select>
        </div>
      </div>
      <p id="spend-capped" class="note" hidden></p>
      <div id="spend-table-wrap" class="table-wrap"></div>
      <p id="spend-nomatch" class="note" hidden data-t="spendNoMatch"></p>
      <div id="spend-totals"></div>
    </div>
  </section>

  <section id="panel-connect" class="panel" role="tabpanel" aria-labelledby="tab-connect" tabindex="0" hidden>
    <div class="panel-head">
      <h2 data-t="connectHeading"></h2>
      <p class="lead" data-t="connectLead"></p>
      <p class="note" data-t="updatesNote"></p>
    </div>
    <div id="connect-state" class="panel-state" hidden></div>
    <div id="connect-body"></div>
    <p class="fine" data-t="connectTokenNote"></p>
  </section>

  <section id="panel-setup" class="panel" role="tabpanel" aria-labelledby="tab-setup" tabindex="0" hidden>
    <div class="panel-head">
      <h2 data-t="setupHeading"></h2>
      <p class="lead" data-t="setupLead"></p>
    </div>
    <div id="setup-writable-warning" class="warn-banner" hidden data-t="setupWritableFalse"></div>
    <p id="setup-path" class="note"></p>
    <div id="setup-state" class="panel-state" hidden></div>
    <div id="setup-body">
      <div class="field span-2" style="margin-bottom:14px">
        <label class="field-label" for="setup-comment" data-t="setupCommentLabel"></label>
        <textarea id="setup-comment" rows="2"></textarea>
      </div>
      <h3 data-t="setupProvidersLabel"></h3>
      <div id="setup-providers"></div>
      <button id="setup-add" type="button" class="btn" data-t="setupAddProvider"></button>
      <div class="controls" style="margin-top:16px">
        <button id="setup-preview" type="button" class="btn primary" data-t="setupPreview"></button>
        <button id="setup-write" type="button" class="btn" data-t="setupWrite"></button>
      </div>
      <div id="setup-result" class="result-box" aria-live="polite"></div>
    </div>
  </section>
</div>
</main>
<footer><p class="fine" data-t="footerNote"></p></footer>
<script type="application/json" id="ui-strings">__PAGE_TEXT_JSON__</script>
<script>
__SCRIPT__
</script>
</body>
</html>
"""

_SCRIPT = r"""
(function () {
  "use strict";
  var T = {};
  try {
    T = JSON.parse(document.getElementById("ui-strings").textContent);
  } catch (e) { T = {}; }
  var POLL_MS = 3000;

  function el(id) { return document.getElementById(id); }
  function fmt(template, values) {
    return String(template).replace(/\{(\w+)\}/g, function (m, key) {
      return Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : m;
    });
  }
  function text(node, value) { node.textContent = value; return node; }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } return node; }
  function fmtInt(n) { return Number(n || 0).toLocaleString("en-US"); }
  function fmtDash(v) { return (v === null || v === undefined) ? "-" : fmtInt(v); }
  function fmtMs(v) { return (Math.round(Number(v || 0) * 10) / 10) + " ms"; }
  function fmtTime(ts) {
    var d = new Date(ts);
    return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
  }

  // ---- static text fill (naming law: all prose comes from T) --------
  function applyText() {
    var nodes = document.querySelectorAll("[data-t]");
    var i;
    for (i = 0; i < nodes.length; i++) {
      var key = nodes[i].getAttribute("data-t");
      if (Object.prototype.hasOwnProperty.call(T, key)) { text(nodes[i], T[key]); }
    }
    var ph = document.querySelectorAll("[data-t-placeholder]");
    for (i = 0; i < ph.length; i++) {
      ph[i].setAttribute("placeholder", T[ph[i].getAttribute("data-t-placeholder")] || "");
    }
    var ti = document.querySelectorAll("[data-t-title]");
    for (i = 0; i < ti.length; i++) {
      ti[i].setAttribute("title", T[ti[i].getAttribute("data-t-title")] || "");
    }
    if (T.htmlLang) { document.documentElement.setAttribute("lang", T.htmlLang); }
  }

  // ---- state ---------------------------------------------------------
  var state = { token: null, tab: "status", pollTimer: null, spend: null, connections: null, wizardLoaded: false };
  var PANELS = {
    status: { state: el("status-state"), body: el("status-body"), refresh: refreshStatus },
    spend: { state: el("spend-state"), body: el("spend-body"), refresh: refreshSpend },
    connect: { state: el("connect-state"), body: el("connect-body"), refresh: refreshConnections },
    setup: { state: el("setup-state"), body: el("setup-body"), refresh: refreshWizardCurrent }
  };

  function setPanelState(name, kind, message) {
    var slot = PANELS[name].state;
    clear(slot);
    if (!kind) { slot.hidden = true; slot.classList.remove("error"); return; }
    slot.hidden = false;
    slot.classList.toggle("error", kind === "error");
    if (kind === "loading") { text(slot, T.stateLoading || "Loading..."); }
    else { text(slot, message || ""); }
    if (kind === "error") {
      var retry = document.createElement("button");
      retry.type = "button";
      retry.className = "btn small";
      text(retry, T.stateRetry || "Retry");
      retry.addEventListener("click", function () { loadPanel(name); });
      slot.appendChild(document.createElement("br"));
      slot.appendChild(retry);
    }
  }
  function loadPanel(name) {
    setPanelState(name, "loading");
    return PANELS[name].refresh();
  }
  function panelFail(name, err) {
    if (err && err.auth) { return; }
    setPanelState(name, "error", (T.stateErrorPrefix || "") + errorMessage(err));
  }
  function errorMessage(err) {
    if (err && err.status) {
      var data = err.data;
      if (data && data.error && data.error.message) { return data.error.message; }
      if (data && data.parseError) { return "HTTP " + err.status + ": " + String(data.parseError).slice(0, 200); }
      return "HTTP " + err.status;
    }
    return String(err);
  }

  // ---- live chip -------------------------------------------------------
  function setLive(ok) {
    var chip = el("live-chip");
    chip.className = "chip " + (ok ? "ok" : "bad");
    text(chip, ok ? (T.liveChip || "live") : (T.liveChipError || "offline"));
  }

  // ---- API -------------------------------------------------------------
  function api(method, path, body) {
    var headers = { "Authorization": "Bearer " + state.token };
    var init = { method: method, headers: headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(path, init).then(function (resp) {
      if (resp.status === 401) {
        enterLogin(true);
        throw { auth: true };
      }
      return resp.text().then(function (raw) {
        var data = null;
        if (raw) {
          try { data = JSON.parse(raw); } catch (e) { data = { parseError: raw }; }
        }
        return { status: resp.status, data: data };
      });
    });
  }

  // ---- login / logout ---------------------------------------------------
  function enterLogin(showBadToken) {
    stopPolling();
    state.token = null;
    state.wizardLoaded = false;
    var err = el("login-error");
    if (showBadToken) {
      text(err, T.loginBadToken || "");
      err.hidden = false;
    } else { err.hidden = true; }
    el("app").hidden = true;
    el("login").hidden = false;
    var btn = el("login-submit");
    text(btn, T.loginButton || "");
    btn.disabled = false;
    setLive(false);
    el("login-token").focus();
  }
  function bootApp() {
    el("login").hidden = true;
    el("app").hidden = false;
    setLive(true);
    loadPanel("status");
    loadPanel("spend");
    loadPanel("connect");
    startPolling();
  }
  function stopPolling() {
    if (state.pollTimer !== null) { clearInterval(state.pollTimer); state.pollTimer = null; }
  }
  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(function () {
      if (!state.token) { return; }
      ["status", "spend", "connect"].forEach(function (name) {
        PANELS[name].refresh().catch(function (err) { panelFail(name, err); });
      });
    }, POLL_MS);
  }

  // ---- tabs -------------------------------------------------------------
  var TAB_IDS = ["status", "spend", "connect", "setup"];
  function activateTab(name, focus) {
    state.tab = name;
    TAB_IDS.forEach(function (id) {
      var tab = el("tab-" + id);
      var panel = el("panel-" + id);
      var selected = id === name;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
      panel.hidden = !selected;
    });
    if (name === "setup" && !state.wizardLoaded && state.token) {
      state.wizardLoaded = true;
      loadPanel("setup");
    }
    if (focus) { el("tab-" + name).focus(); }
  }
  function wireTabs() {
    TAB_IDS.forEach(function (id) {
      el("tab-" + id).addEventListener("click", function () { activateTab(id, false); });
    });
    var tablist = document.querySelector(".tabs");
    tablist.addEventListener("keydown", function (event) {
      var index = TAB_IDS.indexOf(state.tab);
      var next = null;
      if (event.key === "ArrowRight") { next = TAB_IDS[(index + 1) % TAB_IDS.length]; }
      else if (event.key === "ArrowLeft") { next = TAB_IDS[(index - 1 + TAB_IDS.length) % TAB_IDS.length]; }
      else if (event.key === "Home") { next = TAB_IDS[0]; }
      else if (event.key === "End") { next = TAB_IDS[TAB_IDS.length - 1]; }
      if (next) { event.preventDefault(); activateTab(next, true); }
    });
  }

  // ---- small DOM helpers --------------------------------------------------
  function tag(name, className, content) {
    var node = document.createElement(name);
    if (className) { node.className = className; }
    if (content !== undefined && content !== null) { text(node, content); }
    return node;
  }
  function kv(label, valueNode) {
    var row = tag("dt", null, label);
    var cell = tag("dd");
    cell.appendChild(valueNode);
    var wrap = document.createDocumentFragment();
    wrap.appendChild(row);
    wrap.appendChild(cell);
    return wrap;
  }
  function copyButton(getText) {
    var btn = tag("button", "btn small", T.connectCopy || "Copy");
    btn.type = "button";
    btn.addEventListener("click", function () {
      copyText(getText(), btn);
    });
    return btn;
  }
  function copyText(value, btn) {
    var restore = function () {
      text(btn, T.connectCopy || "Copy");
      btn.disabled = false;
    };
    var fail = function () {
      text(btn, T.connectCopyFailed || "");
      btn.disabled = true;
      setTimeout(restore, 2500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () {
        text(btn, T.connectCopied || "");
        setTimeout(restore, 1500);
      }, function () { fallbackCopy(value, btn, fail); });
    } else { fallbackCopy(value, btn, fail); }
  }
  function fallbackCopy(value, btn, fail) {
    try {
      var box = document.createElement("textarea");
      box.value = value;
      box.setAttribute("readonly", "");
      box.style.position = "fixed";
      box.style.left = "-9999px";
      document.body.appendChild(box);
      box.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(box);
      if (ok) {
        text(btn, T.connectCopied || "");
        setTimeout(function () {
          text(btn, T.connectCopy || "Copy");
        }, 1500);
      } else { fail(); }
    } catch (e) { fail(); }
  }

  // ---- status panel ------------------------------------------------------
  function keyChip(key) {
    var chip = tag("span", "chip");
    if (key.cooling) {
      chip.classList.add("warn");
      var seconds = Math.ceil(Number(key.cooldown_remaining_seconds || 0));
      text(chip, fmt(T.statusCooldownLeft || "cooldown {s}s left", { s: seconds }));
    } else if (key.auth_failures > 0) {
      chip.classList.add("bad");
      var template = key.auth_failures === 1 ? (T.statusKeyFailures || "{n} auth failure") : (T.statusKeyFailuresPlural || "{n} auth failures");
      text(chip, fmt(template, { n: key.auth_failures }));
    } else {
      chip.classList.add("ok");
      text(chip, T.statusKeyReady || "ready");
    }
    return chip;
  }
  function renderStatus(data) {
    text(el("status-counts"), fmtInt(data.provider_count) + " " + (T.statusProviderCount || "providers") + ", " + fmtInt(data.model_count) + " " + (T.statusModelCount || "models"));
    var body = clear(el("status-body"));
    if (!data.providers.length) {
      setPanelState("status", "empty", T.statusEmpty || "");
      return;
    }
    data.providers.forEach(function (provider) {
      var card = tag("div", "card");
      card.appendChild(tag("h3", "mono", provider.id));
      var dl = tag("dl", "kv");
      dl.appendChild(kv(T.statusBaseURLLabel || "base URL", tag("span", "mono", provider.base_url)));
      var modelsWrap = tag("div");
      var table = tag("table");
      var head = tag("tr");
      head.appendChild(tag("th", null, "public"));
      head.appendChild(tag("th", null, "upstream"));
      var thead = tag("thead");
      thead.appendChild(head);
      table.appendChild(thead);
      var tbody = tag("tbody");
      provider.models.forEach(function (pair) {
        var row = tag("tr");
        row.appendChild(tag("td", "mono", pair.public));
        row.appendChild(tag("td", "mono", pair.upstream));
        tbody.appendChild(row);
      });
      table.appendChild(tbody);
      modelsWrap.appendChild(table);
      dl.appendChild(kv(T.statusModelsLabel || "models", modelsWrap));
      var keysWrap = tag("div", "keys-list");
      provider.keys.forEach(function (key) {
        var row = tag("div", "key-row");
        row.appendChild(tag("span", "mono", key.alias));
        row.appendChild(keyChip(key));
        keysWrap.appendChild(row);
      });
      if (!provider.keys.length) { keysWrap.appendChild(tag("span", "note", "-")); }
      dl.appendChild(kv(T.statusKeysLabel || "key pool", keysWrap));
      card.appendChild(dl);
      var note = tag("p", "note", T.statusAliasNote || "");
      card.appendChild(note);
      body.appendChild(card);
    });
  }
  function refreshStatus() {
    return api("GET", "/api/status").then(function (r) {
      if (r.status === 200) { setLive(true); setPanelState("status", null); renderStatus(r.data); }
      else { throw r; }
    });
  }

  // ---- spend panel -------------------------------------------------------
  function spendStatusChip(status) {
    var ok = status >= 200 && status < 400;
    var chip = tag("span", "chip " + (ok ? "ok" : "bad"), String(status));
    return chip;
  }
  function spendSummaryCard(label, value) {
    var card = tag("div", "summary-card");
    card.appendChild(tag("div", "value", value));
    card.appendChild(tag("div", "label", label));
    return card;
  }
  function totalsTable(captionKey, rows, nameKey, nameIsMono) {
    if (!rows.length) { return document.createDocumentFragment(); }
    var wrap = tag("div", "card");
    wrap.appendChild(tag("h3", null, captionKey));
    var table = tag("table");
    var thead = tag("thead");
    var head = tag("tr");
    [nameKey === "provider" ? (T.spendTableProvider || "provider") : (T.spendTableModel || "model"),
     T.spendCountColumn || "requests", T.spendOkColumn || "ok", T.spendFailedColumn || "failed",
     T.spendTokensColumn || "tokens (p / c / t)"].forEach(function (label, index) {
      var th = tag("th", index > 0 ? "num" : null, label);
      head.appendChild(th);
    });
    thead.appendChild(head);
    table.appendChild(thead);
    var tbody = tag("tbody");
    rows.forEach(function (row) {
      var tr = tag("tr");
      var name = row[nameKey] === "" && nameKey === "provider" ? (T.spendNoProvider || "(no provider)") : row[nameKey];
      tr.appendChild(tag("td", nameIsMono ? "mono" : null, name));
      tr.appendChild(tag("td", "num", fmtInt(row.requests)));
      tr.appendChild(tag("td", "num", fmtInt(row.ok)));
      tr.appendChild(tag("td", "num", fmtInt(row.failed)));
      tr.appendChild(tag("td", "num", fmtDash(row.prompt_tokens) + " / " + fmtDash(row.completion_tokens) + " / " + fmtDash(row.total_tokens)));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    return wrap;
  }
  function renderSpendRows() {
    var data = state.spend;
    if (!data) { return; }
    var wrap = clear(el("spend-table-wrap"));
    var filter = el("spend-filter").value.trim().toLowerCase();
    var statusFilter = el("spend-status-filter").value;
    var rows = (data.rows || []).filter(function (row) {
      if (filter && (row.provider + " " + row.model + " " + row.key_alias).toLowerCase().indexOf(filter) === -1) { return false; }
      var ok = row.status >= 200 && row.status < 400;
      if (statusFilter === "ok" && !ok) { return false; }
      if (statusFilter === "failed" && ok) { return false; }
      return true;
    });
    el("spend-nomatch").hidden = rows.length !== 0;
    if (!rows.length) { return; }
    var table = tag("table");
    var thead = tag("thead");
    var head = tag("tr");
    [T.spendTableWhen || "time", T.spendTableProvider || "provider", T.spendTableModel || "model",
     T.spendTableAlias || "key", T.spendTableStatus || "status", T.spendTableLatency || "latency",
     T.spendTableTokens || "tokens (prompt / completion / total)"].forEach(function (label, index) {
      head.appendChild(tag("th", index >= 4 ? "num" : null, label));
    });
    thead.appendChild(head);
    table.appendChild(thead);
    var tbody = tag("tbody");
    rows.forEach(function (row) {
      var tr = tag("tr");
      tr.appendChild(tag("td", null, fmtTime(row.ts)));
      tr.appendChild(tag("td", "mono", row.provider === "" ? (T.spendNoProvider || "(no provider)") : row.provider));
      tr.appendChild(tag("td", "mono", row.model));
      tr.appendChild(tag("td", "mono", row.key_alias === "" ? "-" : row.key_alias));
      var statusCell = tag("td", "num");
      statusCell.appendChild(spendStatusChip(row.status));
      tr.appendChild(statusCell);
      tr.appendChild(tag("td", "num", fmtMs(row.latency_ms)));
      tr.appendChild(tag("td", "num", fmtDash(row.prompt_tokens) + " / " + fmtDash(row.completion_tokens) + " / " + fmtDash(row.total_tokens)));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
  }
  function renderSpend(data) {
    state.spend = data;
    var summary = clear(el("spend-summary"));
    var totals = data.totals || {};
    summary.appendChild(spendSummaryCard(T.spendTotalRequests || "requests", fmtInt(totals.requests)));
    summary.appendChild(spendSummaryCard(T.spendOk || "ok", fmtInt(totals.ok)));
    summary.appendChild(spendSummaryCard(T.spendFailed || "failed", fmtInt(totals.failed)));
    summary.appendChild(spendSummaryCard(T.spendPromptTokens || "prompt tokens", fmtInt(totals.prompt_tokens)));
    summary.appendChild(spendSummaryCard(T.spendCompletionTokens || "completion tokens", fmtInt(totals.completion_tokens)));
    summary.appendChild(spendSummaryCard(T.spendTotalTokens || "total tokens", fmtInt(totals.total_tokens)));
    var capped = el("spend-capped");
    capped.hidden = !data.capped;
    if (data.capped) { text(capped, fmt(T.spendCappedNote || "", { shown: (data.rows || []).length, total: data.row_count })); }
    renderSpendRows();
    var totalsWrap = clear(el("spend-totals"));
    totalsWrap.appendChild(totalsTable(T.spendByProvider || "Totals by provider", data.by_provider || [], "provider", false));
    totalsWrap.appendChild(totalsTable(T.spendByModel || "Totals by model", data.by_model || [], "model", true));
  }
  function refreshSpend() {
    return api("GET", "/api/spend").then(function (r) {
      if (r.status === 200) { setPanelState("spend", null); renderSpend(r.data); }
      else { throw r; }
    });
  }

  // ---- connections panel ---------------------------------------------------
  function renderConnections(data) {
    var body = clear(el("connect-body"));
    var cards = data.cards || [];
    if (!cards.length) {
      setPanelState("connect", "empty", T.connectEmpty || "");
      return;
    }
    cards.forEach(function (card) {
      var box = tag("div", "card");
      box.appendChild(tag("h3", "mono", card.model));
      var dl = tag("dl", "kv");
      dl.appendChild(kv(T.spendTableProvider || "provider", tag("span", null, card.provider)));
      var baseNode = tag("span", "mono", card.base_url);
      dl.appendChild(kv(T.statusBaseURLLabel || "base URL", baseNode));
      box.appendChild(dl);
      var endpointLine = tag("div", "endpoint-line");
      var code = tag("code", "mono", card.endpoint);
      endpointLine.appendChild(code);
      var btn = copyButton(function () { return card.endpoint; });
      btn.setAttribute("aria-label", (T.connectEndpointLabel || "endpoint") + ": " + card.model);
      endpointLine.appendChild(btn);
      box.appendChild(endpointLine);
      box.appendChild(tag("p", "field-help", (T.connectCurlLabel || "curl example") + ":"));
      var pre = tag("pre", "curl mono", card.curl);
      box.appendChild(pre);
      var curlCopy = copyButton(function () { return card.curl; });
      curlCopy.setAttribute("aria-label", (T.connectCurlLabel || "curl example") + ": " + card.model);
      box.appendChild(curlCopy);
      body.appendChild(box);
    });
  }
  function refreshConnections() {
    return api("GET", "/api/connections").then(function (r) {
      if (r.status === 200) { setPanelState("connect", null); renderConnections(r.data); }
      else { throw r; }
    });
  }

  // ---- wizard ----------------------------------------------------------------
  function providerFieldset(initial) {
    var initial = initial || {};
    var initialModels = initial.models || {};
    var modelText = Object.keys(initialModels).sort().map(function (publicName) {
      return publicName + " = " + initialModels[publicName];
    }).join("\n");
    var fs = document.createElement("fieldset");
    fs.className = "provider";
    var legend = tag("legend", null, initial.id || "");
    fs.appendChild(legend);
    var head = tag("div", "provider-head");
    var idField = tag("div", "field-grow");
    idField.appendChild(tag("label", "field-label", T.setupIdLabel || "provider id"));
    var idInput = tag("input");
    idInput.type = "text";
    idInput.className = "wiz-id";
    idInput.value = initial.id || "";
    idInput.setAttribute("spellcheck", "false");
    idField.appendChild(idInput);
    idField.appendChild(tag("p", "field-help", T.setupIdHelp || ""));
    head.appendChild(idField);
    var baseField = tag("div", "field-grow");
    baseField.appendChild(tag("label", "field-label", T.setupBaseURLLabel || "base URL"));
    var baseInput = tag("input");
    baseInput.type = "text";
    baseInput.className = "wiz-base-url mono";
    baseInput.value = initial.base_url || "";
    baseInput.setAttribute("spellcheck", "false");
    baseField.appendChild(baseInput);
    head.appendChild(baseField);
    var remove = tag("button", "btn danger small", T.setupRemoveProvider || "Remove");
    remove.type = "button";
    remove.addEventListener("click", function () {
      fs.parentNode.removeChild(fs);
      if (!el("setup-providers").childElementCount) { el("setup-providers").appendChild(providerFieldset(null)); }
    });
    head.appendChild(remove);
    fs.appendChild(head);
    var keysField = tag("div", "span-2");
    keysField.appendChild(tag("label", "field-label", T.setupKeysLabel || "keys"));
    var keysArea = tag("textarea");
    keysArea.className = "wiz-keys";
    keysArea.value = (initial.keys || []).join("\n");
    keysField.appendChild(keysArea);
    keysField.appendChild(tag("p", "field-help", T.setupKeysHelp || ""));
    fs.appendChild(keysField);
    var modelsField = tag("div", "span-2");
    modelsField.appendChild(tag("label", "field-label", T.setupModelsLabel || "models"));
    var modelsArea = tag("textarea");
    modelsArea.className = "wiz-models";
    modelsArea.value = modelText;
    modelsField.appendChild(modelsArea);
    fs.appendChild(modelsField);
    var cooldownField = tag("div");
    cooldownField.appendChild(tag("label", "field-label", T.setupCooldownLabel || "cooldown"));
    var cooldownInput = tag("input");
    cooldownInput.type = "text";
    cooldownInput.className = "wiz-cooldown";
    cooldownInput.value = initial.cooldown_seconds === undefined ? "" : String(initial.cooldown_seconds);
    cooldownInput.setAttribute("inputmode", "decimal");
    cooldownField.appendChild(cooldownInput);
    fs.appendChild(cooldownField);
    var timeoutField = tag("div");
    timeoutField.appendChild(tag("label", "field-label", T.setupTimeoutLabel || "timeout"));
    var timeoutInput = tag("input");
    timeoutInput.type = "text";
    timeoutInput.className = "wiz-timeout";
    timeoutInput.value = initial.timeout_seconds === undefined ? "" : String(initial.timeout_seconds);
    timeoutInput.setAttribute("inputmode", "decimal");
    timeoutField.appendChild(timeoutInput);
    fs.appendChild(timeoutField);
    var insecureWrap = tag("div", "span-2");
    var insecureLabel = tag("label");
    var insecure = tag("input");
    insecure.type = "checkbox";
    insecure.className = "wiz-insecure";
    insecure.checked = !!initial.allow_insecure;
    insecureLabel.appendChild(insecure);
    insecureLabel.appendChild(document.createTextNode(" " + (T.setupInsecureLabel || "allow_insecure")));
    insecureWrap.appendChild(insecureLabel);
    fs.appendChild(insecureWrap);
    return fs;
  }
  function seedWizard(data) {
    el("setup-writable-warning").hidden = !!data.writable;
    var writeBtn = el("setup-write");
    writeBtn.disabled = !data.writable;
    if (!data.writable) { writeBtn.setAttribute("title", T.setupWriteDisabled || ""); }
    var pathLine = el("setup-path");
    text(pathLine, data.config_path ? (T.setupCurrentPath || "Config file") + ": " + data.config_path : (T.setupNoCurrentFile || ""));
    el("setup-comment").value = (data.document && typeof data.document._comment === "string") ? data.document._comment : "";
    var holders = clear(el("setup-providers"));
    var providers = (data.document && data.document.providers) || {};
    var ids = Object.keys(providers);
    if (!ids.length) { holders.appendChild(providerFieldset(null)); }
    else {
      ids.sort().forEach(function (id) {
        // The provider id is the dict KEY in providers.json; carry it
        // into the fieldset seed explicitly.
        var seeded = {};
        Object.keys(providers[id]).forEach(function (field) {
          seeded[field] = providers[id][field];
        });
        seeded.id = id;
        holders.appendChild(providerFieldset(seeded));
      });
    }
    clear(el("setup-result"));
  }
  function refreshWizardCurrent() {
    return api("GET", "/api/wizard/current").then(function (r) {
      if (r.status === 200) { setPanelState("setup", null); seedWizard(r.data); }
      else { throw r; }
    });
  }
  function gatherWizardDocument() {
    var errors = [];
    var documentOut = { providers: {} };
    var comment = el("setup-comment").value.trim();
    if (comment) { documentOut._comment = comment; }
    var seen = {};
    var fieldsets = document.querySelectorAll("#setup-providers fieldset.provider");
    fieldsets.forEach(function (fs) {
      var id = fs.querySelector(".wiz-id").value.trim();
      var base = fs.querySelector(".wiz-base-url").value.trim();
      var keysText = fs.querySelector(".wiz-keys").value;
      var modelsText = fs.querySelector(".wiz-models").value;
      var cooldownText = fs.querySelector(".wiz-cooldown").value.trim();
      var timeoutText = fs.querySelector(".wiz-timeout").value.trim();
      var insecure = fs.querySelector(".wiz-insecure").checked;
      if (!id) { errors.push(T.setupErrIdEmpty || "provider id is empty"); return; }
      if (seen[id]) { errors.push(fmt(T.setupErrIdDuplicate || "", { id: id })); return; }
      seen[id] = true;
      var provider = {};
      if (!base) { errors.push(fmt(T.setupErrBaseURLEmpty || "", { id: id })); return; }
      provider.base_url = base;
      var keys = [];
      keysText.split("\n").forEach(function (line) {
        var name = line.trim();
        if (name && keys.indexOf(name) === -1) { keys.push(name); }
      });
      if (!keys.length) { errors.push(fmt(T.setupErrKeysEmpty || "", { id: id })); return; }
      provider.keys = keys;
      var models = {};
      var modelLines = modelsText.split("\n");
      var sawModel = false;
      modelLines.forEach(function (line, index) {
        if (!line.trim()) { return; }
        var eq = line.indexOf("=");
        if (eq === -1) {
          errors.push(fmt(T.setupErrModelLine || "", { n: index + 1, id: id }));
          return;
        }
        var publicName = line.slice(0, eq).trim();
        var upstream = line.slice(eq + 1).trim();
        if (!publicName || !upstream) {
          errors.push(fmt(T.setupErrModelLine || "", { n: index + 1, id: id }));
          return;
        }
        models[publicName] = upstream;
        sawModel = true;
      });
      if (!sawModel && errors.indexOf(fmt(T.setupErrModelsEmpty || "", { id: id })) === -1 && !modelsText.trim()) {
        errors.push(fmt(T.setupErrModelsEmpty || "", { id: id }));
        return;
      }
      provider.models = models;
      ["cooldown", "timeout"].forEach(function (which) {
        var raw = which === "cooldown" ? cooldownText : timeoutText;
        if (raw === "") { return; }
        var value = Number(raw);
        if (isNaN(value)) {
          errors.push(fmt(T.setupErrNumber || "", { field: which === "cooldown" ? (T.setupCooldownField || "") : (T.setupTimeoutField || ""), id: id }));
          return;
        }
        provider[which + "_seconds"] = value;
      });
      if (insecure) { provider.allow_insecure = true; }
      documentOut.providers[id] = provider;
    });
    return { document: documentOut, errors: errors };
  }
  function showClientErrors(errors) {
    var box = clear(el("setup-result"));
    box.appendChild(tag("p", "form-error", T.setupClientErrors || ""));
    var list = tag("ul");
    errors.forEach(function (message) { list.appendChild(tag("li", null, message)); });
    box.appendChild(list);
  }
  function showWizardResult(result) {
    var box = clear(el("setup-result"));
    if (result.ok) {
      box.className = "result-box ok-message";
      text(box, result.message);
      return;
    }
    box.className = "result-box";
    box.appendChild(tag("p", "form-error", T.setupServerError || ""));
    var list = tag("ul");
    result.errors.forEach(function (message) { list.appendChild(tag("li", null, message)); });
    box.appendChild(list);
  }
  function wireWizard() {
    el("setup-add").addEventListener("click", function () {
      el("setup-providers").appendChild(providerFieldset(null));
    });
    el("setup-preview").addEventListener("click", function () {
      var gathered = gatherWizardDocument();
      if (gathered.errors.length) { showClientErrors(gathered.errors); return; }
      api("POST", "/api/wizard/preview", gathered.document).then(function (r) {
        if (r.status !== 200 || !r.data) { throw r; }
        if (r.data.ok) {
          var box = clear(el("setup-result"));
          box.className = "result-box ok-message";
          text(box, fmt(T.setupPreviewOk || "", { providers: r.data.summary.provider_count, models: r.data.summary.model_count }));
        } else { showWizardResult(r.data); }
      }).catch(function (err) {
        if (err && err.auth) { return; }
        showWizardResult({ ok: false, errors: [errorMessage(err)] });
      });
    });
    el("setup-write").addEventListener("click", function () {
      var gathered = gatherWizardDocument();
      if (gathered.errors.length) { showClientErrors(gathered.errors); return; }
      api("POST", "/api/wizard/write", gathered.document).then(function (r) {
        if (r.status !== 200 || !r.data) { throw r; }
        if (r.data.ok) {
          showWizardResult(r.data);
          refreshWizardCurrent().catch(function (err) { panelFail("setup", err); });
        } else { showWizardResult(r.data); }
      }).catch(function (err) {
        if (err && err.auth) { return; }
        showWizardResult({ ok: false, errors: [errorMessage(err)] });
      });
    });
  }

  // ---- spend filter wiring ------------------------------------------------
  function wireSpendFilters() {
    el("spend-filter").addEventListener("input", renderSpendRows);
    el("spend-status-filter").addEventListener("change", renderSpendRows);
  }

  // ---- login wiring ---------------------------------------------------------
  function wireLogin() {
    el("login-form").addEventListener("submit", function (event) {
      event.preventDefault();
      var value = el("login-token").value;
      if (!value) { return; }
      state.token = value;
      var btn = el("login-submit");
      btn.disabled = true;
      text(btn, T.loginChecking || "...");
      api("GET", "/api/status").then(function (r) {
        if (r.status === 200) { el("login-error").hidden = true; bootApp(); }
        else { throw r; }
      }).catch(function (err) {
        if (err && err.auth) { return; }
        state.token = null;
        btn.disabled = false;
        text(btn, T.loginButton || "");
        var box = el("login-error");
        text(box, T.loginBadToken || "");
        box.hidden = false;
      });
    });
    el("logout").addEventListener("click", function () { enterLogin(false); });
  }

  applyText();
  wireTabs();
  wireLogin();
  wireSpendFilters();
  wireWizard();
  setPanelState("status", "loading");
  enterLogin(false);
})();
"""

# Guard: the JSON blob must not be able to close its own <script> element.
_PAGE_TEXT_JSON = json.dumps(_T, ensure_ascii=True, separators=(",", ":"))
assert "</script" not in _PAGE_TEXT_JSON.lower(), "ui strings must not contain '</script'"

DOCUMENT: str = (
    _HTML.replace("__CSS__", _CSS)
    .replace("__PAGE_TEXT_JSON__", _PAGE_TEXT_JSON)
    .replace("__SCRIPT__", _SCRIPT)
)
DOCUMENT_BYTES: bytes = DOCUMENT.encode("ascii")
CONTENT_TYPE: str = "text/html; charset=utf-8"

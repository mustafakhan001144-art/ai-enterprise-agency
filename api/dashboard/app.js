// Dashboard for the AI Audit Agency API. Plain JS, no build step, no external requests.
// Every value from the API is escaped before it reaches the DOM: reports quote client data.
"use strict";

const KEY_STORAGE = "aea.apiKey";
const ACTIVE = new Set(["queued", "running"]);
const state = { key: "", selectedJob: null, jobTab: "brief", poll: null, cache: {} };

const $ = (sel) => document.querySelector(sel);
const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function storageGet() {
  try { return localStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
}
function storageSet(value) {
  try { value ? localStorage.setItem(KEY_STORAGE, value) : localStorage.removeItem(KEY_STORAGE); } catch { /* private mode */ }
}

async function api(path, options = {}) {
  const headers = { Authorization: `Bearer ${state.key}`, ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  const type = response.headers.get("content-type") || "";
  const body = type.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof body === "object" ? body.detail : body;
    const message = Array.isArray(detail)
      ? detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ")
      : detail || response.statusText;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------
const STATUS_CLASS = {
  succeeded: "b-ok", failed: "b-bad", running: "b-info", queued: "b-muted",
  CRITICAL: "b-bad", HIGH: "b-bad", MEDIUM: "b-warn", LOW: "b-ok", NONE: "b-muted",
  RELEASE: "b-ok", RELEASE_WITH_CAVEATS: "b-warn", HOLD: "b-bad",
  STAFFED: "b-ok", PARTIAL: "b-warn", CATALOG_UNAVAILABLE: "b-muted",
  P1: "b-bad", P2: "b-warn", P3: "b-muted",
  active: "b-ok", trialing: "b-ok", past_due: "b-warn", canceled: "b-bad", inactive: "b-muted",
};
const badge = (text) => `<span class="badge ${STATUS_CLASS[text] || "b-muted"}">${esc(text)}</span>`;
const when = (iso) => {
  if (!iso) return "";
  const date = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`);
  return Number.isNaN(date.getTime()) ? esc(iso) : esc(date.toLocaleString());
};
const KIND_LABEL = { forensics_contain: "AI incident", archeology_audit: "Legacy code" };

function refs(list) {
  return (list || [])
    .map((r) => (r.artifact_id ? `${r.artifact_id}:${r.locator || ""}` : r.file ? `${r.file}:${r.line ?? ""}` : ""))
    .filter(Boolean)
    .map((r) => `<code>${esc(r)}</code>`)
    .join(" ") || '<span class="muted">none</span>';
}

// Minimal Markdown: headings, lists, tables, code, bold, italics. Input is escaped first.
function markdown(source) {
  const inline = (text) =>
    esc(text)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|\W)_([^_]+)_(?=\W|$)/g, "$1<em>$2</em>");
  const lines = String(source || "").replace(/\r/g, "").split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (line.startsWith("```")) {
      const block = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) block.push(lines[i++]);
      i += 1;
      out.push(`<pre>${esc(block.join("\n"))}</pre>`);
      continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      const level = Math.min(heading[1].length + 1, 4);
      out.push(`<h${level}>${inline(heading[2])}</h${level}>`);
      i += 1;
      continue;
    }
    if (line.trim().startsWith("|") && i + 1 < lines.length && /^\s*\|[\s:|-]+\|\s*$/.test(lines[i + 1])) {
      const cells = (row) => row.trim().replace(/^\||\|$/g, "").split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim().startsWith("|")) rows.push(cells(lines[i++]));
      out.push(
        `<div class="table-wrap"><table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join("")}</tr></thead><tbody>` +
          rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("") +
          "</tbody></table></div>"
      );
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(lines[i++].replace(/^\s*[-*]\s+/, ""));
      out.push(`<ul>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</ul>`);
      continue;
    }
    if (line.trim()) out.push(`<p>${inline(line)}</p>`);
    i += 1;
  }
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
function renderAccount(account) {
  const quota = account.credit_quota || 0;
  const pct = quota ? Math.min(100, Math.round((account.credits_used / quota) * 100)) : 0;
  $("#account").innerHTML = `
    <div class="stat"><div class="label">Subscription</div><div class="value">${badge(account.subscription_status)}</div></div>
    <div class="stat"><div class="label">Credits remaining</div><div class="value">${esc(account.credits_remaining)}</div>
      <div class="meter" title="${pct}% used"><span style="width:${pct}%"></span></div></div>
    <div class="stat"><div class="label">Used this period</div><div class="value">${esc(account.credits_used)} / ${esc(quota)}</div></div>
    <div class="stat"><div class="label">Account</div><div class="value mono small">${esc(account.account_id.slice(0, 8))}…</div></div>`;
}

function renderJobs(jobs) {
  const body = $("#jobs-body");
  if (!jobs.length) {
    body.innerHTML = '<tr><td colspan="5" class="muted">No jobs yet. Start an audit to see it here.</td></tr>';
    return;
  }
  body.innerHTML = jobs
    .map(
      (j) => `<tr data-job="${esc(j.job_id)}" class="${j.job_id === state.selectedJob ? "selected" : ""}">
        <td class="mono">${esc(j.job_id.slice(0, 8))}</td>
        <td>${esc(KIND_LABEL[j.kind] || j.kind)}</td>
        <td>${badge(j.status)}</td>
        <td class="num">${esc(j.credits_charged)}</td>
        <td class="small">${when(j.created_at)}</td></tr>`
    )
    .join("");
}

function renderAgents(page) {
  const custom = page.agents.filter((a) => a.source === "custom");
  const groups = {};
  custom.forEach((a) => (groups[a.division] = groups[a.division] || []).push(a));
  const order = ["forensics", "archaeology", "management", "marketing"];
  let html = order
    .filter((d) => groups[d])
    .map(
      (d) => `<div class="division"><h3>${esc(d[0].toUpperCase() + d.slice(1))} ${badge(String(groups[d].length))}</h3>
        ${groups[d]
          .map(
            (a) => `<div class="agent"><div class="name">${esc(a.name)} <span class="muted small mono">${esc(a.output_schema)}</span></div>
              <div class="desc">${esc(a.description)}</div></div>`
          )
          .join("")}</div>`
    )
    .join("");
  html += renderCatalog(page);
  if (page.warnings && page.warnings.length) {
    html += `<p class="small">${page.warnings.slice(0, 3).map((w) => `<span class="b-warn">${esc(w)}</span>`).join("<br>")}</p>`;
  }
  $("#agents").innerHTML = html;
  const search = $("#catalog-search");
  if (search) search.addEventListener("input", () => filterCatalog(search.value));
}

// The Agency Agents catalog (msitarzewski/agency-agents), grouped by division.
function renderCatalog(page) {
  const catalog = page.agents.filter((a) => a.source === "upstream" || a.source === "installed");
  if (!catalog.length) return '<p class="muted small">The Agency Agents catalog is not loaded. Run <code>git submodule update --init</code> or set AGENCY_INSTALLED_AGENTS_DIR.</p>';
  const labels = Object.fromEntries((page.divisions || []).map((d) => [d.division, d.label]));
  const groups = {};
  catalog.forEach((a) => (groups[a.division] = groups[a.division] || []).push(a));
  const installed = catalog.filter((a) => a.location === "installed");
  const modified = installed.filter((a) => a.modified).length;
  const source = installed.length
    ? `${installed.length} read from your installed folder${modified ? `, ${modified} of them changed from the catalog` : ""}.`
    : "Read from the copy vendored in this repository.";
  const divisions = Object.keys(groups)
    .sort((a, b) => groups[b].length - groups[a].length || a.localeCompare(b))
    .map(
      (d) => `<details class="catalog-division"><summary>${esc(labels[d] || d)} ${badge(String(groups[d].length))}</summary>
        ${groups[d]
          .sort((a, b) => a.name.localeCompare(b.name))
          .map(
            (a) => `<div class="agent" data-search="${esc(`${a.name} ${a.description} ${a.agent_id}`.toLowerCase())}">
              <div class="name">${esc(a.name)}${a.location === "installed" ? ` <span class="badge ${a.modified ? "b-warn" : "b-ok"}">${a.modified ? "installed, changed" : "installed"}</span>` : ""}</div>
              <div class="desc">${esc(a.description)}</div></div>`
          )
          .join("")}</details>`
    )
    .join("");
  return `<h3 class="catalog-title">Agency Agents catalog ${badge(String(catalog.length))}</h3>
    <p class="muted small">Jobs are staffed from these agents. ${source}</p>
    <input id="catalog-search" type="search" placeholder="Search ${catalog.length} agents" aria-label="Search the agent catalog">
    <div id="catalog">${divisions}</div>`;
}

function filterCatalog(query) {
  const q = query.trim().toLowerCase();
  document.querySelectorAll("#catalog .catalog-division").forEach((group) => {
    let shown = 0;
    group.querySelectorAll(".agent").forEach((agent) => {
      const match = !q || agent.dataset.search.includes(q);
      agent.hidden = !match;
      shown += match ? 1 : 0;
    });
    group.hidden = shown === 0;
    group.open = Boolean(q) && shown > 0;
  });
}

function renderLedger(page) {
  const rows = page.entries.slice(0, 12);
  $("#ledger-body").innerHTML = rows.length
    ? rows
        .map(
          (e) => `<tr><td class="small">${when(e.created_at)}</td><td>${esc(e.reason)}${e.job_id ? ` <span class="mono muted small">${esc(e.job_id.slice(0, 8))}</span>` : ""}</td>
          <td class="num ${e.delta < 0 ? "b-bad" : "b-ok"}">${e.delta > 0 ? "+" : ""}${esc(e.delta)}</td></tr>`
        )
        .join("")
    : '<tr><td colspan="3" class="muted">No credit movements yet.</td></tr>';
}

function renderBrief(result) {
  const o = result.outputs || {};
  const brief = o.executive_brief;
  if (!brief) return '<p class="muted">This job has no executive brief.</p>';
  const metrics = Object.entries(brief.metrics || {})
    .map(([k, v]) => `<div><b>${esc(v ?? "n/a")}</b><span>${esc(k.replace(/_/g, " "))}</span></div>`)
    .join("");
  let html = `<div class="pill-row">Risk ${badge(brief.risk_rating)} Quality review ${badge(brief.release_verdict)}</div>
    <p class="headline">${esc(brief.headline)}</p>
    <div class="kv">${metrics}</div>`;
  const narrative = o.client_narrative;
  if (narrative && narrative.status === "COMPLETE" && narrative.narrative_markdown) {
    html += `<h3>Plain-language summary</h3><div class="narrative md">${markdown(narrative.narrative_markdown)}</div>
      <p class="muted small">Written by ${esc(narrative.model)} from the brief and proposal only.</p>`;
  }
  if (brief.key_findings?.length) {
    html += `<h3>Key findings</h3><div class="table-wrap"><table><thead><tr><th>Finding</th><th>Evidence</th></tr></thead><tbody>
      ${brief.key_findings.map((f) => `<tr><td>${esc(f.finding)}<div class="muted small mono">${esc(f.source)}</div></td><td>${refs(f.evidence_refs)}</td></tr>`).join("")}
      </tbody></table></div>`;
  }
  if (brief.decisions_required?.length) {
    html += `<h3>Decisions for you</h3><ul>${brief.decisions_required
      .map((d) => `<li><strong>${esc(d.decision)}</strong>${d.disruptive ? ' <span class="badge b-warn">disruptive</span>' : ""}<div class="muted small">${esc(d.why)}</div></li>`)
      .join("")}</ul>`;
  }
  if (brief.next_steps?.length) html += `<h3>Next steps</h3><ul>${brief.next_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`;
  if (brief.caveats?.length) html += `<h3>Caveats</h3><ul>${brief.caveats.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`;
  const proposal = o.follow_up_proposal;
  if (proposal) {
    html += `<h3>Follow-up proposal ${badge(proposal.status)}</h3>`;
    if (proposal.items?.length) {
      html += `<div class="table-wrap"><table><thead><tr><th>Priority</th><th>Service</th><th class="num">Credits</th></tr></thead><tbody>
        ${proposal.items
          .map((i) => `<tr><td>${badge(i.priority)}</td><td><strong>${esc(i.title)}</strong><div class="muted small">${esc(i.scope)}</div>
            <div class="muted small">Because: ${esc(i.triggered_by.join(", "))}</div></td><td class="num">${esc(i.estimated_credits)}<div class="muted small">${esc(i.estimate_basis)}</div></td></tr>`)
          .join("")}
        </tbody></table></div><p class="small">Estimated total <strong>${esc(proposal.estimated_credits_total)} credits</strong>. ${esc(proposal.terms)}</p>`;
    } else {
      html += `<p class="muted small">${esc(proposal.terms)}</p>`;
    }
  }
  html += renderTeam(o.specialist_roster, o.specialist_consults);
  return html;
}

function renderTeam(roster, consults) {
  if (!roster) return "";
  const notes = Object.fromEntries(((consults && consults.consults) || []).map((c) => [c.agent_id, c]));
  let html = `<h3>Specialist team ${badge(roster.status)}</h3>
    <p class="muted small">Staffed from the Agency Agents catalog (${esc(roster.catalog?.agents_available ?? 0)} agents available${roster.catalog?.installed_copies_used ? `, ${esc(roster.catalog.installed_copies_used)} assigned from your installed folder` : ""}).</p>`;
  if (roster.assignments?.length) {
    html += `<div class="table-wrap"><table><thead><tr><th>Specialist</th><th>Task</th></tr></thead><tbody>
      ${roster.assignments
        .map((a) => {
          const note = notes[a.agent_id];
          const body = note
            ? note.status === "COMPLETE" && note.notes_markdown
              ? `<div class="narrative md">${markdown(note.notes_markdown)}</div><div class="muted small">Written by ${esc(note.model)} using this agent's prompt.</div>`
              : `<div class="muted small">Consult not available: ${esc(note.detail)}</div>`
            : "";
          return `<tr><td><strong>${esc(a.name)}</strong>${a.role === "lead" ? ' <span class="badge b-info">lead</span>' : ""}
            <div class="muted small mono">${esc(a.catalog_name)}</div></td>
            <td>${esc(a.task)}<div class="muted small">Because: ${esc(a.triggered_by.join(", "))}</div>${body}</td></tr>`;
        })
        .join("")}
      </tbody></table></div>`;
  }
  if (roster.not_found?.length) html += `<p class="muted small">Not in the catalog: ${esc(roster.not_found.join(", "))}</p>`;
  return html;
}

function renderEvidence(evidence) {
  const v = evidence.verification || {};
  const entries = (evidence.manifest?.entries || [])
    .map((e) => `<tr><td class="mono small">${esc(e.path)}</td><td class="num">${esc(e.bytes)}</td><td class="mono small">${esc(e.sha256.slice(0, 16))}…</td></tr>`)
    .join("");
  return `<p>${v.valid ? '<span class="badge b-ok">VERIFIED</span> Every file matches the hash chain recorded when the job finished.'
      : `<span class="badge b-bad">BROKEN</span> ${esc((v.problems || []).join("; "))}`}</p>
    <p class="small muted">Chain head <code>${esc(evidence.recorded_head)}</code></p>
    <div class="table-wrap"><table><thead><tr><th>File</th><th class="num">Bytes</th><th>SHA-256</th></tr></thead><tbody>${entries}</tbody></table></div>`;
}

async function renderJobDetail() {
  const id = state.selectedJob;
  const panel = $("#job-detail");
  if (!id) { panel.hidden = true; return; }
  panel.hidden = false;
  document.querySelectorAll("#job-tabs .tab").forEach((t) => t.classList.toggle("active", t.dataset.jtab === state.jobTab));
  const content = $("#job-content");
  try {
    const job = await api(`/api/v1/jobs/${encodeURIComponent(id)}`);
    $("#job-title").innerHTML = `${esc(KIND_LABEL[job.kind] || job.kind)} <span class="mono muted small">${esc(id)}</span> ${badge(job.status)}`;
    if (job.status !== "succeeded") {
      content.innerHTML = job.status === "failed"
        ? `<p class="b-bad">The job failed after ${esc(job.attempts)} attempt(s): ${esc(job.error)}</p><p class="muted small">Its credits were refunded.</p>`
        : `<p class="muted">${job.status === "queued" ? "Waiting for a worker. Make sure <code>python -m core.worker</code> is running." : "Running…"}</p>`;
      return;
    }
    const cache = (state.cache[id] = state.cache[id] || {});
    if (state.jobTab === "brief" || state.jobTab === "raw") {
      cache.result = cache.result || (await api(`/api/v1/jobs/${encodeURIComponent(id)}/result`));
      content.innerHTML = state.jobTab === "brief" ? renderBrief(cache.result) : `<pre class="raw">${esc(JSON.stringify(cache.result, null, 2))}</pre>`;
    } else if (state.jobTab === "report") {
      cache.report = cache.report || (await api(`/api/v1/jobs/${encodeURIComponent(id)}/report`));
      content.innerHTML = `<div class="md">${markdown(cache.report)}</div>`;
    } else {
      content.innerHTML = renderEvidence(await api(`/api/v1/jobs/${encodeURIComponent(id)}/evidence`));
    }
  } catch (error) {
    content.innerHTML = `<p class="b-bad">${esc(error.message)}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Data flow
// ---------------------------------------------------------------------------
async function refresh() {
  const [account, jobs, ledger] = await Promise.all([api("/api/v1/account"), api("/api/v1/jobs?limit=25"), api("/api/v1/account/ledger?limit=12")]);
  renderAccount(account);
  renderJobs(jobs.jobs);
  renderLedger(ledger);
  const selected = jobs.jobs.find((j) => j.job_id === state.selectedJob);
  if (selected && !state.cache[selected.job_id]?.result && state.jobTab !== "evidence") renderJobDetail();
  schedulePoll(jobs.jobs.some((j) => ACTIVE.has(j.status)));
}

function schedulePoll(active) {
  clearTimeout(state.poll);
  if (active) state.poll = setTimeout(() => refresh().catch(showKeyError), 2500);
}

async function connect(key) {
  state.key = key.trim();
  const status = $("#key-status");
  if (!state.key) return;
  status.textContent = "Connecting…";
  try {
    await refresh();
    renderAgents(await api("/api/v1/agents"));
    storageSet(state.key);
    $("#app").hidden = false;
    status.textContent = "Connected. The key stays in this browser only.";
    status.className = "muted small";
  } catch (error) {
    showKeyError(error);
  }
}

function showKeyError(error) {
  const status = $("#key-status");
  status.className = "msg error";
  status.textContent =
    error.status === 401 ? "That key was not accepted." :
    error.status === 402 ? `Key accepted, but the subscription is not active: ${error.message}` :
    `Could not reach the API: ${error.message}`;
  if (error.status === 401) $("#app").hidden = true;
}

async function submit(path, body, button) {
  const msg = $("#submit-msg");
  button.disabled = true;
  msg.className = "msg";
  msg.textContent = "Submitting…";
  try {
    const accepted = await api(path, { method: "POST", body: JSON.stringify(body) });
    msg.className = "msg ok";
    msg.textContent = `Queued job ${accepted.job_id.slice(0, 8)} for ${accepted.credits_charged} credit(s). ${accepted.credits_remaining} left.`;
    state.selectedJob = accepted.job_id;
    state.jobTab = "brief";
    await refresh();
    renderJobDetail();
  } catch (error) {
    msg.className = "msg error";
    msg.textContent = error.message;
  } finally {
    button.disabled = false;
  }
}

async function checkHealth() {
  const el = $("#health");
  try {
    const r = await fetch("/readyz");
    const body = await r.json();
    el.className = r.ok ? "health ok" : "health bad";
    $("#health-text").textContent = r.ok ? `API ready · schema v${body.schema_version}` : "API not ready";
  } catch {
    el.className = "health bad";
    $("#health-text").textContent = "API unreachable";
  }
}

async function loadSample() {
  const response = await fetch("/dashboard/sample-incident.json");
  $("#forensics-body").value = JSON.stringify(await response.json(), null, 2);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  checkHealth();
  loadSample();
  $("#key-form").addEventListener("submit", (e) => { e.preventDefault(); connect($("#key-input").value); });
  $("#key-clear").addEventListener("click", () => {
    storageSet("");
    state.key = "";
    $("#key-input").value = "";
    $("#app").hidden = true;
    $("#key-status").textContent = "Key removed from this browser.";
  });
  $("#load-sample").addEventListener("click", loadSample);
  document.querySelectorAll(".tabs .tab[data-tab]").forEach((tab) =>
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab[data-tab]").forEach((t) => t.classList.toggle("active", t === tab));
      document.querySelectorAll(".tabpanel").forEach((p) => (p.hidden = p.dataset.panel !== tab.dataset.tab));
    })
  );
  $("#forensics-form").addEventListener("submit", (e) => {
    e.preventDefault();
    let body;
    try { body = JSON.parse($("#forensics-body").value); } catch (error) {
      $("#submit-msg").className = "msg error";
      $("#submit-msg").textContent = `That is not valid JSON: ${error.message}`;
      return;
    }
    submit("/api/v1/forensics/contain", body, e.submitter || e.target.querySelector("button[type=submit]"));
  });
  $("#archaeology-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const body = { repo_url: $("#repo-url").value.trim() };
    const ref = $("#repo-ref").value.trim();
    if (ref) body.ref = ref;
    submit("/api/v1/archeology/audit", body, e.submitter || e.target.querySelector("button[type=submit]"));
  });
  $("#jobs-body").addEventListener("click", (e) => {
    const row = e.target.closest("tr[data-job]");
    if (!row) return;
    state.selectedJob = row.dataset.job;
    state.jobTab = "brief";
    document.querySelectorAll("#jobs-body tr").forEach((r) => r.classList.toggle("selected", r === row));
    renderJobDetail();
    $("#job-detail").scrollIntoView({ behavior: "smooth", block: "start" });
  });
  $("#job-tabs").addEventListener("click", (e) => {
    const tab = e.target.closest(".tab");
    if (!tab) return;
    state.jobTab = tab.dataset.jtab;
    renderJobDetail();
  });
  $("#close-job").addEventListener("click", () => { state.selectedJob = null; renderJobDetail(); });
  $("#refresh").addEventListener("click", () => refresh().catch(showKeyError));

  const saved = storageGet();
  if (saved) {
    $("#key-input").value = saved;
    connect(saved);
  }
});

// config.js sets window.SPEAR_API (your Render backend URL). Empty = local.
const API = (window.SPEAR_API || "http://127.0.0.1:8000").replace(/\/+$/, "") + "/api";
const escapeHTML = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const statusEl = document.getElementById("api-status");
const views = [...document.querySelectorAll(".view")];
const navLinks = [...document.querySelectorAll(".nav-link[data-page]")];
const pageNames = {
  home: "Overview",
  analyze: "Analyze email",
  history: "History",
  learn: "Learn",
  about: "About S.P.E.A.R",
};
let latestReport = null;

function route() {
  const routeName = location.hash.slice(1) || "home";
  const page = pageNames[routeName] ? routeName : "home";
  views.forEach((v) => v.classList.toggle("active", v.id === `page-${page}`));
  navLinks.forEach((a) =>
    a.classList.toggle("active", a.dataset.page === page),
  );
  document.getElementById("crumb").textContent = pageNames[page];
  if (page === "history") loadHistory();
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);
route();

async function api(path, options) {
  const response = await fetch(`${API}${path}`, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
async function health() {
  try {
    await api("/health");
    statusEl.innerHTML = "<i></i> Backend connected";
    statusEl.classList.add("online");
  } catch {
    statusEl.innerHTML = "<i></i> Backend offline";
    statusEl.classList.remove("online");
  }
}
health();
setInterval(health, 12000);

const fileInput = document.getElementById("email-file");
const dropZone = document.getElementById("drop-zone");
fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  document.getElementById("selected-file").textContent = file
    ? `${file.name} · ${(file.size / 1024).toFixed(1)} KB`
    : "No file selected";
  document.getElementById("upload-error").textContent = "";
});
for (const event of ["dragenter", "dragover"])
  dropZone.addEventListener(event, (e) => {
    e.preventDefault();
    dropZone.classList.add("dragging");
  });
for (const event of ["dragleave", "drop"])
  dropZone.addEventListener(event, (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragging");
  });
dropZone.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    fileInput.dispatchEvent(new Event("change"));
  }
});

document.getElementById("upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const file = fileInput.files[0],
    err = document.getElementById("upload-error");
  err.textContent = "";
  if (!file) {
    err.textContent = "Choose an .eml file first.";
    return;
  }
  if (!file.name.toLowerCase().endsWith(".eml")) {
    err.textContent = "Only .eml files are supported.";
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    err.textContent = "The file exceeds the 5 MB limit.";
    return;
  }
  const button = document.getElementById("submit-button");
  button.disabled = true;
  button.innerHTML = "Analyzing…";
  try {
    const form = new FormData();
    form.append("file", file);
    const data = await api("/analyze", { method: "POST", body: form });
    renderReport(data.result);
  } catch (error) {
    err.textContent = error.message.includes("fetch")
      ? "Backend is not running. Start the backend using the included README, then try again."
      : error.message;
  } finally {
    button.disabled = false;
    button.innerHTML = "Analyze email <span>→</span>";
  }
});

function renderReport(r) {
  latestReport = r;
  const findings = r.findings.length
    ? r.findings
        .map(
          (f) =>
            `<article class="finding ${escapeHTML(f.level)}"><b>${escapeHTML(f.title)}</b><p>${escapeHTML(f.detail)}</p></article>`,
        )
        .join("")
    : '<div class="empty-findings">No configured warning indicators were found in the supplied text. This does not prove the email is safe.</div>';
  const auth = Object.entries(r.authentication)
    .map(
      ([k, v]) =>
        `<div class="auth-chip"><small>${escapeHTML(k)}</small><b>${escapeHTML(v)}</b></div>`,
    )
    .join("");
  const links = r.links.length
    ? r.links
        .map(
          (x) =>
            `<li><span>${escapeHTML(x.url)}</span>${x.signals.length ? `<small>${escapeHTML(x.signals.join(" · "))}</small>` : ""}</li>`,
        )
        .join("")
    : "<li>No links found in readable message body.</li>";
  const attachments = r.attachments.length
    ? r.attachments
        .map(
          (x) =>
            `<li>${escapeHTML(x.name)} <small>${escapeHTML(x.content_type)}</small></li>`,
        )
        .join("")
    : "<li>No attachment metadata found.</li>";
  const received = r.received.length
    ? r.received.map((x) => `<li>${escapeHTML(x)}</li>`).join("")
    : "<li>No Received fields present.</li>";
  const target = document.getElementById("result-section");
  target.innerHTML = `<div class="report-head"><div><div class="eyebrow"><i></i> ANALYSIS COMPLETE · #${escapeHTML(r.id)}</div><h2>${escapeHTML(r.verdict)}</h2><p>${escapeHTML(r.filename)} · ${escapeHTML(r.subject)}</p></div><span class="score-badge">${escapeHTML(r.score)}<small>signal score</small></span></div>
    <div class="report-grid"><section class="report-card"><h3>Message details</h3>${row("From", r.from)}${row("Sender domain", r.from_domain)}${row("Reply-To", r.reply_to)}${row("Return-Path", r.return_path)}</section>
    <section class="report-card"><h3>Reported authentication</h3><div class="auth-grid">${auth}</div><p class="muted-note">Values are read from this message only; this tool did not verify them.</p>${r.authentication_raw ? `<details><summary>Raw Authentication-Results</summary><p>${escapeHTML(r.authentication_raw)}</p></details>` : ""}</section></div>
    <section class="report-card"><h3>Review findings <span class="count">${r.findings.length}</span></h3><div class="finding-list">${findings}</div></section>
    <div class="report-grid"><section class="report-card"><h3>Links <span class="count">${r.links.length}</span></h3><ul class="evidence-list">${links}</ul></section><section class="report-card"><h3>Attachment names <span class="count">${r.attachments.length}</span></h3><ul class="evidence-list">${attachments}</ul></section></div>
    <section class="report-card"><h3>Mail route (Received)</h3><ul class="evidence-list">${received}</ul></section>
    <div class="report-disclaimer">ⓘ ${escapeHTML(r.disclaimer)}</div>`;
  target.classList.remove("hidden");
  target.scrollIntoView({ behavior: "smooth", block: "start" });
}
function row(label, value) {
  return `<div class="detail-row"><b>${escapeHTML(label)}</b><span>${escapeHTML(value || "Not found in supplied message")}</span></div>`;
}

const assistantPanel = document.getElementById("assistant-panel");
const assistantToggle = document.getElementById("assistant-toggle");
const assistantMessages = document.getElementById("assistant-messages");
function toggleAssistant(open) {
  assistantPanel.classList.toggle("open", open);
  assistantPanel.setAttribute("aria-hidden", String(!open));
  assistantToggle.setAttribute("aria-expanded", String(open));
  if (open) document.getElementById("assistant-question").focus();
}
assistantToggle.addEventListener("click", () =>
  toggleAssistant(!assistantPanel.classList.contains("open")),
);
document
  .getElementById("assistant-close")
  .addEventListener("click", () => toggleAssistant(false));
function addChatMessage(text, who) {
  const bubble = document.createElement("div");
  bubble.className = `chat-message ${who === "user" ? "user-message" : "assistant-message"}`;
  bubble.textContent = text;
  assistantMessages.append(bubble);
  assistantMessages.scrollTop = assistantMessages.scrollHeight;
  return bubble;
}
async function askGuide(question) {
  addChatMessage(question, "user");
  const pending = addChatMessage("Thinking…", "assistant");
  try {
    const { answer } = await api("/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question, report: latestReport }),
    });
    pending.textContent = answer;
  } catch (error) {
    pending.textContent = error.message.includes("fetch")
      ? "The backend is offline. Start it using Run-Backend.bat and try again."
      : error.message;
  }
  assistantMessages.scrollTop = assistantMessages.scrollHeight;
}
document
  .getElementById("assistant-form")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = document.getElementById("assistant-question"),
      question = input.value.trim();
    if (!question) return;
    input.value = "";
    await askGuide(question);
  });
assistantMessages
  .querySelectorAll(".suggested-questions button")
  .forEach((button) =>
    button.addEventListener("click", () => askGuide(button.textContent)),
  );

async function loadHistory() {
  const list = document.getElementById("history-list");
  try {
    const { items } = await api("/history");
    list.innerHTML = items.length
      ? `<div class="history-head"><span>EMAIL</span><span>RESULT</span><span>DATE</span></div>` +
        items
          .map(
            (x) =>
              `<button class="history-item" type="button" data-id="${Number(x.id)}"><span><b>${escapeHTML(x.sender || x.filename)}</b><small>${escapeHTML(x.subject)}</small></span><span class="history-verdict">${escapeHTML(x.verdict)}</span><span>${escapeHTML(new Date(x.created).toLocaleString())}</span></button>`,
          )
          .join("")
      : '<div class="empty-state"><span class="card-icon">◷</span><b>No email reviews yet</b><p>Upload an .eml message to create your first history entry.</p><a class="button primary" href="#analyze">Analyze an email →</a></div>';
  } catch (e) {
    list.innerHTML = `<div class="empty-state">${escapeHTML(e.message)}<p>Check that the backend is running.</p></div>`;
  }
}
document.getElementById("clear-history").addEventListener("click", async () => {
  if (!confirm("Delete all locally saved analysis history?")) return;
  try {
    await api("/history/clear", { method: "POST" });
    await loadHistory();
  } catch (e) {
    alert(e.message);
  }
});

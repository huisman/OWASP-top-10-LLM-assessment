"""
OWASP LLM Agent Reviewer — Web Portal
Run:  python app.py
Open: http://localhost:5000
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, request, Response, stream_with_context, render_template_string

from llm_provider import LLMClient, ProviderError
from review_agent import (
    SYSTEM_PROMPT, SUPPORTED_EXTENSIONS, MODEL, PROMPT_HASH,
    OWASP_VERSION, OWASP_LAST_UPDATED, OWASP_EDITION,
    OWASP_UPDATE_URL, check_owasp_staleness, update_owasp_definitions,
)

app = Flask(__name__)

AUDIT_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl")

# ---------------------------------------------------------------------------
# HTML / CSS / JS  (single-file, no templates folder needed)
# ---------------------------------------------------------------------------

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OWASP LLM Agent Reviewer</title>
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f1117;
      color: #e2e8f0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }

    header {
      background: #1a1d2e;
      border-bottom: 1px solid #2d3148;
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    header h1 { font-size: 1.2rem; font-weight: 600; }
    header .badge {
      background: #e53e3e;
      color: #fff;
      font-size: 0.7rem;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      letter-spacing: 0.05em;
    }
    header .readme-btn {
      margin-left: auto;
      background: none;
      border: 1px solid #2d3148;
      border-radius: 6px;
      color: #94a3b8;
      cursor: pointer;
      font-size: 0.82rem;
      padding: 4px 12px;
      transition: border-color 0.15s, color 0.15s;
    }
    header .readme-btn:hover { border-color: #4f6ef7; color: #e2e8f0; }
    .owasp-update-btn {
      background: none;
      border: none;
      color: #475569;
      cursor: pointer;
      font-size: 1rem;
      line-height: 1;
      padding: 2px 5px;
      transition: color 0.15s;
      vertical-align: middle;
    }
    .owasp-update-btn:hover:not(:disabled) { color: #94a3b8; }
    .owasp-update-btn:disabled { opacity: 0.4; cursor: default; }

    /* README modal */
    .modal-overlay {
      display: none;
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.65);
      z-index: 100;
      align-items: center;
      justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: #1a1d2e;
      border: 1px solid #2d3148;
      border-radius: 10px;
      max-width: 640px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      padding: 2rem;
    }
    .modal h2 { font-size: 1.1rem; margin-bottom: 1.2rem; color: #e2e8f0; }
    .modal h3 { font-size: 0.82rem; text-transform: uppercase; letter-spacing: 0.06em; color: #94a3b8; margin: 1.2rem 0 0.4rem; }
    .modal p, .modal li { font-size: 0.88rem; line-height: 1.7; color: #cbd5e1; }
    .modal ul { padding-left: 1.4rem; }
    .modal li { margin-bottom: 0.25rem; }
    .modal code {
      background: #0f1117;
      border-radius: 4px;
      padding: 1px 6px;
      font-family: Consolas, monospace;
      font-size: 0.82em;
      color: #7dd3fc;
    }
    .modal .close-btn {
      display: block;
      margin-top: 1.5rem;
      margin-left: auto;
      background: #4f6ef7;
      border: none;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font-size: 0.9rem;
      padding: 0.5rem 1.2rem;
    }
    .modal .close-btn:hover { background: #3b55d9; }

    main {
      flex: 1;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0;
      min-height: 0;
    }

    /* ---- LEFT PANEL ---- */
    .panel-left {
      border-right: 1px solid #2d3148;
      display: flex;
      flex-direction: column;
      padding: 1.5rem;
      gap: 0.75rem;
      min-height: 0;
    }

    .agents-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .agents-header label { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; }
    .add-agent-btn {
      background: none;
      border: 1px solid #2d3148;
      border-radius: 5px;
      color: #94a3b8;
      cursor: pointer;
      font-size: 0.78rem;
      padding: 3px 10px;
      transition: border-color 0.15s, color 0.15s;
    }
    .add-agent-btn:hover { border-color: #4f6ef7; color: #e2e8f0; }

    /* Scrollable agent card list */
    .agents-list {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      min-height: 0;
    }

    /* Individual agent card */
    .agent-card {
      border: 1px solid #2d3148;
      border-radius: 6px;
      overflow: hidden;
      flex-shrink: 0;
    }
    .agent-card-header {
      background: #12152a;
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #2d3148;
    }
    .agent-card-header input[type="text"] {
      background: transparent;
      border: none;
      color: #e2e8f0;
      flex: 1;
      font-size: 0.82rem;
      outline: none;
      padding: 2px 4px;
    }
    .agent-card-header input[type="text"]::placeholder { color: #475569; }
    .upload-btn {
      background: none;
      border: 1px solid #2d3148;
      border-radius: 4px;
      color: #64748b;
      cursor: pointer;
      font-size: 0.72rem;
      padding: 2px 8px;
      transition: border-color 0.15s, color 0.15s;
      white-space: nowrap;
    }
    .upload-btn:hover { border-color: #4f6ef7; color: #e2e8f0; }
    .remove-btn {
      background: none;
      border: none;
      color: #475569;
      cursor: pointer;
      font-size: 1rem;
      line-height: 1;
      padding: 2px 4px;
      transition: color 0.15s;
    }
    .remove-btn:hover { color: #f87171; }

    .agent-card textarea {
      background: #1a1d2e;
      border: none;
      color: #c9d1e0;
      display: block;
      font-family: "Fira Code", "Cascadia Code", Consolas, monospace;
      font-size: 0.8rem;
      line-height: 1.55;
      min-height: 160px;
      padding: 0.6rem 0.75rem;
      resize: vertical;
      transition: background 0.15s;
      width: 100%;
    }
    .agent-card textarea:focus { outline: none; background: #1e2240; }
    .agent-card textarea.drag-over { background: #1e2240; border: 1px dashed #4f6ef7; }

    .agent-card-footer {
      background: #12152a;
      border-top: 1px solid #2d3148;
      padding: 2px 0.75rem;
      text-align: right;
    }
    .char-counter {
      font-size: 0.72rem;
      color: #475569;
    }
    .char-counter.warn   { color: #f59e0b; }
    .char-counter.danger { color: #ef4444; }

    /* Repo URL input */
    .repo-section {
      border: 1px solid #2d3148;
      border-radius: 6px;
      padding: 0.75rem;
      background: #12152a;
    }
    .repo-section label {
      font-size: 0.8rem;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      display: block;
      margin-bottom: 0.4rem;
    }
    .repo-input-row {
      display: flex;
      gap: 0.4rem;
    }
    .repo-input-row input {
      flex: 1;
      background: #1a1d2e;
      border: 1px solid #2d3148;
      border-radius: 5px;
      color: #e2e8f0;
      font-size: 0.85rem;
      padding: 0.45rem 0.65rem;
      outline: none;
      transition: border-color 0.15s;
    }
    .repo-input-row input:focus { border-color: #4f6ef7; }
    .repo-input-row input::placeholder { color: #475569; }
    .fetch-btn {
      background: #1e293b;
      border: 1px solid #2d3148;
      border-radius: 5px;
      color: #94a3b8;
      cursor: pointer;
      font-size: 0.82rem;
      padding: 0.45rem 0.85rem;
      white-space: nowrap;
      transition: border-color 0.15s, color 0.15s, background 0.15s;
    }
    .fetch-btn:hover:not(:disabled) { border-color: #4f6ef7; color: #e2e8f0; background: #253047; }
    .fetch-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .repo-status {
      font-size: 0.75rem;
      color: #64748b;
      margin-top: 0.35rem;
      min-height: 1.1em;
    }
    .repo-status.error { color: #f87171; }
    .repo-status.success { color: #4ade80; }
    .divider-or {
      text-align: center;
      font-size: 0.75rem;
      color: #475569;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      position: relative;
    }
    .divider-or::before, .divider-or::after {
      content: '';
      position: absolute;
      top: 50%;
      width: 38%;
      height: 1px;
      background: #2d3148;
    }
    .divider-or::before { left: 0; }
    .divider-or::after { right: 0; }

    /* Submit row */
    .submit-row { display: flex; gap: 0.5rem; }
    button#submit-btn {
      background: #4f6ef7;
      border: none;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font-size: 0.95rem;
      font-weight: 600;
      padding: 0.65rem 1.5rem;
      transition: background 0.15s;
      flex: 1;
    }
    button#submit-btn:hover:not(:disabled) { background: #3b55d9; }
    button#submit-btn:disabled { opacity: 0.55; cursor: not-allowed; }

    /* ---- RIGHT PANEL ---- */
    .panel-right {
      display: flex;
      flex-direction: column;
      padding: 1.5rem;
      gap: 0.75rem;
      overflow-y: auto;
    }

    .output-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .output-header h2 { font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.06em; }

    .output-actions { display: flex; gap: 0.4rem; }
    .output-actions button {
      background: none;
      border: 1px solid #2d3148;
      border-radius: 5px;
      color: #94a3b8;
      cursor: pointer;
      font-size: 0.78rem;
      padding: 3px 10px;
      transition: border-color 0.15s, color 0.15s;
    }
    .output-actions button:hover:not(:disabled) { border-color: #4f6ef7; color: #e2e8f0; }
    .output-actions button:disabled { opacity: 0.35; cursor: not-allowed; }

    /* ---- THINKING PANEL ---- */
    .thinking-panel {
      border: 1px solid #2d3148;
      border-radius: 6px;
      overflow: hidden;
    }
    .thinking-toggle {
      width: 100%;
      background: #12152a;
      border: none;
      border-radius: 0;
      color: #64748b;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 0.78rem;
      padding: 0.45rem 0.85rem;
      text-align: left;
      transition: color 0.15s, background 0.15s;
      gap: 0.5rem;
    }
    .thinking-toggle:hover { background: #1a1d2e; color: #94a3b8; }
    .thinking-toggle .thinking-label { display: flex; align-items: center; gap: 0.5rem; }
    .thinking-dot {
      width: 6px; height: 6px;
      background: #6366f1;
      border-radius: 50%;
      animation: pulse 1.4s ease-in-out infinite;
    }
    .thinking-dot.done { animation: none; background: #475569; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
    .thinking-toggle .thinking-arrow { font-size: 0.7rem; color: #475569; }
    .thinking-body {
      background: #0a0d1a;
      border-top: 1px solid #2d3148;
      max-height: 260px;
      overflow-y: auto;
      padding: 0.75rem 1rem;
    }
    .thinking-body pre {
      color: #475569;
      font-family: "Fira Code", Consolas, monospace;
      font-size: 0.76rem;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-word;
    }

    /* ---- AUDIT META BAR ---- */
    .audit-bar {
      background: #12152a;
      border: 1px solid #2d3148;
      border-radius: 6px;
      display: none;
      font-family: "Fira Code", Consolas, monospace;
      font-size: 0.72rem;
      color: #475569;
      padding: 0.5rem 0.85rem;
      line-height: 1.8;
    }
    .audit-bar.visible { display: block; }
    .audit-bar span { color: #64748b; }

    #output {
      flex: 1;
      background: #1a1d2e;
      border: 1px solid #2d3148;
      border-radius: 6px;
      padding: 1rem 1.25rem;
      overflow-y: auto;
      min-height: 420px;
      font-size: 0.88rem;
      line-height: 1.7;
    }
    #output .placeholder { color: #475569; font-style: italic; }

    /* Markdown rendering */
    #output h1, #output h2 { color: #e2e8f0; margin-top: 1.2rem; margin-bottom: 0.4rem; }
    #output h3 { color: #93c5fd; margin-top: 1rem; margin-bottom: 0.3rem; }
    #output strong { color: #f0abfc; }
    #output ul, #output ol { padding-left: 1.4rem; }
    #output li { margin-bottom: 0.2rem; }
    #output code {
      background: #0f1117; border-radius: 4px; padding: 1px 5px;
      font-family: Consolas, monospace; font-size: 0.82em; color: #7dd3fc;
    }
    #output pre { background: #0f1117; border-radius: 6px; padding: 0.75rem; overflow-x: auto; margin: 0.5rem 0; }
    #output pre code { background: none; padding: 0; }
    #output hr { border: none; border-top: 1px solid #2d3148; margin: 1rem 0; }

    .status-bar {
      font-size: 0.78rem; color: #64748b;
      display: flex; align-items: center; gap: 0.5rem;
    }
    .spinner {
      width: 12px; height: 12px;
      border: 2px solid #4f6ef7; border-top-color: transparent;
      border-radius: 50%; animation: spin 0.7s linear infinite; display: none;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>

<header>
  <h1>OWASP LLM Agent Reviewer</h1>
  <span class="badge" id="owasp-badge" title="OWASP definitions version">Top 10 · 2025</span>
  <button class="owasp-update-btn" id="owasp-update-btn" onclick="triggerOwaspUpdate()" title="Refresh OWASP definitions">↻</button>
  <a id="owasp-stale-link" href="https://genai.owasp.org/llm-top-10/" target="_blank" rel="noopener"
     style="display:none; font-size:0.72rem; color:#d97706; text-decoration:none; transition:color 0.15s;"
     onmouseover="this.style.color='#f59e0b'" onmouseout="this.style.color='#d97706'">⚠ New version available?</a>
  <button class="readme-btn" onclick="document.getElementById('readme-modal').classList.add('open')">README</button>
</header>

<!-- README modal -->
<div class="modal-overlay" id="readme-modal" onclick="if(event.target===this)this.classList.remove('open')">
  <div class="modal">
    <h2>OWASP LLM Agent Reviewer</h2>

    <h3>What it does</h3>
    <p>Paste or upload one or more agent files and this tool analyses them against all ten categories of the <strong>OWASP Top 10 for Large Language Model Applications (2025 edition)</strong>. For multi-agent systems it also assesses inter-agent risks: cross-agent prompt injection, sensitive data flows, and cumulative agency.</p>

    <h3>How to use</h3>
    <ul>
      <li><strong>From a repo:</strong> paste a GitHub URL and click <strong>Fetch</strong> — all supported files are loaded automatically.</li>
      <li><strong>From code:</strong> each <strong>agent card</strong> represents one component. Add cards with <strong>+ Add agent</strong>, then paste code or click <strong>Upload</strong> / drag a file.</li>
      <li>Click <strong>Review Agent</strong> (single) or <strong>Review System</strong> (multi) — or press <kbd>Ctrl+Enter</kbd>.</li>
      <li>If the model uses extended thinking, the <strong>Extended thinking</strong> panel appears — click to inspect the reasoning.</li>
      <li>The <strong>audit bar</strong> shows timestamp, model, and SHA-256 hashes for reperformance verification.</li>
      <li>Use <strong>Copy</strong> or <strong>Download</strong> to save the report. The <code>.md</code> includes the full audit header and any extended thinking.</li>
    </ul>

    <h3>OWASP definitions</h3>
    <p>The reviewer loads category definitions from <code>owasp_llm_top10.json</code>. The badge in the header shows the current version. A warning colour (amber) means the definitions are older than 30 days — click <strong>↻</strong> to fetch a fresh copy. The server must be restarted for new definitions to take effect.</p>

    <h3>Audit log</h3>
    <p>Every completed review is appended to <code>audit_log.jsonl</code> in the server working directory.</p>

    <h3>Supported file types</h3>
    <p><code>.py</code> · <code>.js</code> · <code>.ts</code> · <code>.json</code> · <code>.yaml</code> · <code>.yml</code> · <code>.txt</code> · <code>.md</code></p>

    <h3>Running locally</h3>
    <p>Requires an API key for your configured provider (<code>ANTHROPIC_API_KEY</code> or <code>OPENAI_API_KEY</code> — see <code>SAAF_LLM_PROVIDER</code>) and <code>pip install anthropic openai flask</code>. Start with <code>python app.py</code>; port defaults to <code>5000</code>.</p>

    <button class="close-btn" onclick="document.getElementById('readme-modal').classList.remove('open')">Close</button>
  </div>
</div>

<main>
  <!-- LEFT: input -->
  <div class="panel-left">

    <div class="repo-section">
      <label>Repository URL</label>
      <div class="repo-input-row">
        <input type="text" id="repo-url" placeholder="https://github.com/owner/repo" onkeydown="if(event.key==='Enter')fetchRepo()" />
        <button class="fetch-btn" id="fetch-btn" onclick="fetchRepo()">Fetch</button>
      </div>
      <div class="repo-status" id="repo-status"></div>
    </div>

    <div class="divider-or">or paste code</div>

    <div class="agents-header">
      <label>Agents</label>
      <button class="add-agent-btn" onclick="addCard()">+ Add agent</button>
    </div>

    <div class="agents-list" id="agents-list"></div>

    <div class="submit-row">
      <button id="submit-btn" onclick="startReview()">Review Agent</button>
      <button onclick="document.getElementById('readme-modal').classList.add('open')"
              style="background:none;border:1px solid #2d3148;border-radius:6px;color:#94a3b8;cursor:pointer;font-size:0.82rem;padding:0 1rem;white-space:nowrap;transition:border-color 0.15s,color 0.15s;"
              onmouseover="this.style.borderColor='#4f6ef7';this.style.color='#e2e8f0'"
              onmouseout="this.style.borderColor='#2d3148';this.style.color='#94a3b8'">README</button>
    </div>
  </div>

  <!-- RIGHT: output -->
  <div class="panel-right">
    <div class="output-header">
      <h2>OWASP LLM Top 10 Analysis</h2>
      <div class="output-actions">
        <button id="copy-btn" onclick="copyReport()" disabled>Copy</button>
        <button id="download-btn" onclick="downloadReport()" disabled>Download .md</button>
      </div>
    </div>

    <!-- Extended thinking panel -->
    <div class="thinking-panel" id="thinking-panel" style="display:none">
      <button class="thinking-toggle" id="thinking-toggle" onclick="toggleThinking()">
        <span class="thinking-label">
          <span class="thinking-dot" id="thinking-dot"></span>
          Extended thinking
        </span>
        <span class="thinking-arrow" id="thinking-arrow">▶ Show</span>
      </button>
      <div class="thinking-body" id="thinking-body" style="display:none">
        <pre id="thinking-content"></pre>
      </div>
    </div>

    <!-- Audit metadata bar -->
    <div class="audit-bar" id="audit-bar">
      <span>Reviewed:</span> <span id="audit-ts">—</span> &nbsp;·&nbsp;
      <span>Model:</span> <span id="audit-model">—</span> &nbsp;·&nbsp;
      <span>Risk:</span> <span id="audit-risk">—</span><br>
      <span>SHA-256 (input):</span> <span id="audit-input-hash">—</span><br>
      <span>SHA-256 (prompt):</span> <span id="audit-prompt-hash">—</span>
    </div>

    <div id="output">
      <p class="placeholder">Your security analysis will appear here.</p>
    </div>
    <div class="status-bar">
      <div class="spinner" id="spinner"></div>
      <span id="status">Ready</span>
    </div>
  </div>
</main>

<script>
  let rawMarkdown = "";
  let rawThinking = "";
  let thinkingOpen = false;
  let auditMeta = {};
  let cardCounter = 0;

  // ---- Agent card management ----

  function createCard(id) {
    const div = document.createElement("div");
    div.className = "agent-card";
    div.id = `agent-card-${id}`;
    div.innerHTML = `
      <div class="agent-card-header">
        <input type="text" placeholder="e.g. agent_${id + 1}.py" oninput="updateSubmitLabel()" />
        <button class="upload-btn" onclick="triggerUpload(${id})">Upload</button>
        <input type="file" id="file-input-${id}"
               accept=".py,.js,.ts,.json,.yaml,.yml,.txt,.md"
               style="display:none"
               onchange="handleFileInput(event,${id})" />
        <button class="remove-btn" onclick="removeCard(${id})" title="Remove">×</button>
      </div>
      <textarea placeholder="Paste agent code or drag & drop a file…"
                oninput="updateCharCounter(this)"></textarea>
      <div class="agent-card-footer">
        <span class="char-counter">0 chars</span>
      </div>
    `;

    const textarea = div.querySelector("textarea");
    textarea.addEventListener("dragover", (e) => {
      e.preventDefault();
      textarea.classList.add("drag-over");
    });
    textarea.addEventListener("dragleave", () => textarea.classList.remove("drag-over"));
    textarea.addEventListener("drop", (e) => {
      e.preventDefault();
      textarea.classList.remove("drag-over");
      const file = e.dataTransfer.files[0];
      if (file) loadFileIntoCard(file, div);
    });
    // Ctrl+Enter on any textarea submits
    textarea.addEventListener("keydown", (e) => {
      if (e.ctrlKey && e.key === "Enter") startReview();
    });

    return div;
  }

  function addCard() {
    const card = createCard(cardCounter++);
    document.getElementById("agents-list").appendChild(card);
    updateRemoveButtons();
    updateSubmitLabel();
  }

  function removeCard(id) {
    const card = document.getElementById(`agent-card-${id}`);
    if (card) card.remove();
    updateRemoveButtons();
    updateSubmitLabel();
  }

  function updateRemoveButtons() {
    const cards = document.querySelectorAll(".agent-card");
    cards.forEach(card => {
      card.querySelector(".remove-btn").style.display = cards.length > 1 ? "" : "none";
    });
  }

  function updateSubmitLabel() {
    const n = document.querySelectorAll(".agent-card").length;
    document.getElementById("submit-btn").textContent =
      n === 1 ? "Review Agent" : `Review System (${n} agents)`;
  }

  // ---- File upload ----

  function triggerUpload(id) {
    document.getElementById(`file-input-${id}`).click();
  }

  function handleFileInput(e, id) {
    const file = e.target.files[0];
    if (!file) return;
    const card = document.getElementById(`agent-card-${id}`);
    loadFileIntoCard(file, card);
    e.target.value = "";
  }

  function loadFileIntoCard(file, card) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const textarea = card.querySelector("textarea");
      textarea.value = e.target.result;
      updateCharCounter(textarea);
      const filenameInput = card.querySelector("input[type=text]");
      if (!filenameInput.value) filenameInput.value = file.name;
      updateSubmitLabel();
    };
    reader.readAsText(file);
  }

  function updateCharCounter(textarea) {
    const n = textarea.value.length;
    const counter = textarea.closest(".agent-card").querySelector(".char-counter");
    counter.textContent = n.toLocaleString() + " chars";
    counter.className = "char-counter" + (n > 100000 ? " danger" : n > 50000 ? " warn" : "");
  }

  // ---- Collect agents from cards ----

  function collectAgents() {
    return Array.from(document.querySelectorAll(".agent-card")).map(card => ({
      filename: card.querySelector("input[type=text]").value.trim() || "pasted_code",
      code: card.querySelector("textarea").value.trim()
    })).filter(a => a.code);
  }

  // ---- Thinking panel toggle ----

  function toggleThinking() {
    thinkingOpen = !thinkingOpen;
    document.getElementById("thinking-body").style.display = thinkingOpen ? "block" : "none";
    document.getElementById("thinking-arrow").textContent = thinkingOpen ? "▼ Hide" : "▶ Show";
  }

  // ---- Review ----

  async function startReview() {
    const agents = collectAgents();
    if (!agents.length) { alert("Please paste some agent code first."); return; }

    const btn      = document.getElementById("submit-btn");
    const output   = document.getElementById("output");
    const spinner  = document.getElementById("spinner");
    const status   = document.getElementById("status");
    const copyBtn  = document.getElementById("copy-btn");
    const dlBtn    = document.getElementById("download-btn");
    const tPanel   = document.getElementById("thinking-panel");
    const tContent = document.getElementById("thinking-content");
    const tDot     = document.getElementById("thinking-dot");
    const tBody    = document.getElementById("thinking-body");
    const tArrow   = document.getElementById("thinking-arrow");
    const auditBar = document.getElementById("audit-bar");

    btn.disabled     = true;
    copyBtn.disabled = true;
    dlBtn.disabled   = true;
    spinner.style.display = "inline-block";
    status.textContent = agents.length > 1
      ? `Analysing ${agents.length}-agent system…`
      : "Analysing…";
    rawMarkdown    = "";
    rawThinking    = "";
    auditMeta      = { filenames: agents.map(a => a.filename) };
    thinkingOpen   = false;
    output.innerHTML = "";
    tPanel.style.display  = "none";
    tBody.style.display   = "none";
    tArrow.textContent    = "▶ Show";
    tContent.textContent  = "";
    tDot.className        = "thinking-dot";
    auditBar.classList.remove("visible");

    try {
      const response = await fetch("/review", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agents }),
      });

      if (!response.ok) {
        const err = await response.text();
        output.innerHTML = `<p style="color:#f87171">Error: ${err}</p>`;
        return;
      }

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\\n");
        buffer = lines.pop();

        for (const line of lines) {
          if (!line.trim()) continue;
          let chunk;
          try { chunk = JSON.parse(line); } catch { continue; }

          if (chunk.type === "meta") {
            auditMeta = { ...auditMeta, ...chunk };

          } else if (chunk.type === "thinking") {
            rawThinking += chunk.text;
            if (tPanel.style.display === "none") tPanel.style.display = "block";
            tContent.textContent = rawThinking;
            if (thinkingOpen) tBody.scrollTop = tBody.scrollHeight;

          } else if (chunk.type === "text") {
            rawMarkdown += chunk.text;
            output.innerHTML = DOMPurify.sanitize(marked.parse(rawMarkdown));
            output.scrollTop = output.scrollHeight;

          } else if (chunk.type === "done") {
            auditMeta.risk = chunk.risk;
            document.getElementById("audit-ts").textContent          = auditMeta.timestamp   || "—";
            document.getElementById("audit-model").textContent       = auditMeta.model       || "—";
            document.getElementById("audit-risk").textContent        = auditMeta.risk        || "—";
            document.getElementById("audit-input-hash").textContent  = auditMeta.file_hash   || "—";
            document.getElementById("audit-prompt-hash").textContent = auditMeta.prompt_hash || "—";
            auditBar.classList.add("visible");
          }
        }
      }

      status.textContent = "Review complete";
      copyBtn.disabled   = false;
      dlBtn.disabled     = false;
      tDot.className     = "thinking-dot done";
    } catch (e) {
      output.innerHTML = `<p style="color:#f87171">Request failed: ${e.message}</p>`;
      status.textContent = "Error";
    } finally {
      btn.disabled = false;
      spinner.style.display = "none";
    }
  }

  // ---- Copy to clipboard ----

  async function copyReport() {
    try {
      await navigator.clipboard.writeText(rawMarkdown);
      const btn  = document.getElementById("copy-btn");
      const prev = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = prev; }, 1500);
    } catch {
      alert("Copy failed — please select and copy the text manually.");
    }
  }

  // ---- Download as .md (includes audit header + thinking) ----

  function downloadReport() {
    const filenames = auditMeta.filenames || ["pasted_code"];
    let content = "";

    content += "---\\n";
    content += "owasp_review_audit:\\n";
    content += `  reviewed: "${auditMeta.timestamp || ''}"\\n`;
    content += `  files: [${filenames.map(f => `"${f}"`).join(", ")}]\\n`;
    content += `  sha256_input: "${auditMeta.file_hash || ''}"\\n`;
    content += `  sha256_prompt: "${auditMeta.prompt_hash || ''}"\\n`;
    content += `  model: "${auditMeta.model || ''}"\\n`;
    content += `  risk_rating: "${auditMeta.risk || 'Unknown'}"\\n`;
    content += "---\\n\\n";

    if (rawThinking) {
      content += "## Extended Thinking\\n\\n";
      content += "> Model's reasoning chain, preserved for audit/reperformance purposes.\\n\\n";
      content += "```\\n" + rawThinking + "\\n```\\n\\n---\\n\\n";
    }

    content += rawMarkdown;

    const safe = filenames[0].replace(/[^a-zA-Z0-9._-]/g, "_");
    const suffix = filenames.length > 1 ? `_and_${filenames.length - 1}_more` : "";
    const name = `owasp_review_${safe}${suffix}.md`;
    const blob = new Blob([content], { type: "text/markdown" });
    const a    = document.createElement("a");
    a.href     = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // ---- OWASP version badge ----

  async function loadOwaspVersion() {
    try {
      const r = await fetch("/owasp-version");
      if (!r.ok) return;
      const data = await r.json();
      const badge     = document.getElementById("owasp-badge");
      const staleLink = document.getElementById("owasp-stale-link");
      badge.textContent = `Top 10 · ${data.version}`;
      if (data.is_stale && data.days_old >= 0) {
        badge.style.background = "#d97706";
        badge.title = `Definitions are ${data.days_old} days old — click ↻ to pull an update`;
        staleLink.style.display = "inline";
        staleLink.title = `Definitions are ${data.days_old} days old. Click to check the OWASP LLM Top 10 changelog.`;
      } else {
        badge.title = `${data.edition} — updated ${data.last_updated || "unknown"}`;
        staleLink.style.display = "none";
      }
    } catch {}
  }

  async function triggerOwaspUpdate() {
    const btn = document.getElementById("owasp-update-btn");
    btn.disabled = true;
    btn.textContent = "…";
    try {
      const r = await fetch("/owasp-update", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      const data = await r.json();
      if (data.status === "ok") {
        alert(`Updated to ${data.edition}.\\nRestart the server to apply the new definitions.`);
        await loadOwaspVersion();
      } else {
        alert(`Update failed: ${data.message}`);
      }
    } catch (e) {
      alert(`Update failed: ${e.message}`);
    } finally {
      btn.disabled = false;
      btn.textContent = "↻";
    }
  }

  // ---- Fetch repo ----

  async function fetchRepo() {
    const urlInput   = document.getElementById("repo-url");
    const fetchBtn   = document.getElementById("fetch-btn");
    const repoStatus = document.getElementById("repo-status");
    const url = urlInput.value.trim();

    if (!url) { repoStatus.textContent = "Please enter a repository URL."; repoStatus.className = "repo-status error"; return; }

    fetchBtn.disabled = true;
    fetchBtn.textContent = "Cloning…";
    repoStatus.textContent = "Cloning repository…";
    repoStatus.className = "repo-status";

    try {
      const resp = await fetch("/fetch-repo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await resp.json();
      if (!resp.ok || data.error) {
        repoStatus.textContent = data.error || "Failed to fetch repository.";
        repoStatus.className = "repo-status error";
        return;
      }

      // Clear existing cards and populate with repo files
      const list = document.getElementById("agents-list");
      list.innerHTML = "";
      cardCounter = 0;

      for (const file of data.files) {
        const card = createCard(cardCounter++);
        list.appendChild(card);
        const filenameInput = card.querySelector("input[type=text]");
        const textarea = card.querySelector("textarea");
        filenameInput.value = file.path;
        textarea.value = file.content;
        updateCharCounter(textarea);
      }

      updateRemoveButtons();
      updateSubmitLabel();
      repoStatus.textContent = `Loaded ${data.files.length} file(s) from ${data.repo_name}`;
      repoStatus.className = "repo-status success";
    } catch (e) {
      repoStatus.textContent = `Error: ${e.message}`;
      repoStatus.className = "repo-status error";
    } finally {
      fetchBtn.disabled = false;
      fetchBtn.textContent = "Fetch";
    }
  }

  // ---- Init: start with one empty card + load OWASP version ----
  addCard();
  loadOwaspVersion();
</script>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/review", methods=["POST"])
def review():
    data = request.get_json(silent=True) or {}

    # Accept multi-agent format {agents: [{filename, code}]} or legacy {code, filename}
    if "agents" in data:
        agents = [
            {
                "filename": a.get("filename", "pasted_code").strip() or "pasted_code",
                "code": a.get("code", "").strip(),
            }
            for a in data["agents"]
            if a.get("code", "").strip()
        ]
    else:
        code_text = data.get("code", "").strip()
        filename  = data.get("filename", "pasted_code").strip() or "pasted_code"
        agents    = [{"filename": filename, "code": code_text}]

    if not agents:
        return "No code provided.", 400

    try:
        llm_client = LLMClient()
    except ProviderError as e:
        return str(e), 500

    def generate():
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        combined  = "|".join(f"{a['filename']}:{a['code']}" for a in agents)
        file_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        yield json.dumps({
            "type":        "meta",
            "timestamp":   ts,
            "model":       MODEL,
            "file_hash":   file_hash,
            "prompt_hash": PROMPT_HASH,
        }) + "\n"

        # Build user message
        if len(agents) == 1:
            user_message = (
                f"Please review the following agent code/config for OWASP LLM Top 10 compliance.\n"
                f"Filename: {agents[0]['filename']}\n\n"
                f"```\n{agents[0]['code']}\n```"
            )
        else:
            parts = [
                f"Please review the following multi-agent system ({len(agents)} components) "
                f"for OWASP LLM Top 10 compliance.\n\n"
                f"Assess each component individually and then consider inter-agent risks: "
                f"cross-agent prompt injection paths, sensitive data flowing between agents, "
                f"and cumulative agency across the system.\n"
            ]
            for i, agent in enumerate(agents, 1):
                parts.append(
                    f"\n---\n\n### Component {i}: `{agent['filename']}`\n\n"
                    f"```\n{agent['code']}\n```\n"
                )
            user_message = "\n".join(parts)

        full_text = []

        for event in llm_client.stream(system=SYSTEM_PROMPT, user=user_message, max_tokens=8192):
            if event.type == "thinking":
                yield json.dumps({"type": "thinking", "text": event.text}) + "\n"
            elif event.type == "text":
                full_text.append(event.text)
                yield json.dumps({"type": "text", "text": event.text}) + "\n"

        review_text = "".join(full_text)
        risk_match  = re.search(r"[Oo]verall risk rating[:\s]+(Critical|High|Medium|Low)", review_text)
        risk        = risk_match.group(1) if risk_match else "Unknown"

        log_entry = {
            "timestamp":     ts,
            "filenames":     [a["filename"] for a in agents],
            "agent_count":   len(agents),
            "sha256_input":  file_hash,
            "sha256_prompt": PROMPT_HASH,
            "model":         MODEL,
            "risk_rating":   risk,
        }
        try:
            with open(AUDIT_LOG, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(log_entry) + "\n")
        except OSError:
            pass

        yield json.dumps({"type": "done", "risk": risk}) + "\n"

    return Response(stream_with_context(generate()), mimetype="text/plain")


# ---------------------------------------------------------------------------
# Repo fetch route
# ---------------------------------------------------------------------------

_MAX_FILE_SIZE = 100_000  # skip files larger than 100 KB
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".tox", "site-packages", ".mypy_cache"}


@app.route("/fetch-repo", methods=["POST"])
def fetch_repo():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return {"error": "No URL provided."}, 400

    tmp_dir = tempfile.mkdtemp(prefix="owasp-review-")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp_dir],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            err = result.stderr.strip() or "git clone failed"
            return {"error": err}, 400

        repo_name = url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
        repo_path = Path(tmp_dir)
        files = []

        for ext in SUPPORTED_EXTENSIONS:
            for fpath in sorted(repo_path.rglob(f"*{ext}")):
                if _SKIP_DIRS & set(fpath.relative_to(repo_path).parts):
                    continue
                if fpath.stat().st_size > _MAX_FILE_SIZE:
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel = str(fpath.relative_to(repo_path)).replace("\\", "/")
                files.append({"path": rel, "content": content})

        if not files:
            return {"error": f"No supported files found ({', '.join(SUPPORTED_EXTENSIONS)})."}, 400

        return {"repo_name": repo_name, "files": files}

    except subprocess.TimeoutExpired:
        return {"error": "Clone timed out after 120 seconds."}, 400
    except FileNotFoundError:
        return {"error": "git is not installed on the server."}, 500
    except Exception as e:
        return {"error": str(e)}, 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# OWASP definitions routes
# ---------------------------------------------------------------------------

@app.route("/owasp-version", methods=["GET"])
def owasp_version_route():
    is_stale, days = check_owasp_staleness()
    return {
        "version":      OWASP_VERSION,
        "edition":      OWASP_EDITION,
        "last_updated": OWASP_LAST_UPDATED,
        "is_stale":     is_stale,
        "days_old":     days,
    }


@app.route("/owasp-update", methods=["POST"])
def owasp_update_route():
    data = request.get_json(silent=True) or {}
    url = data.get("url") or OWASP_UPDATE_URL
    try:
        new_defs = update_owasp_definitions(url)
        return {"status": "ok", "version": new_defs.get("version"), "edition": new_defs.get("edition")}
    except (RuntimeError, ValueError) as e:
        return {"status": "error", "message": str(e)}, 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting OWASP LLM Agent Reviewer on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)

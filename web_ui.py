import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from vault import (
    analyze_pattern,
    atbash_lab,
    audit_key_strength,
    compare_protection_lab,
    controlled_caesar_lab,
    decode_layers_lab,
    detect_vulnerabilities,
    morse_lab,
    rot13_lab,
    tamper_resistance_demo,
    unwrap_payload,
    vigenere_lab,
    weak_hash_lab,
    wrap_payload,
    xor_repeating_lab,
    xor_single_byte_lab,
)

HTML_PAGE = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>AEGIS-RT // Security & Crypto Command Center</title>
<style>
  :root {
    --bg: #05080f;
    --bg-elev: #0b111e;
    --panel: #0e1626;
    --panel-2: #121d31;
    --border: rgba(148, 163, 184, 0.16);
    --border-strong: rgba(0, 255, 163, 0.35);
    --green: #00ffa3;
    --green-dim: rgba(0, 255, 163, 0.12);
    --cyan: #38bdf8;
    --cyan-dim: rgba(56, 189, 248, 0.12);
    --amber: #fbbf24;
    --amber-dim: rgba(251, 191, 36, 0.14);
    --red: #fb7185;
    --red-dim: rgba(251, 113, 133, 0.14);
    --text: #f1f5f9;
    --muted: #94a3b8;
    --shadow: 0 20px 50px rgba(0, 0, 0, 0.45);
  }

  * {
    box-sizing: border-box;
    transition: background-color 0.18s ease, border-color 0.18s ease, color 0.18s ease, transform 0.15s ease;
  }

  body {
    margin: 0;
    background:
      radial-gradient(circle at 12% 0%, rgba(0, 255, 163, 0.08), transparent 36%),
      radial-gradient(circle at 88% 8%, rgba(56, 189, 248, 0.09), transparent 38%),
      var(--bg);
    color: var(--text);
    font-family: "Segoe UI", Tahoma, system-ui, sans-serif;
    min-height: 100vh;
    padding: 24px 18px 40px;
  }

  .container {
    max-width: 1220px;
    margin: 0 auto;
  }

  /* Topbar */
  .topbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
    background: linear-gradient(135deg, rgba(14, 22, 38, 0.92), rgba(11, 17, 30, 0.95));
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 18px 24px;
    box-shadow: var(--shadow);
    backdrop-filter: blur(12px);
    margin-bottom: 18px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .brand-mark {
    width: 46px;
    height: 46px;
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(0, 255, 163, 0.2), rgba(56, 189, 248, 0.2));
    border: 1px solid var(--border-strong);
    display: grid;
    place-items: center;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-weight: 800;
    font-size: 18px;
    color: var(--green);
  }

  .brand-title {
    font-size: 20px;
    font-weight: 700;
    letter-spacing: 0.3px;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .tag-v1 {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 6px;
    background: var(--cyan-dim);
    color: var(--cyan);
    border: 1px solid rgba(56, 189, 248, 0.35);
  }

  .brand-sub {
    color: var(--muted);
    font-size: 13px;
    margin-top: 3px;
  }

  .status-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 14px;
    border-radius: 999px;
    background: var(--green-dim);
    border: 1px solid var(--border-strong);
    color: var(--green);
    font-size: 12.5px;
    font-weight: 600;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 10px var(--green);
  }

  /* KPI Strip */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-bottom: 18px;
  }

  @media (max-width: 960px) {
    .kpi-grid { grid-template-columns: repeat(2, 1fr); }
  }
  @media (max-width: 540px) {
    .kpi-grid { grid-template-columns: 1fr; }
  }

  .kpi-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 15px 18px;
    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.25);
  }

  .kpi-label {
    color: var(--muted);
    font-size: 12px;
    margin-bottom: 6px;
  }

  .kpi-value {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 17px;
    font-weight: 700;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .kpi-meta {
    font-size: 11.5px;
    color: var(--cyan);
    margin-top: 4px;
  }

  /* Main Layout */
  .main-grid {
    display: grid;
    grid-template-columns: 1.02fr 1.18fr;
    gap: 18px;
    align-items: start;
  }

  @media (max-width: 960px) {
    .main-grid { grid-template-columns: 1fr; }
  }

  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
    box-shadow: var(--shadow);
  }

  .panel-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }

  .panel-title {
    font-size: 15px;
    font-weight: 700;
    color: var(--text);
  }

  /* Category Tabs */
  .tabs {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }

  .tab-btn {
    background: var(--bg-elev);
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 7px 12px;
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
  }

  .tab-btn.active {
    background: var(--cyan-dim);
    color: var(--cyan);
    border-color: rgba(56, 189, 248, 0.45);
  }

  label {
    display: block;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--cyan);
    margin: 12px 0 6px;
  }

  select, input, textarea {
    width: 100%;
    background: var(--bg-elev);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 11px 13px;
    font-size: 13.5px;
    outline: none;
  }

  select:focus, input:focus, textarea:focus {
    border-color: var(--green);
    box-shadow: 0 0 0 3px rgba(0, 255, 163, 0.1);
  }

  textarea {
    min-height: 105px;
    resize: vertical;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    line-height: 1.5;
  }

  .row-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  @media (max-width: 540px) {
    .row-2 { grid-template-columns: 1fr; }
  }

  /* Presets */
  .presets-label {
    font-size: 11.5px;
    color: var(--muted);
    margin-top: 12px;
    margin-bottom: 6px;
  }

  .presets {
    display: flex;
    flex-wrap: wrap;
    gap: 7px;
  }

  .chip {
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 5px 10px;
    font-size: 11.5px;
    cursor: pointer;
  }

  .chip:hover {
    border-color: var(--cyan);
    color: var(--cyan);
  }

  .actions-row {
    display: flex;
    gap: 10px;
    margin-top: 16px;
  }

  .btn-primary {
    flex: 1;
    background: linear-gradient(135deg, var(--green), #00d68f);
    color: #03130c;
    border: none;
    border-radius: 11px;
    padding: 12px 16px;
    font-size: 14px;
    font-weight: 800;
    cursor: pointer;
    box-shadow: 0 8px 24px rgba(0, 255, 163, 0.22);
  }

  .btn-primary:hover {
    transform: translateY(-1px);
    filter: brightness(1.04);
  }

  .btn-ghost {
    background: var(--bg-elev);
    color: var(--muted);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 12px 14px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
  }

  .btn-ghost:hover {
    color: var(--text);
    border-color: rgba(148, 163, 184, 0.35);
  }

  /* Output side */
  .toolbar {
    display: flex;
    gap: 7px;
    flex-wrap: wrap;
  }

  .mini-btn {
    background: var(--bg-elev);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
  }

  .mini-btn:hover {
    border-color: var(--green);
    color: var(--green);
  }

  .summary-box {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
    margin-bottom: 12px;
    min-height: 76px;
  }

  .vuln-item {
    border-right: 3px solid var(--amber);
    background: rgba(251, 191, 36, 0.06);
    padding: 9px 12px;
    border-radius: 8px;
    margin-top: 8px;
    font-size: 12.5px;
  }

  .vuln-item.high {
    border-right-color: var(--red);
    background: rgba(251, 113, 133, 0.08);
  }

  .badge-sev {
    display: inline-block;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 10.5px;
    padding: 1px 6px;
    border-radius: 5px;
    margin-left: 6px;
    font-weight: 700;
  }

  .sev-high { background: var(--red-dim); color: var(--red); }
  .sev-med  { background: var(--amber-dim); color: var(--amber); }

  pre.json-box {
    background: #050911;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 15px;
    color: #86efac;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12.5px;
    line-height: 1.55;
    overflow: auto;
    max-height: 430px;
    min-height: 250px;
    margin: 0;
    direction: ltr;
    text-align: left;
  }

  .error-text {
    color: var(--red) !important;
  }

  .muted {
    color: var(--muted);
    font-size: 13px;
  }
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <div class="brand">
      <div class="brand-mark">AR</div>
      <div>
        <div class="brand-title">
          <span>AEGIS-RT Command Studio</span>
          <span class="tag-v1">AEGIS-X-v1</span>
        </div>
        <div class="brand-sub">لوحة تحليل التشفير والثغرات — متصلة مباشرة بمحرك <code>vault.py</code> على Kali Linux</div>
      </div>
    </div>
    <div class="status-pill">
      <span class="dot"></span>
      <span>Kali Engine Connected</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">النمط المكتشف</div>
      <div class="kpi-value" id="kpi-type">—</div>
      <div class="kpi-meta" id="kpi-conf">بانتظار أول فحص</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">الإنتروبيا (Entropy)</div>
      <div class="kpi-value" id="kpi-entropy">0.000</div>
      <div class="kpi-meta" id="kpi-len">الطول: 0 حرف</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">الثغرات المكتشفة</div>
      <div class="kpi-value" id="kpi-vulns">0</div>
      <div class="kpi-meta" id="kpi-key">المفتاح: غير محدد</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">آخر عملية</div>
      <div class="kpi-value" id="kpi-op">Ready</div>
      <div class="kpi-meta" id="kpi-time">زمن التنفيذ: —</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">إعدادات المختبر والمدخلات</div>
      </div>

      <div class="tabs">
        <button class="tab-btn active" onclick="filterCategory('all', this)">الكل</button>
        <button class="tab-btn" onclick="filterCategory('audit', this)">فحص وثغرات</button>
        <button class="tab-btn" onclick="filterCategory('crypto', this)">مختبرات الشفرات</button>
        <button class="tab-btn" onclick="filterCategory('envelope', this)">AEGIS-X-v1 والاختبارات</button>
      </div>

      <label for="op">اختر العملية / المختبر</label>
      <select id="op" onchange="syncDefaults()">
        <optgroup label="فحص وثغرات">
          <option value="scan" data-cat="audit">Scan & Detect Vulnerabilities — فحص العينة وكشف الثغرات</option>
          <option value="pattern" data-cat="audit">Pattern & Entropy — تحليل النمط والإنتروبيا</option>
          <option value="key" data-cat="audit">Audit Passphrase Strength — فحص قوة كلمة المرور</option>
        </optgroup>
        <optgroup label="مختبرات التشفير والتحليل">
          <option value="caesar" data-cat="crypto">Caesar / ROT Lab (0..25) — كسر قيصر الشامل</option>
          <option value="atbash" data-cat="crypto">Atbash Cipher Lab — شفرة أتباش</option>
          <option value="rot13" data-cat="crypto">ROT13 Lab — إزاحة 13</option>
          <option value="morse" data-cat="crypto">Morse Encode / Decode — ترميز وفك مورس</option>
          <option value="vigenere" data-cat="crypto">Vigenere Lab — تقدير طول المفتاح والقاموس</option>
          <option value="layers" data-cat="crypto">Multi-Layer Decoder — فك الطبقات المتداخلة</option>
          <option value="xor_sb" data-cat="crypto">Single-Byte XOR Lab — فحص XOR أحادي البايت</option>
          <option value="xor_rep" data-cat="crypto">Repeating-Key XOR Lab — فحص XOR متكرر المفتاح</option>
          <option value="hash" data-cat="crypto">Weak Hash Lab — اختبار التجزئة الضعيفة</option>
        </optgroup>
        <optgroup label="AEGIS-X-v1 والاختبارات">
          <option value="wrap" data-cat="envelope">Wrap Payload (AEGIS-X-v1) — تغليف وتشفير مصادق</option>
          <option value="unwrap" data-cat="envelope">Unwrap Payload (AEGIS-X-v1) — التحقق وفك الغلاف</option>
          <option value="tamper" data-cat="envelope">Tamper & Wrong-Key Test — اختبار التلاعب والمفتاح الخطأ</option>
          <option value="compare" data-cat="envelope">Compare Encoding vs AEGIS-X-v1 — مقارنة الترميز بالغلاف</option>
        </optgroup>
      </select>

      <label for="input_text">المدخل (نص، شفرة، عينة، غلاف، أو Hash)</label>
      <textarea id="input_text" placeholder="أدخل النص أو الشفرة أو اختر عينة جاهزة بالأسفل..."></textarea>

      <div class="row-2">
        <div>
          <label for="passphrase">Passphrase / Secret</label>
          <input id="passphrase" type="text" value="StrongPass!2026" placeholder="مثال: StrongPass!2026" />
        </div>
        <div>
          <label for="algo">Hash Algorithm (md5 / sha1 / sha256)</label>
          <input id="algo" type="text" value="md5" placeholder="md5" />
        </div>
      </div>

      <div class="presets-label">عينات سريعة للتجربة بنقرة واحدة:</div>
      <div class="presets">
        <button type="button" class="chip" onclick="applyPreset('scan', 'aGVsbG8gd29ybGQ=', '123456')">Base64 + Weak Key</button>
        <button type="button" class="chip" onclick="applyPreset('caesar', 'khoor zruog', '')">Caesar Shift 3</button>
        <button type="button" class="chip" onclick="applyPreset('morse', '.... . .-.. .-.. --- / .-- --- .-. .-.. -..', '')">Morse Hello World</button>
        <button type="button" class="chip" onclick="applyPreset('layers', 'JVhSMGNIbGxZbXhs', '')">Multi-Layer Sample</button>
        <button type="button" class="chip" onclick="applyPreset('tamper', 'confidential-kali-lab-note', 'AegisStrong#2026')">Tamper Test</button>
        <button type="button" class="chip" onclick="applyPreset('compare', 'red-team-payload-2026', 'AegisStrong#2026')">Compare Lab</button>
      </div>

      <div class="actions-row">
        <button class="btn-primary" onclick="runLab()">تشغيل العملية</button>
        <button class="btn-ghost" onclick="clearAll()">تفريغ</button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <div class="panel-title">النتائج والتقرير</div>
        <div class="toolbar">
          <button class="mini-btn" onclick="copyJson()">نسخ JSON</button>
          <button class="mini-btn" onclick="downloadReport()">تنزيل .json</button>
        </div>
      </div>

      <div class="summary-box" id="summary-box">
        <div class="muted">اختر عملية واضغط «تشغيل العملية» لعرض الملخص والثغرات والنتائج هنا.</div>
      </div>

      <label>مخرجات المحرك الكاملة (JSON)</label>
      <pre class="json-box" id="out">{ "status": "ready", "engine": "vault.py" }</pre>
    </div>
  </div>
</div>

<script>
let lastResult = null;

function filterCategory(cat, btn) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  const sel = document.getElementById("op");
  let firstVisible = null;
  for (const opt of sel.options) {
    const optCat = opt.dataset.cat || "all";
    const show = (cat === "all" || optCat === cat);
    opt.hidden = !show;
    if (show && !firstVisible) firstVisible = opt.value;
  }
  if (firstVisible && sel.selectedOptions[0]?.hidden) {
    sel.value = firstVisible;
  }
}

function syncDefaults() {
  const op = document.getElementById("op").value;
  const txt = document.getElementById("input_text");
  if (!txt.value.trim()) {
    if (op === "caesar") txt.value = "khoor zruog";
    else if (op === "atbash") txt.value = "svool dliow";
    else if (op === "rot13") txt.value = "uryyb jbeyq";
    else if (op === "morse") txt.value = ".... . .-.. .-.. ---";
  }
}

function applyPreset(op, sampleText, pw) {
  document.getElementById("op").value = op;
  document.getElementById("input_text").value = sampleText;
  if (pw !== undefined && pw !== "") {
    document.getElementById("passphrase").value = pw;
  }
  runLab();
}

function clearAll() {
  document.getElementById("input_text").value = "";
  document.getElementById("summary-box").innerHTML = '<div class="muted">تم التفريغ. جاهز لإدخال جديد.</div>';
}

function updateKpis(op, data, elapsedMs) {
  document.getElementById("kpi-op").textContent = op;
  document.getElementById("kpi-time").textContent = `زمن التنفيذ: ${elapsedMs} ms`;

  if (data.pattern) {
    document.getElementById("kpi-type").textContent = data.pattern.detected_type || "—";
    document.getElementById("kpi-conf").textContent = `الثقة: ${data.pattern.confidence || "—"}`;
    document.getElementById("kpi-entropy").textContent = `${data.pattern.entropy ?? 0} b/c`;
    document.getElementById("kpi-len").textContent = `الطول: ${data.pattern.length ?? 0} حرف`;
  } else if (data.detected_type) {
    document.getElementById("kpi-type").textContent = data.detected_type;
    document.getElementById("kpi-conf").textContent = `الثقة: ${data.confidence || "—"}`;
    document.getElementById("kpi-entropy").textContent = `${data.entropy ?? 0} b/c`;
    document.getElementById("kpi-len").textContent = `الطول: ${data.length ?? 0} حرف`;
  }

  if (typeof data.vulnerability_count === "number") {
    document.getElementById("kpi-vulns").textContent = String(data.vulnerability_count);
  }
  if (data.key_audit) {
    document.getElementById("kpi-key").textContent = `المفتاح: ${data.key_audit.rating} (${data.key_audit.score}/100)`;
  }
}

function renderSummary(op, data) {
  const box = document.getElementById("summary-box");

  if (data.error) {
    box.innerHTML = `<div class="error-text"><strong>خطأ:</strong> ${escapeHtml(data.error)}</div>`;
    return;
  }

  if (Array.isArray(data.vulnerabilities)) {
    if (data.vulnerabilities.length === 0) {
      box.innerHTML = `<div style="color:var(--green);font-weight:700;">✓ لم يتم رصد ثغرات واضحة في العينة.</div>`;
      return;
    }
    let html = `<div style="font-weight:700;color:var(--red);">! تم رصد ${data.vulnerabilities.length} نقطة ضعف / ملاحظة:</div>`;
    for (const v of data.vulnerabilities) {
      const isHigh = v.severity === "High";
      const badgeCls = isHigh ? "sev-high" : "sev-med";
      html += `
        <div class="vuln-item ${isHigh ? "high" : ""}">
          <div><span class="badge-sev ${badgeCls}">${escapeHtml(v.severity)}</span><strong>${escapeHtml(v.title)}</strong> (${escapeHtml(v.id)})</div>
          <div style="color:var(--muted);margin-top:4px;">${escapeHtml(v.detail)}</div>
          <div style="color:var(--green);margin-top:4px;">المعالجة: ${escapeHtml(v.remediation)}</div>
        </div>`;
    }
    box.innerHTML = html;
    return;
  }

  if (data.envelope) {
    box.innerHTML = `<div><strong style="color:var(--green);">تم إنشاء غلاف AEGIS-X-v1 بنجاح:</strong></div>
      <div style="font-family:monospace;font-size:12px;word-break:break-all;margin-top:6px;color:var(--cyan);">${escapeHtml(data.envelope)}</div>`;
    return;
  }

  if (typeof data.plaintext === "string") {
    box.innerHTML = `<div><strong style="color:var(--green);">تم التحقق وفك الغلاف بنجاح:</strong></div>
      <div style="font-family:monospace;font-size:13px;margin-top:6px;">${escapeHtml(data.plaintext)}</div>`;
    return;
  }

  if (typeof data.output === "string") {
    box.innerHTML = `<div><strong style="color:var(--cyan);">النتيجة المباشرة:</strong></div>
      <div style="font-family:monospace;font-size:13.5px;color:var(--green);margin-top:6px;">${escapeHtml(data.output)}</div>`;
    return;
  }

  if (typeof data.final_output === "string") {
    box.innerHTML = `<div><strong style="color:var(--cyan);">تم فك ${data.layers_peeled} طبقة — الناتج النهائي:</strong></div>
      <div style="font-family:monospace;font-size:13.5px;color:var(--green);margin-top:6px;">${escapeHtml(data.final_output)}</div>`;
    return;
  }

  if (typeof data.tampered_envelope_blocked === "boolean") {
    box.innerHTML = `
      <div><strong>اختبار التلاعب:</strong> <span style="color:${data.tampered_envelope_blocked ? "var(--green)" : "var(--red)"}">${data.tampered_envelope_blocked ? "محظور (BLOCKED)" : "مخترق"}</span> — ${escapeHtml(data.tamper_message || "")}</div>
      <div style="margin-top:6px;"><strong>اختبار المفتاح الخطأ:</strong> <span style="color:${data.wrong_passphrase_blocked ? "var(--green)" : "var(--red)"}">${data.wrong_passphrase_blocked ? "محظور (BLOCKED)" : "مخترق"}</span> — ${escapeHtml(data.wrong_passphrase_message || "")}</div>`;
    return;
  }

  box.innerHTML = `<div class="muted">تم تنفيذ العملية <strong>${escapeHtml(op)}</strong> بنجاح. راجع تفاصيل JSON الكاملة بالأسفل.</div>`;
}

function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function runLab() {
  const out = document.getElementById("out");
  const op = document.getElementById("op").value;
  out.classList.remove("error-text");
  out.textContent = "Running on Kali engine...";
  document.getElementById("summary-box").innerHTML = '<div class="muted">جاري التنفيذ على محرك vault.py...</div>';

  const t0 = performance.now();
  const payload = {
    op,
    text: document.getElementById("input_text").value,
    passphrase: document.getElementById("passphrase").value,
    algo: document.getElementById("algo").value || "md5"
  };

  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    const elapsedMs = Math.round(performance.now() - t0);
    lastResult = { op, elapsed_ms: elapsedMs, data };

    if (!res.ok) {
      out.classList.add("error-text");
      out.textContent = JSON.stringify(data, null, 2);
      renderSummary(op, data);
      return;
    }

    out.textContent = JSON.stringify(data, null, 2);
    updateKpis(op, data, elapsedMs);
    renderSummary(op, data);
  } catch (err) {
    out.classList.add("error-text");
    out.textContent = "Connection error: " + err;
    document.getElementById("summary-box").innerHTML = `<div class="error-text">تعذر الاتصال بسيرفر Kali: ${escapeHtml(err)}</div>`;
  }
}

function copyJson() {
  const text = document.getElementById("out").textContent;
  navigator.clipboard?.writeText(text);
}

function downloadReport() {
  const content = JSON.stringify(lastResult || { status: "empty" }, null, 2);
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "aegis-rt-report.json";
  a.click();
  URL.revokeObjectURL(url);
}
</script>
</body>
</html>
"""


def execute_operation(payload: dict) -> dict:
    op = (payload.get("op") or "scan").strip()
    text = payload.get("text") or ""
    pw = payload.get("passphrase") or ""
    algo = (payload.get("algo") or "md5").strip()

    if op == "scan":
        return detect_vulnerabilities(text, passphrase=pw)
    if op == "pattern":
        return analyze_pattern(text)
    if op == "key":
        return audit_key_strength(pw or text)
    if op == "caesar":
        return controlled_caesar_lab(text or "khoor zruog")
    if op == "atbash":
        return atbash_lab(text or "svool dliow")
    if op == "rot13":
        return rot13_lab(text or "uryyb jbeyq")
    if op == "morse":
        return morse_lab(text or "HELLO")
    if op == "vigenere":
        return vigenere_lab(text, max_attempts=5000, timeout=5.0)
    if op == "layers":
        return decode_layers_lab(text)
    if op == "xor_sb":
        return xor_single_byte_lab(text)
    if op == "xor_rep":
        return xor_repeating_lab(text, max_key_len=3, max_attempts=80000, timeout=5.0)
    if op == "hash":
        return weak_hash_lab(text, algo=algo, max_attempts=200000, timeout=8.0)
    if op == "wrap":
        return {"envelope": wrap_payload(text, pw)}
    if op == "unwrap":
        return {"plaintext": unwrap_payload(text, pw)}
    if op == "tamper":
        return tamper_resistance_demo(text or "red-team-note", pw or "StrongPass!2026")
    if op == "compare":
        return compare_protection_lab(text or "sample-secret", pw or "StrongPass!2026")
    raise ValueError(f"Unknown operation: {op}")


class AegisWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/api/run":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
            result = execute_operation(payload)
            body = json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except ValueError as exc:
            body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            body = json.dumps({"error": f"Server error: {exc}"}, ensure_ascii=False).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        return


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def serve_web(host: str = "0.0.0.0", port: int = 8080) -> None:
    ip = get_local_ip()
    server = ThreadingHTTPServer((host, port), AegisWebHandler)
    print(f"[+] AEGIS-RT Web UI running:")
    print(f"    - Local (Kali)   : http://127.0.0.1:{port}")
    print(f"    - Windows Browser: http://{ip}:{port}")
    print("    Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Web server stopped.")
    finally:
        server.server_close()


def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO", "/")

    if method == "GET" and path in ("/", "/index.html"):
        body = HTML_PAGE.encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    if method == "POST" and path == "/api/run":
        try:
            length = int(environ.get("CONTENT_LENGTH") or "0")
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length).decode("utf-8", errors="replace") if length > 0 else ""
        try:
            payload = json.loads(raw) if raw else {}
            result = execute_operation(payload)
            body = json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8")
            start_response("200 OK", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ])
            return [body]
        except ValueError as exc:
            body = json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8")
            start_response("400 Bad Request", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ])
            return [body]
        except Exception as exc:
            body = json.dumps({"error": f"Server error: {exc}"}, ensure_ascii=False).encode("utf-8")
            start_response("500 Internal Server Error", [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

    body = b"Not Found"
    start_response("404 Not Found", [
        ("Content-Type", "text/plain; charset=utf-8"),
        ("Content-Length", str(len(body))),
    ])
    return [body]

/* ISO 27001 Compliance Auditor — frontend
 *
 * Talks to three serverless endpoints:
 *   GET  /api/baseline   control catalogue + sample list (cached at the edge)
 *   POST /api/audit      telemetry -> full assessment
 *   POST /api/report     telemetry -> PDF audit report
 *
 * The audit is always recomputed server-side by the same engine the Streamlit
 * app and the test suite use, so results cannot drift between interfaces.
 * No build step, no framework; Chart.js is the only external dependency.
 */
'use strict';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const S = {
  baseline: null,      // /api/baseline response
  source: null,        // {kind:'sample'|'content', sample?, content?, filename?}
  report: null,        // report object from /api/audit
  evidence: {},        // flat telemetry
  meta: {},
  attestations: {},    // {key: true|false}
  scopedOut: new Set(),
  strict: false,
  charts: {},
};

const STATUS = ['PASS', 'PARTIAL', 'FAIL', 'MANUAL', 'NO_DATA', 'N/A'];
const COLOR = {
  PASS: '#16a34a', PARTIAL: '#ca8a04', FAIL: '#dc2626',
  MANUAL: '#2563eb', NO_DATA: '#94a3b8', 'N/A': '#cbd5e1',
  High: '#dc2626', Medium: '#ca8a04', Low: '#16a34a', None: '#94a3b8',
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function esc(v) {
  return String(v ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function cls(s) { return String(s).replace(/[^A-Za-z0-9_]/g, '_'); }

function busy(on, text) {
  const el = $('#busy');
  $('#busyText').textContent = text || 'Assessing…';
  el.hidden = !on;
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function api(path, payload, wantBlob) {
  const opts = payload
    ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }
    : { method: 'GET' };
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = `Request failed (HTTP ${res.status})`;
    try { const e = await res.json(); if (e.error) msg = e.error; } catch (_) { /* non-JSON */ }
    throw new Error(msg);
  }
  return wantBlob ? res.blob() : res.json();
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', async () => {
  wireTabs();
  wireUpload();
  wireResultsBar();
  wireRegister();
  wireRoadmap();
  wireAttestations();
  wireEvidence();
  wireExport();

  try {
    S.baseline = await api('/api/baseline');
    renderIntro();
  } catch (err) {
    // A failure here is almost always a deployment problem rather than a user
    // one, so point at the self-check endpoint instead of leaving a bare code.
    showUploadError(
      `Could not reach the audit service: ${err.message}. ` +
      `Open /api/health for a diagnosis of what the server is missing.`);
  }
});

function renderIntro() {
  const b = S.baseline;
  $('#badgeTotal').textContent = b.total;

  $('#modeSummary').innerHTML = [
    ['automated', 'Automated'], ['hybrid', 'Hybrid'], ['manual', 'Attested'],
  ].map(([k, label]) =>
    `<div class="mode-card"><b>${b.modes[k]}</b><span>${label}</span></div>`).join('');

  const pretty = {
    'hardened_server.json': 'Hardened server',
    'legacy_workstation.json': 'Legacy workstation',
    'mixed_endpoint.csv': 'Mixed endpoint (CSV)',
  };
  $('#sampleButtons').innerHTML = b.samples.map(s =>
    `<button class="btn small" data-sample="${esc(s)}">${esc(pretty[s] || s)}</button>`).join('');
  $$('#sampleButtons button').forEach(btn =>
    btn.addEventListener('click', () => runAudit({ kind: 'sample', sample: btn.dataset.sample })));
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------
function showUploadError(msg) {
  const el = $('#uploadError');
  el.textContent = msg;
  el.hidden = !msg;
}

function wireUpload() {
  const dz = $('#dropzone'), input = $('#fileInput');
  dz.addEventListener('click', () => input.click());
  dz.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
  });
  input.addEventListener('change', () => { if (input.files[0]) readFile(input.files[0]); });

  ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault(); dz.classList.add('drag');
  }));
  ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => {
    e.preventDefault(); dz.classList.remove('drag');
  }));
  dz.addEventListener('drop', e => {
    const f = e.dataTransfer.files[0];
    if (f) readFile(f);
  });
}

function readFile(file) {
  showUploadError('');
  // Vercel caps function request bodies at 4.5 MB; catch it here with a useful
  // message rather than letting the upload fail at the edge.
  if (file.size > 4 * 1024 * 1024) {
    showUploadError(`"${file.name}" is ${(file.size / 1048576).toFixed(1)} MB. ` +
      `The limit is 4 MB — a telemetry report is normally well under 200 KB, ` +
      `so check this is the right file.`);
    return;
  }
  const reader = new FileReader();
  reader.onerror = () => showUploadError(`Could not read "${file.name}".`);
  reader.onload = () => runAudit({ kind: 'content', content: reader.result, filename: file.name });
  reader.readAsText(file);
}

// ---------------------------------------------------------------------------
// Run the audit
// ---------------------------------------------------------------------------
function payload() {
  const p = {
    attestations: S.attestations,
    scopedOut: Array.from(S.scopedOut),
    strict: S.strict,
  };
  if (S.source.kind === 'sample') p.sample = S.source.sample;
  else { p.content = S.source.content; p.filename = S.source.filename; }
  return p;
}

async function runAudit(source, quiet) {
  if (source) {
    S.source = source;
    S.attestations = {};
    S.scopedOut = new Set();
  }
  busy(true, quiet ? 'Recalculating…' : 'Assessing 93 controls…');
  try {
    const data = await api('/api/audit', payload());
    S.report = data.report;
    S.evidence = data.evidence || {};
    S.meta = data.meta || {};
    S.sourceName = data.source;
    showUploadError('');
    renderAll(!quiet);
  } catch (err) {
    if (!S.report) showUploadError(err.message);
    else alert(`Could not recalculate: ${err.message}`);
  } finally {
    busy(false);
  }
}

function renderAll(firstLoad) {
  $('#intro').hidden = true;
  $('#results').hidden = false;

  const r = S.report, m = S.meta;
  $('#hostName').textContent = m.hostname || 'Unknown host';
  $('#hostMeta').textContent =
    `${m.os || 'Unknown OS'} · collected ${m.collected_utc || 'unknown'} · ` +
    `source ${S.sourceName} · ${m.populated_keys}/${m.total_keys} parameters populated`;

  const warn = $('#coverageWarning');
  if (r.coverage_warning) {
    warn.innerHTML = `<strong>Assessment coverage ${r.coverage}%</strong> — ${esc(r.coverage_warning)}`;
    warn.hidden = false;
  } else warn.hidden = true;

  renderMetrics();
  renderDashboard();
  renderRegister();
  renderRoadmap();
  renderAttestations();
  renderEvidence();
  renderSnapshot();

  if (firstLoad) {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    activateTab('dashboard');
  }
}

function renderMetrics() {
  const r = S.report, c = r.counts;
  const items = [
    [`${r.compliance_score}%`, 'Weighted compliance'],
    [c.PASS, 'Passed'],
    [c.FAIL, 'Failed'],
    [c.PARTIAL, 'Partial'],
    [c.MANUAL + c.NO_DATA, 'Manual / no data'],
    [r.risk_counts.High, 'High risks open'],
  ];
  $('#metrics').innerHTML = items.map(([v, l]) =>
    `<div class="metric"><b>${esc(v)}</b><span>${esc(l)}</span></div>`).join('');
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
function renderDashboard() {
  const r = S.report;
  drawGauge(r.compliance_score);
  $('#maturityLine').innerHTML =
    `Maturity: <strong>${esc(r.maturity)}</strong><br>` +
    `Unweighted pass rate ${r.raw_score}% · assessment coverage ${r.coverage}%`;

  const c = r.counts;
  const present = STATUS.filter(s => c[s] > 0);
  chart('donut', {
    type: 'doughnut',
    data: {
      labels: present,
      datasets: [{
        data: present.map(s => c[s]),
        backgroundColor: present.map(s => COLOR[s]),
        borderWidth: 2, borderColor: '#fff',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false, cutout: '58%',
      plugins: { legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } } },
    },
  });

  const themes = r.themes;
  chart('themeBar', {
    type: 'bar',
    data: {
      labels: themes.map(t => t.Theme),
      datasets: STATUS.filter(s => themes.some(t => t[s] > 0)).map(s => ({
        label: s, data: themes.map(t => t[s]), backgroundColor: COLOR[s],
      })),
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      scales: { x: { stacked: true, beginAtZero: true }, y: { stacked: true } },
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } } },
    },
  });

  chart('radar', {
    type: 'radar',
    data: {
      labels: themes.map(t => t.Theme),
      datasets: [
        {
          label: 'Achieved', data: themes.map(t => t['Compliance %']),
          borderColor: '#2563af', backgroundColor: 'rgba(37,99,175,.18)', pointRadius: 3,
        },
        {
          label: 'Target (75%)', data: themes.map(() => 75),
          borderColor: '#dc2626', borderDash: [5, 4], pointRadius: 0, fill: false,
        },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { r: { beginAtZero: true, max: 100, ticks: { stepSize: 25, font: { size: 9 } } } },
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 10 } } } },
    },
  });

  const rc = r.risk_counts;
  chart('riskBar', {
    type: 'bar',
    data: {
      labels: ['High', 'Medium', 'Low'],
      datasets: [{
        data: ['High', 'Medium', 'Low'].map(k => rc[k]),
        backgroundColor: ['High', 'Medium', 'Low'].map(k => COLOR[k]),
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      plugins: { legend: { display: false } },
    },
  });

  const top = r.roadmap.filter(x => x.Status === 'FAIL' || x.Status === 'PARTIAL').slice(0, 6);
  $('#topFindings').innerHTML = top.length ? top.map(i => `
    <div class="finding" style="border-left-color:${COLOR[i.Risk]}">
      <h4>${esc(i.Control)} — ${esc(i.Title)}
        <span class="pill ${cls(i.Risk)}">${esc(i.Risk)}</span></h4>
      <div class="muted">${esc(i.Finding)}</div>
      <div class="muted"><strong>${esc(i['Target Window'])}</strong> · ${esc(i.Phase)}</div>
    </div>`).join('')
    : `<p class="muted">No failed or partially implemented controls. Remaining gaps are
       attestation-only.</p>`;
}

function chart(id, config) {
  if (S.charts[id]) S.charts[id].destroy();
  S.charts[id] = new Chart($('#' + id).getContext('2d'), config);
}

function drawGauge(score) {
  // Semicircular arc. Drawn by hand rather than with a chart library so the
  // banded scale matches the PDF report exactly.
  const cx = 110, cy = 108, rad = 88, w = 17;
  const bands = [[0, 35, '#fecaca'], [35, 55, '#fed7aa'], [55, 75, '#fef08a'],
                 [75, 90, '#bbf7d0'], [90, 100, '#86efac']];
  const pt = (pct, r) => {
    const a = Math.PI * (1 - pct / 100);
    return [cx + r * Math.cos(a), cy - r * Math.sin(a)];
  };
  const arc = (from, to, r, stroke, width) => {
    const [x1, y1] = pt(from, r), [x2, y2] = pt(to, r);
    const large = (to - from) > 50 ? 1 : 0;
    return `<path d="M ${x1.toFixed(2)} ${y1.toFixed(2)} A ${r} ${r} 0 ${large} 1 ` +
           `${x2.toFixed(2)} ${y2.toFixed(2)}" fill="none" stroke="${stroke}" ` +
           `stroke-width="${width}" stroke-linecap="butt"/>`;
  };
  const val = Math.max(0, Math.min(100, score));
  const colour = val >= 75 ? '#16a34a' : val >= 50 ? '#ca8a04' : '#dc2626';
  const [nx, ny] = pt(val, rad - w / 2);

  $('#gauge').innerHTML =
    bands.map(([a, b, col]) => arc(a, b, rad - w / 2, col, w)).join('') +
    arc(0, Math.max(val, 0.4), rad - w / 2, colour, w - 5) +
    `<circle cx="${nx.toFixed(2)}" cy="${ny.toFixed(2)}" r="5.5" fill="#112240"/>` +
    `<text x="${cx}" y="${cy - 22}" text-anchor="middle" font-size="34" font-weight="700"
       fill="#112240">${val}%</text>` +
    `<text x="18" y="126" font-size="10" fill="#64748b">0</text>` +
    `<text x="196" y="126" font-size="10" fill="#64748b">100</text>` +
    `<text x="${cx}" y="126" text-anchor="middle" font-size="10" fill="#64748b">
       target 75%</text>`;
}

// ---------------------------------------------------------------------------
// Control register
// ---------------------------------------------------------------------------
function wireRegister() {
  ['#fTheme', '#fStatus', '#fRisk'].forEach(s =>
    $(s).addEventListener('change', renderRegisterRows));
  $('#fSearch').addEventListener('input', renderRegisterRows);
}

function renderRegister() {
  const r = S.report;
  fillSelect('#fTheme', [...new Set(r.controls.map(c => c.theme))].sort(), 'All themes');
  fillSelect('#fStatus', STATUS.filter(s => r.counts[s] > 0), 'All statuses');
  fillSelect('#fRisk', ['High', 'Medium', 'Low', 'None'], 'All risk levels');
  renderRegisterRows();
  $('#controlDetail').hidden = true;
}

function fillSelect(sel, values, allLabel) {
  const el = $(sel), keep = el.value;
  el.innerHTML = `<option value="">${esc(allLabel)}</option>` +
    values.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
  if (values.includes(keep)) el.value = keep;
}

function renderRegisterRows() {
  const theme = $('#fTheme').value, status = $('#fStatus').value,
        risk = $('#fRisk').value, q = $('#fSearch').value.trim().toLowerCase();
  const rows = S.report.controls.filter(c =>
    (!theme || c.theme === theme) && (!status || c.status === status) &&
    (!risk || c.risk === risk) &&
    (!q || c.id.toLowerCase().includes(q) || c.title.toLowerCase().includes(q)));

  $('#registerCount').textContent = `Showing ${rows.length} of ${S.report.controls.length} controls`;
  $('#registerTable tbody').innerHTML = rows.map(c => {
    const passed = c.checks.filter(x => x.passed).length;
    return `<tr class="clickable" data-id="${esc(c.id)}">
      <td class="mono">${esc(c.id)}</td><td>${esc(c.title)}</td>
      <td>${esc(c.theme)}</td><td>${esc(c.mode[0].toUpperCase() + c.mode.slice(1))}</td>
      <td><span class="pill ${cls(c.status)}">${esc(c.status)}</span></td>
      <td><span class="pill ${cls(c.risk)}">${esc(c.risk)}</span></td>
      <td class="mono">${c.checks.length ? `${passed}/${c.checks.length}` : '—'}</td>
    </tr>`;
  }).join('') || `<tr><td colspan="7" class="muted">No controls match these filters.</td></tr>`;

  $$('#registerTable tbody tr.clickable').forEach(tr =>
    tr.addEventListener('click', () => showControl(tr.dataset.id)));
}

function showControl(id) {
  const c = S.report.controls.find(x => x.id === id);
  if (!c) return;
  const checks = c.checks.length ? `
    <table class="data"><thead><tr>
      <th>Check</th><th>Result</th><th>Telemetry field</th><th>Rule</th><th>Observed</th>
    </tr></thead><tbody>
    ${c.checks.map(ch => `<tr>
      <td>${esc(ch.label)}</td>
      <td><span class="pill ${ch.passed === true ? 'PASS' : ch.passed === null ? 'NO_DATA' : 'FAIL'}">
        ${ch.passed === true ? 'PASS' : ch.passed === null ? 'NO DATA' : 'FAIL'}</span></td>
      <td class="mono">${esc(ch.field)}</td>
      <td class="mono">${esc(ch.op)} ${esc(ch.expected ?? '')}</td>
      <td class="mono">${ch.observed === null ? '<i>not collected</i>' : esc(fmt(ch.observed))}</td>
    </tr>`).join('')}
    </tbody></table>`
    : `<p class="muted">This control has no automatable technical check. Record an
       attestation in the Attestations tab.</p>`;

  $('#controlDetail').hidden = false;
  $('#controlDetail').innerHTML = `
    <h3>${esc(c.id)} — ${esc(c.title)}</h3>
    <div class="detail-grid">
      <div>
        <p><span class="pill ${cls(c.status)}">${esc(c.status)}</span>
           <span class="pill ${cls(c.risk)}">Risk: ${esc(c.risk)}</span></p>
        <div class="kv"><b>Theme</b> · ${esc(c.theme)}</div>
        <div class="kv"><b>Assessment mode</b> · ${esc(c.mode)}</div>
        <div class="kv"><b>Inherent severity</b> · ${esc(c.severity)}</div>
        <p><b>Objective</b><br>${esc(c.objective)}</p>
        <p><b>Finding</b><br>${esc(c.evidence)}</p>
      </div>
      <div>
        <h4>Technical checks</h4>
        ${checks}
        <h4 class="mt">Remediation guidance</h4>
        <ol>${c.remediation.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
      </div>
    </div>`;
  $('#controlDetail').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function fmt(v) {
  if (Array.isArray(v)) return v.length ? v.join(', ') : '(none)';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  return String(v);
}

// ---------------------------------------------------------------------------
// Roadmap
// ---------------------------------------------------------------------------
function wireRoadmap() {
  $('#rPhase').addEventListener('change', renderRoadmapList);
  $('#rRisk').addEventListener('change', renderRoadmapList);
  $('#roadmapCsv').addEventListener('click', downloadRoadmapCsv);
}

function renderRoadmap() {
  fillSelect('#rPhase', [...new Set(S.report.roadmap.map(i => i.Phase))].sort(), 'All phases');
  fillSelect('#rRisk', ['High', 'Medium', 'Low'], 'All risk levels');
  renderRoadmapList();
}

function renderRoadmapList() {
  const phase = $('#rPhase').value, risk = $('#rRisk').value;
  const items = S.report.roadmap.filter(i =>
    (!phase || i.Phase === phase) && (!risk || i.Risk === risk));
  $('#roadmapCount').textContent = `${items.length} item${items.length === 1 ? '' : 's'}`;

  $('#roadmapList').innerHTML = items.slice(0, 60).map(i => `
    <div class="rm-item">
      <div class="rm-head" data-open="0">
        <span class="cid">#${i.Priority} ${esc(i.Control)}</span>
        <span class="grow">${esc(i.Title)}</span>
        <span class="pill ${cls(i.Risk)}">${esc(i.Risk)}</span>
        <span class="pill ${cls(i.Status)}">${esc(i.Status)}</span>
        <span class="muted">${esc(i['Target Window'])}</span>
      </div>
      <div class="rm-body" hidden>
        <p><strong>Finding</strong> — ${esc(i.Finding)}</p>
        ${i['Failed Checks'].length ? `<p><strong>Failed checks</strong></p><ul>${
          i['Failed Checks'].map(f => `<li class="failed-check">${esc(f)}</li>`).join('')}</ul>` : ''}
        <p><strong>Remediation steps</strong></p>
        <ol>${i['Remediation Steps'].map(s => `<li>${esc(s)}</li>`).join('')}</ol>
      </div>
    </div>`).join('') || `<p class="muted">Nothing matches these filters.</p>`;

  $$('#roadmapList .rm-head').forEach(h => h.addEventListener('click', () => {
    const body = h.nextElementSibling;
    body.hidden = !body.hidden;
  }));

  if (items.length > 60) {
    $('#roadmapList').insertAdjacentHTML('beforeend',
      `<p class="muted">Showing the first 60 of ${items.length} items —
        narrow the filters or download the CSV for the full list.</p>`);
  }
}

function csvCell(v) {
  const s = Array.isArray(v) ? v.join(' | ') : String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadRoadmapCsv() {
  const cols = ['Priority', 'Phase', 'Target Window', 'Control', 'Title', 'Theme',
                'Status', 'Risk', 'Finding', 'Remediation Steps'];
  const lines = [cols.join(',')].concat(
    S.report.roadmap.map(i => cols.map(c => csvCell(i[c])).join(',')));
  download(new Blob([lines.join('\r\n')], { type: 'text/csv' }),
    `iso27001_roadmap_${S.meta.hostname || 'host'}.csv`);
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------
function wireAttestations() {
  $('#attestOpenOnly').addEventListener('change', renderAttestations);
  $('#attestExport').addEventListener('click', () =>
    download(new Blob([JSON.stringify(S.attestations, null, 2)], { type: 'application/json' }),
      'iso27001_attestations.json'));
  $('#attestImport').addEventListener('click', () => $('#attestFile').click());
  $('#attestFile').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    const fr = new FileReader();
    fr.onload = () => {
      try {
        const obj = JSON.parse(fr.result);
        if (typeof obj !== 'object' || Array.isArray(obj)) throw new Error('Expected a JSON object');
        S.attestations = obj;
        runAudit(null, true);
      } catch (err) { alert(`Could not read attestations: ${err.message}`); }
    };
    fr.readAsText(f);
    e.target.value = '';
  });
}

function renderAttestations() {
  const attestable = S.report.controls.filter(c => c.attestation);
  const openOnly = $('#attestOpenOnly').checked;
  const answered = Object.keys(S.attestations).filter(k => S.attestations[k] != null).length;

  $('#attestProgress').style.width = `${(answered / Math.max(1, attestable.length)) * 100}%`;
  $('#attestCount').textContent =
    `${answered} of ${attestable.length} attestable controls answered`;

  let html = '';
  for (const theme of ['Organizational', 'People', 'Physical', 'Technological']) {
    const group = attestable.filter(c => c.theme === theme &&
      (!openOnly || S.attestations[c.attestation] == null));
    if (!group.length) continue;
    html += `<div class="attest-theme">${esc(theme)}</div>`;
    html += group.map(c => {
      const cur = S.attestations[c.attestation];
      const opt = (val, label) => {
        const checked = (val === null ? cur == null : cur === val) ? 'checked' : '';
        return `<label><input type="radio" name="att_${cls(c.id)}"
          data-key="${esc(c.attestation)}" data-val="${val}" ${checked}><span>${label}</span></label>`;
      };
      return `<div class="attest-row">
        <span class="grow"><span class="cid">${esc(c.id)}</span> ${esc(c.title)}
          <div class="muted">${esc(c.objective)}</div></span>
        <span class="radios">${opt(null, 'Not assessed')}${opt(true, 'Implemented')}${opt(false, 'Not implemented')}</span>
      </div>`;
    }).join('');
  }
  $('#attestList').innerHTML = html ||
    `<p class="muted">Every attestable control has been answered.</p>`;

  $$('#attestList input[type=radio]').forEach(el => el.addEventListener('change', () => {
    const key = el.dataset.key, v = el.dataset.val;
    if (v === 'null') delete S.attestations[key];
    else S.attestations[key] = v === 'true';
    runAudit(null, true);
  }));

  renderScope();
}

function renderScope() {
  $('#scopeList').innerHTML = S.report.controls.map(c =>
    `<label><input type="checkbox" data-id="${esc(c.id)}"
      ${S.scopedOut.has(c.id) ? 'checked' : ''}> ${esc(c.id)} ${esc(c.title)}</label>`).join('');
  $$('#scopeList input').forEach(el => el.addEventListener('change', () => {
    if (el.checked) S.scopedOut.add(el.dataset.id); else S.scopedOut.delete(el.dataset.id);
    runAudit(null, true);
  }));
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------
function wireEvidence() {
  $('#eSection').addEventListener('change', renderEvidenceRows);
  $('#eSearch').addEventListener('input', renderEvidenceRows);
}

function renderEvidence() {
  const sections = [...new Set(Object.keys(S.evidence)
    .filter(k => k.includes('.')).map(k => k.split('.')[0]))].sort();
  fillSelect('#eSection', sections, 'All sections');
  renderEvidenceRows();
}

function renderEvidenceRows() {
  const sec = $('#eSection').value, q = $('#eSearch').value.trim().toLowerCase();
  const rows = Object.entries(S.evidence)
    .filter(([k]) => (!sec || k.startsWith(sec + '.')) && (!q || k.toLowerCase().includes(q)))
    .sort(([a], [b]) => a.localeCompare(b));

  $('#evidenceCount').textContent = `${rows.length} parameters`;
  $('#evidenceTable tbody').innerHTML = rows.map(([k, v]) => `
    <tr><td class="mono">${esc(k)}</td>
        <td>${v === null ? '<i class="muted">not collected</i>' : esc(fmt(v))}</td>
        <td class="muted">${v === null ? 'null' : Array.isArray(v) ? 'list' : typeof v}</td></tr>`
  ).join('') || `<tr><td colspan="3" class="muted">No parameters match.</td></tr>`;
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------
function wireExport() {
  $('#pdfBtn').addEventListener('click', buildPdf);
  $('#dlRegister').addEventListener('click', () => {
    const cols = ['id', 'title', 'theme', 'mode', 'status', 'risk', 'severity', 'evidence'];
    const head = ['Control', 'Title', 'Theme', 'Mode', 'Status', 'Risk', 'Severity', 'Finding'];
    const lines = [head.join(',')].concat(
      S.report.controls.map(c => cols.map(k => csvCell(c[k])).join(',')));
    download(new Blob([lines.join('\r\n')], { type: 'text/csv' }),
      `iso27001_register_${S.meta.hostname || 'host'}.csv`);
  });
  $('#dlResults').addEventListener('click', () =>
    download(new Blob([JSON.stringify(S.report, null, 2)], { type: 'application/json' }),
      `iso27001_results_${S.meta.hostname || 'host'}.json`));
  $('#dlEvidence').addEventListener('click', () =>
    download(new Blob([JSON.stringify(S.evidence, null, 2)], { type: 'application/json' }),
      `telemetry_${S.meta.hostname || 'host'}.json`));
}

async function buildPdf() {
  const btn = $('#pdfBtn'), status = $('#pdfStatus');
  btn.disabled = true;
  status.textContent = 'Rendering…';
  busy(true, 'Building the PDF audit report…');
  try {
    const body = Object.assign(payload(), {
      org: $('#expOrg').value,
      auditor: $('#expAuditor').value,
      scopeNote: $('#expScope').value,
      sections: {
        register: $('#secRegister').checked,
        roadmap: $('#secRoadmap').checked,
        appendix: $('#secAppendix').checked,
      },
    });
    const blob = await api('/api/report', body, true);
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    download(blob, `ISO27001_Audit_${S.meta.hostname || 'host'}_${date}.pdf`);
    status.textContent = `Downloaded — ${(blob.size / 1024).toFixed(0)} KB`;
  } catch (err) {
    status.textContent = `Failed: ${err.message}`;
  } finally {
    btn.disabled = false;
    busy(false);
  }
}

function renderSnapshot() {
  const r = S.report;
  $('#snapshot').textContent = JSON.stringify({
    host: r.host, compliance_score: r.compliance_score, raw_score: r.raw_score,
    coverage: r.coverage, maturity: r.maturity,
    counts: r.counts, risk_counts: r.risk_counts,
  }, null, 2);
}

// ---------------------------------------------------------------------------
// Tabs & results bar
// ---------------------------------------------------------------------------
function wireTabs() {
  $$('.tab').forEach(t => t.addEventListener('click', () => activateTab(t.dataset.tab)));
}

function activateTab(name) {
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.panel').forEach(p => p.classList.toggle('active', p.id === `panel-${name}`));
}

function wireResultsBar() {
  $('#strictToggle').addEventListener('change', e => {
    S.strict = e.target.checked;
    runAudit(null, true);
  });
  $('#newAuditBtn').addEventListener('click', () => {
    S.report = null; S.source = null; S.attestations = {}; S.scopedOut = new Set();
    S.strict = false; $('#strictToggle').checked = false;
    $('#results').hidden = true;
    $('#intro').hidden = false;
    $('#fileInput').value = '';
    showUploadError('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

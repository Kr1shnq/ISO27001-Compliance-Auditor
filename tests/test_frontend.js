/* test_frontend.js
 * ----------------
 * Loads public/index.html in jsdom, executes the real public/app.js against a
 * live API, and drives the interface the way a user would: pick a sample, read
 * the dashboard, filter the register, open a control, expand a roadmap item,
 * record an attestation, scope a control out, toggle strict mode.
 *
 * Catches the class of bug a Python test cannot: JS exceptions, DOM wiring
 * mistakes, and element IDs referenced in script but absent from the markup.
 *
 * Requires a dev server already running (tests/test_frontend.py starts one):
 *     node tests/test_frontend.js <baseUrl>
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { JSDOM, VirtualConsole } = require('jsdom');

const BASE = process.argv[2] || 'http://127.0.0.1:3000';
const ROOT = path.dirname(__dirname);
const failed = [];
const jsErrors = [];

function check(name, cond, detail = '') {
  console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? '  -> ' + detail : ''}`);
  if (!cond) failed.push(name);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** Wait until fn() is truthy, or time out. */
async function until(fn, ms = 15000, step = 60) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    try { if (fn()) return true; } catch (_) { /* not ready */ }
    await sleep(step);
  }
  return false;
}

(async () => {
  const html = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(ROOT, 'public', 'styles.css'), 'utf8');
  const js = fs.readFileSync(path.join(ROOT, 'public', 'app.js'), 'utf8');

  // jsdom has no navigation or download implementation, so the anchor-click
  // trick used to save a file logs a "not implemented" notice. That is a gap in
  // the test environment, not a fault in the app — everything else must stay
  // fatal so real exceptions cannot hide behind it.
  const KNOWN_JSDOM_GAPS = [/Not implemented: navigation/i];
  const record = msg => {
    if (!KNOWN_JSDOM_GAPS.some(rx => rx.test(msg))) jsErrors.push(msg);
  };

  const vc = new VirtualConsole();
  vc.on('jsdomError', e => record(e.message));
  vc.on('error', (...a) => record(a.join(' ')));

  const dom = new JSDOM(html, {
    url: BASE + '/',
    runScripts: 'outside-only',
    pretendToBeVisual: true,
    virtualConsole: vc,
  });
  const { window } = dom;

  // ---- stubs for things jsdom lacks -------------------------------------
  // Chart.js needs a real canvas; record the configs instead so the test can
  // assert on what would have been drawn.
  window.__charts = {};
  window.Chart = class {
    constructor(ctx, cfg) { window.__charts[ctx.__id] = cfg; }
    destroy() {}
  };
  window.HTMLCanvasElement.prototype.getContext = function () { return { __id: this.id }; };
  window.URL.createObjectURL = () => 'blob:stub';
  window.URL.revokeObjectURL = () => {};
  window.scrollTo = () => {};
  window.Element.prototype.scrollIntoView = () => {};
  window.alert = m => jsErrors.push('alert: ' + m);
  // Node's global fetch requires an absolute URL, whereas the app quite
  // correctly uses same-origin relative paths. Resolve them against the base.
  window.fetch = (url, opts) => fetch(new URL(url, BASE).href, opts);
  window.Blob = global.Blob;
  window.FileReader = class {
    readAsText(file) {
      Promise.resolve(file.text()).then(t => {
        this.result = t;
        if (this.onload) this.onload();
      });
    }
  };

  // Apply the stylesheet only to prove it parses; layout is irrelevant here.
  const style = window.document.createElement('style');
  style.textContent = css;
  window.document.head.appendChild(style);

  window.eval(js);
  window.document.dispatchEvent(new window.Event('DOMContentLoaded'));

  const $ = s => window.document.querySelector(s);
  const $$ = s => Array.from(window.document.querySelectorAll(s));
  const click = el => el.dispatchEvent(new window.Event('click', { bubbles: true }));
  const change = el => el.dispatchEvent(new window.Event('change', { bubbles: true }));
  const input = el => el.dispatchEvent(new window.Event('input', { bubbles: true }));

  // ---------------------------------------------------------------------
  console.log('\n=== 1. Boot and baseline ===');
  const booted = await until(() => $$('#sampleButtons button').length === 3);
  check('Baseline loaded and sample buttons rendered', booted,
    `${$$('#sampleButtons button').length} buttons`);
  check('Control total shown in header', $('#badgeTotal').textContent === '93',
    $('#badgeTotal').textContent);
  check('Mode summary rendered', $$('#modeSummary .mode-card').length === 3);
  check('No upload error on boot', $('#uploadError').hidden);

  // ---------------------------------------------------------------------
  console.log('\n=== 2. Run an audit from a sample ===');
  click($$('#sampleButtons button').find(b => b.dataset.sample === 'legacy_workstation.json'));
  const ran = await until(() => !$('#results').hidden && $$('#metrics .metric').length === 6);
  check('Results section shown', ran);
  check('Six metric cards rendered', $$('#metrics .metric').length === 6);
  check('Weighted compliance is 13.4%', $('#metrics .metric b').textContent === '13.4%',
    $('#metrics .metric b').textContent);
  check('Host name populated', $('#hostName').textContent === 'WS-FIN-014',
    $('#hostName').textContent);
  check('Intro hidden', $('#intro').hidden);

  console.log('\n=== 3. Dashboard ===');
  check('Gauge rendered as SVG', $('#gauge').innerHTML.includes('<path'),
    `${$('#gauge').innerHTML.length} chars`);
  check('Gauge shows the score', $('#gauge').textContent.includes('13.4'),
    $('#gauge').textContent.trim().slice(0, 30));
  check('Maturity line populated', $('#maturityLine').textContent.includes('Initial'),
    $('#maturityLine').textContent.slice(0, 46));
  for (const id of ['donut', 'themeBar', 'radar', 'riskBar']) {
    check(`Chart '${id}' configured`, !!window.__charts[id],
      window.__charts[id] ? window.__charts[id].type : 'missing');
  }
  check('Donut has data', window.__charts.donut.data.datasets[0].data.length > 0);
  check('Theme bar covers 4 themes', window.__charts.themeBar.data.labels.length === 4,
    String(window.__charts.themeBar.data.labels));
  check('Radar has achieved + target series',
    window.__charts.radar.data.datasets.length === 2);
  check('Top findings rendered', $$('#topFindings .finding').length > 0,
    `${$$('#topFindings .finding').length} cards`);

  console.log('\n=== 4. Control register ===');
  click($$('.tab').find(t => t.dataset.tab === 'register'));
  check('Register panel active', $('#panel-register').classList.contains('active'));
  check('93 rows rendered', $$('#registerTable tbody tr').length === 93,
    String($$('#registerTable tbody tr').length));

  $('#fStatus').value = 'FAIL'; change($('#fStatus'));
  await sleep(60);
  const failRows = $$('#registerTable tbody tr').length;
  check('Status filter narrows rows', failRows > 0 && failRows < 93, `${failRows} FAIL rows`);

  $('#fStatus').value = ''; change($('#fStatus'));
  $('#fSearch').value = 'A.8.5'; input($('#fSearch'));
  await sleep(60);
  check('Search filters by control ID', $$('#registerTable tbody tr').length >= 1,
    String($$('#registerTable tbody tr').length));
  $('#fSearch').value = ''; input($('#fSearch'));
  await sleep(60);

  click($$('#registerTable tbody tr')[0]);
  await sleep(80);
  check('Control detail opens', !$('#controlDetail').hidden);
  check('Detail shows remediation steps', $$('#controlDetail ol li').length > 0,
    `${$$('#controlDetail ol li').length} steps`);

  $('#fSearch').value = 'A.8.7'; input($('#fSearch'));
  await sleep(60);
  click($$('#registerTable tbody tr')[0]);
  await sleep(80);
  check('Detail shows the individual checks table',
    $$('#controlDetail table.data tbody tr').length > 0,
    `${$$('#controlDetail table.data tbody tr').length} checks`);
  $('#fSearch').value = ''; input($('#fSearch'));
  await sleep(60);

  console.log('\n=== 5. Roadmap ===');
  click($$('.tab').find(t => t.dataset.tab === 'roadmap'));
  const items = $$('#roadmapList .rm-item');
  check('Roadmap items rendered', items.length > 0, `${items.length} items`);
  check('Bodies start collapsed', $$('#roadmapList .rm-body')[0].hidden);
  click($$('#roadmapList .rm-head')[0]);
  await sleep(60);
  check('Clicking a head expands it', !$$('#roadmapList .rm-body')[0].hidden);
  check('Expanded item lists remediation steps',
    $$('#roadmapList .rm-body')[0].querySelectorAll('ol li').length > 0);

  $('#rRisk').value = 'High'; change($('#rRisk'));
  await sleep(60);
  check('Risk filter applies', $('#roadmapCount').textContent.match(/^\d+ item/) !== null,
    $('#roadmapCount').textContent);
  $('#rRisk').value = ''; change($('#rRisk'));
  await sleep(60);

  console.log('\n=== 6. Evidence ===');
  click($$('.tab').find(t => t.dataset.tab === 'evidence'));
  check('Evidence rows rendered', $$('#evidenceTable tbody tr').length > 100,
    String($$('#evidenceTable tbody tr').length));
  $('#eSearch').value = 'mfa'; input($('#eSearch'));
  await sleep(60);
  check('Evidence search filters',
    $$('#evidenceTable tbody tr').length > 0 && $$('#evidenceTable tbody tr').length < 20,
    String($$('#evidenceTable tbody tr').length));
  $('#eSearch').value = ''; input($('#eSearch'));

  console.log('\n=== 7. Attestations (round-trips to the API) ===');
  click($$('.tab').find(t => t.dataset.tab === 'attest'));
  await sleep(80);
  const radios = $$('#attestList input[type=radio]');
  check('Attestation controls rendered', radios.length > 0, `${radios.length} radios`);
  const before = $('#metrics .metric b').textContent;
  const implemented = radios.find(r => r.dataset.val === 'true');
  implemented.checked = true;
  change(implemented);
  const recalculated = await until(() =>
    $('#attestCount').textContent.startsWith('1 of'), 15000);
  check('Attestation recorded and re-audited', recalculated, $('#attestCount').textContent);
  check('Score updated after attestation',
    $('#metrics .metric b').textContent !== before,
    `${before} -> ${$('#metrics .metric b').textContent}`);

  const scopeBoxes = $$('#scopeList input');
  check('Scope exclusion list rendered', scopeBoxes.length === 93, String(scopeBoxes.length));
  scopeBoxes[0].checked = true;
  change(scopeBoxes[0]);
  await sleep(1200);
  check('Scoping a control out is reflected in the register',
    $$('#registerTable tbody tr').some(tr => tr.textContent.includes('N/A')),
    'N/A row present');

  console.log('\n=== 8. Strict mode ===');
  const preStrict = $('#metrics .metric b').textContent;
  $('#strictToggle').checked = true;
  change($('#strictToggle'));
  const strictDone = await until(() =>
    $('#metrics .metric b').textContent !== preStrict, 15000);
  check('Strict mode changes the score', strictDone,
    `${preStrict} -> ${$('#metrics .metric b').textContent}`);
  $('#strictToggle').checked = false;
  change($('#strictToggle'));
  await sleep(1200);

  console.log('\n=== 9. Export ===');
  click($$('.tab').find(t => t.dataset.tab === 'export'));
  check('Snapshot rendered', $('#snapshot').textContent.includes('compliance_score'));
  let downloaded = null;
  window.URL.createObjectURL = b => { downloaded = b; return 'blob:stub'; };
  click($('#dlRegister'));
  await sleep(150);
  check('Register CSV generated', downloaded && downloaded.size > 1000,
    downloaded ? `${downloaded.size} bytes` : 'none');
  downloaded = null;
  click($('#dlResults'));
  await sleep(150);
  check('Results JSON generated', downloaded && downloaded.size > 10000,
    downloaded ? `${downloaded.size} bytes` : 'none');

  downloaded = null;
  click($('#pdfBtn'));
  const pdfDone = await until(() => $('#pdfStatus').textContent.includes('Downloaded') ||
    $('#pdfStatus').textContent.includes('Failed'), 40000);
  check('PDF export completes', pdfDone && $('#pdfStatus').textContent.includes('Downloaded'),
    $('#pdfStatus').textContent);
  check('PDF blob is a plausible size', downloaded && downloaded.size > 15000,
    downloaded ? `${(downloaded.size / 1024).toFixed(0)} KB` : 'none');

  console.log('\n=== 10. New audit resets state ===');
  click($('#newAuditBtn'));
  await sleep(80);
  check('Back to the intro screen', !$('#intro').hidden && $('#results').hidden);

  console.log('\n=== 11. Error handling ===');
  // A file the parser cannot read must surface a message, not a silent failure.
  const badFile = new window.File(['@@@ not telemetry @@@'], 'bad.json',
    { type: 'application/json' });
  Object.defineProperty($('#fileInput'), 'files', { value: [badFile], configurable: true });
  change($('#fileInput'));
  const errShown = await until(() => !$('#uploadError').hidden, 15000);
  check('Unreadable upload shows an error', errShown, $('#uploadError').textContent.slice(0, 70));

  console.log('\n=== 12. No uncaught JavaScript errors ===');
  check('Console clean', jsErrors.length === 0, jsErrors.slice(0, 3).join(' | ') || 'none');

  console.log('\n' + '='.repeat(62));
  if (failed.length) {
    console.log(`RESULT: ${failed.length} check(s) FAILED`);
    failed.forEach(f => console.log('   - ' + f));
    process.exit(1);
  }
  console.log('RESULT: all frontend checks passed');
  console.log('='.repeat(62));
  process.exit(0);
})().catch(err => {
  console.error('\nFATAL:', err && err.stack || err);
  process.exit(1);
});

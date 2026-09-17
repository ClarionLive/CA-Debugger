// Regression check: a Variables/Watch row must never keep a STALE instance address or its edit pencil.
//
// Rows are reused across stops. A row that resolved to one thread's instance and then gets a reply with no
// va (THREADed data not yet used on that thread, or a read that failed) used to keep the old va, the
// 'editable' class and a live pencil, so committing an edit wrote ANOTHER thread's memory while the row
// displayed the template value.
//
// Runs the REAL clearEditMeta/setEditMeta/wireEdit/applyValue out of debugger.html against a minimal DOM.
// Point it at a pre-fix copy of the page and steps 2 and 3 fail - that is the before/after proof.
//
//   node tools/test-pad-editmeta.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
// The mini-DOM and the page-function extractor are shared with the pad's other tests (tools/pad-dom.js).
const pad = require('./pad-dom');
const html = pad.readPage(process.argv[2]);
const extract = name => pad.extract(html, name);
const El = pad.El;

// ---- scenario state: this test drives ONE row at a time, so the document stub is deliberately tiny ----
let ROW = null;
let DETAIL = null;          // an OPEN Watch detail panel, when a scenario registers one
const document = {
  createElement: t => new El(t),
  querySelectorAll: sel => (sel.startsWith('[data-name=') && ROW) ? [ROW] : [],
  querySelector: sel => {
    const m = /^\.wdetail\[data-detail="(.*)"\]$/.exec(sel);
    if (m && DETAIL && DETAIL.dataset.detail === m[1]) return DETAIL;
    return null;
  },
};
// the hover data-tip's own elements ($('dtName') / $('dtType') / $('dtVal')) and the tip container
const TIP_ELS = {};
const $ = id => (TIP_ELS[id] = TIP_ELS[id] || new El('span'));
const tip = new El('div');
const window = { innerWidth: 1200, innerHeight: 800 };
let tipTarget = null, tipTimer = null;
// deps applyValue touches that are not under test
const values = new Map();
const cssEsc = s => s.replace(/["\\]/g, '\\$&');
const beginEdit = () => {};
const STAR = '*';
// dtApply is REAL, not a stub: it inserts its own .vas tag next to the same cell and runs AFTER wireEdit,
// so on a DATE/TIME/integer row it sits between the cell and the pencil. Stubbing it out is precisely how a
// position-based pencil lookup passed this test while leaving a live pencil on every numeric row.
const dtModes = {};

// clearEditMeta exists only in the FIXED page; running this against the pre-fix one is the before/after proof
const src = ['dtParseInt','fieldPart','fmtClarionDate','fmtClarionTime','dtDefault','dtModeFor','dtApply','dtCycle',
             'clearEditMeta','setEditMeta','applyNote','wireEdit','applyValue','showTipFor'].map(n => {
  try { return extract(n); }
  catch (e) { console.log('   (note: ' + n + ' absent — pre-fix page)'); return 'function ' + n + '(){}'; }
}).join('\n');
eval(src);

// ---- scenario ----
function makeRow(name){
  const tree = new El('div');                    // rows live in a container (the THREAD tag inserts beside the row)
  const row = new El('div'); row.dataset.name = name || 'AUT:AU_LNAME';
  const v = new El('span'); v.classList.add('vval','pending'); v.textContent = '…';
  row.append(v); tree.append(row); ROW = row; return row;
}
// sibling order after the cell, which is what a position-based lookup gets wrong
function siblings(row){ return row.children.map(c => c.classList.toString().split(' ')[0]).join(','); }
function state(row){
  const v = row.querySelector('.vval');
  const btn = row.querySelector('.vedit-btn');
  return { text: v.textContent, cls: v.classList.toString(), va: v.dataset.va, pencil: !!btn, title: v.title };
}
const THREAD_A = { va: '0x847A76', typeCode: '0x18', size: 41, places: 0 };

let failures = 0;
function check(label, cond, detail){
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

console.log('1) stop on thread A: value resolves to an instance');
const row = makeRow();
applyValue('AUT:AU_LNAME', true, "'Del Castillo'", 'STRING(41)', true, THREAD_A);
let s = state(row); console.log('   ' + JSON.stringify(s));
check('row is editable, bound to A, pencil shown', s.cls.includes('editable') && s.va === THREAD_A.va && s.pencil);

console.log('2) later stop: engine reports the value not yet allocated on this thread (no va)');
applyValue('AUT:AU_LNAME', true, "''", 'STRING(41)', true, { note: 'not yet used on this thread — initial value' });
s = state(row); console.log('   ' + JSON.stringify(s));
check("stale instance VA cleared", s.va === undefined, 'va=' + s.va);
check("'editable' cleared", !s.cls.includes('editable'));
check('edit pencil removed', !s.pencil);
check('note surfaced', s.cls.includes('noted') && !!s.title);

console.log('3) re-bind to an instance, then a failed read (found:false + error)');
applyValue('AUT:AU_LNAME', true, "'Del Castillo'", 'STRING(41)', true, THREAD_A);
applyValue('AUT:AU_LNAME', false, null, null, false, { error: 'THR$GetInstance is not emulatable on this runtime' });
s = state(row); console.log('   ' + JSON.stringify(s));
check("stale instance VA cleared", s.va === undefined, 'va=' + s.va);
check('edit pencil removed', !s.pencil);
check('row reads (unavailable), not "…"', s.text === '(unavailable)' && s.cls.includes('unavail'));
check('reason in tooltip', !!s.title);

console.log('4) a normal reply still re-arms editing');
applyValue('AUT:AU_LNAME', true, "'White'", 'STRING(41)', true, THREAD_A);
s = state(row); console.log('   ' + JSON.stringify(s));
check('editable + va + pencil restored', s.cls.includes('editable') && s.va === THREAD_A.va && s.pencil);

// ---- the same lifecycle on rows where dtApply inserts a .vas tag between the cell and the pencil ----
// A STRING row alone never exercises that ordering, which is how a position-based pencil lookup slipped through.
function numericScenario(label, name, resolved, typeName, meta, rawTooltip){
  console.log(label);
  const NOTE = 'not yet used on this thread — initial value';
  const ERR = 'THR$GetInstance returned no instance';
  const row = makeRow(name);
  applyValue(name, true, resolved, typeName, true, meta);
  let s = state(row);
  console.log('   after a resolved reply: ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('pencil armed, .vas tag present', s.pencil && siblings(row).includes('vas'));
  // dtApply owns the tooltip for an ORDINARY value and must keep doing so
  if (rawTooltip) check("dtApply's raw tooltip preserved", s.title === rawTooltip, 'title=' + JSON.stringify(s.title));

  applyValue(name, true, resolved, typeName, true, { note: NOTE });
  s = state(row);
  console.log('   after a no-va reply:    ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('stale instance VA cleared', s.va === undefined, 'va=' + s.va);
  check("'editable' cleared", !s.cls.includes('editable'));
  check('edit pencil removed', !s.pencil, 'siblings=[' + siblings(row) + ']');
  // the dotted 'noted' underline is meaningless without the explanation behind it
  check('note survives dtApply in the tooltip', s.title === NOTE, 'title=' + JSON.stringify(s.title));

  applyValue(name, false, null, null, false, { error: ERR });
  s = state(row);
  console.log('   after a failed read:    ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('edit pencil removed', !s.pencil, 'siblings=[' + siblings(row) + ']');
  check('engine reason in the tooltip', s.title === ERR, 'title=' + JSON.stringify(s.title));
}
numericScenario('5) LONG row (dtApply inserts .vas between the cell and the pencil)',
                'JOB:JOBID', '4711', 'LONG', { va: '0x847B20', typeCode: '0x11', size: 4, places: 0 }, '');
numericScenario('6) DATE row (same ordering, value rendered as a date, raw kept in the tooltip)',
                'TIT:PUBDATE', '80000', 'ULONG', { va: '0x847B40', typeCode: '0x12', size: 4, places: 0 }, 'raw: 80000');

// ---- the `values` cache behind the hover data-tip and the Watch detail panel ----
// It is read by BOTH of those long after the reply that filled it, so it has to carry the caveat with the
// value and be evicted when a reply resolves to nothing. Otherwise a qualified value (shared template /
// not yet used on this thread) reads as an ordinary live value, and a name the engine could not read keeps
// quoting the previous stop's value.
console.log('7) hover data-tip reflects a qualified value, and forgets an unreadable one');
{
  const name = 'TIT:PUBDATE';
  const row = makeRow(name);
  const tEl = new El('span'); tEl.classList.add('vtype'); tEl.textContent = 'ULONG'; row.append(tEl);

  applyValue(name, true, '80000', 'ULONG', true, { note: 'no thread instance — shared template value' });
  showTipFor(row);
  console.log('   tip after a template-value reply: ' + JSON.stringify($('dtVal').textContent));
  check('tip carries the caveat', $('dtVal').textContent.includes('no thread instance'));

  applyValue(name, false, null, null, false, { error: 'could not resolve the thread\'s TEB' });
  showTipFor(row);
  console.log('   tip after a failed read:          ' + JSON.stringify($('dtVal').textContent));
  check('tip drops the stale value', !$('dtVal').textContent.includes('2020-01-09') && !$('dtVal').textContent.includes('80000'),
        'tip=' + JSON.stringify($('dtVal').textContent));
  check('tip shows the unavailable state', $('dtVal').textContent.includes('(unavailable)'));

  // The tip a SOURCE identifier raises has no row behind it, so it reads the cache directly — this is the
  // path where a stale entry is actually visible, and the one the eviction exists for.
  const token = new El('span'); token.dataset.name = name;   // no .vval child
  showTipFor(token);
  console.log('   tip over a source identifier:     ' + JSON.stringify($('dtVal').textContent));
  check('source tip quotes no stale value', !$('dtVal').textContent.includes('2020-01-09') && !$('dtVal').textContent.includes('80000'),
        'tip=' + JSON.stringify($('dtVal').textContent));
}

console.log('8) an OPEN Watch detail panel follows the row when the read fails');
{
  const name = 'AUT:AU_LNAME';
  const row = makeRow(name); row.classList.add('watchrow');
  DETAIL = new El('div'); DETAIL.classList.add('wdetail'); DETAIL.dataset.detail = name; DETAIL.style.display = '';

  applyValue(name, true, "'Del Castillo'", 'STRING(41)', true, { va: '0x847A76', typeCode: '0x18', size: 41, places: 0 });
  console.log('   detail after a resolved reply: ' + JSON.stringify(DETAIL.textContent));
  check('detail shows the value', DETAIL.textContent === "'Del Castillo'");

  applyValue(name, false, null, null, false, { error: 'THR$GetInstance returned no instance' });
  console.log('   detail after a failed read:    ' + JSON.stringify(DETAIL.textContent));
  check('open detail no longer shows the stale value', DETAIL.textContent !== "'Del Castillo'",
        'detail=' + JSON.stringify(DETAIL.textContent));
  check('detail shows the unavailable state', DETAIL.textContent === '(unavailable)');
  DETAIL = null;
}

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

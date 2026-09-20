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
//   node tools/test-pad-editmeta.js [path/to/debugger.html] [--allow-missing]
// Exit code 0 = all checks passed.
// The mini-DOM and the page-function extractor are shared with the pad's other tests (tools/pad-dom.js).
//
// --allow-missing stubs out any page function this file cannot find, instead of refusing to run. It exists
// ONLY for the deliberate pre-fix run described above, where clearEditMeta genuinely does not exist yet.
// Without it a missing target is a HARD FAILURE: silently stubbing a renamed function turns every check
// that depends on it into a vacuous pass that still exits 0.
const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const ALLOW_MISSING = argv.includes('--allow-missing');
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const extract = name => pad.extract(html, name);
const El = pad.El;

// ---- scenario state: this test drives ONE row at a time, so the document stub is deliberately tiny ----
let selTid = null, stopTid = null;   // no thread selection in this suite: editThreadSuffix() -> ''
let ROW = null;
let DETAIL = null;          // an OPEN Watch detail panel, when a scenario registers one
const document = {
  createElement: t => new El(t),
  querySelectorAll: sel => (sel.startsWith('[data-name=') && ROW) ? [ROW] : [],
  querySelector: sel => {
    // `[… i]` — the page looks the panel up case-insensitively, because Clarion names are
    // case-insensitive and the reply carries whatever spelling was asked for.
    const m = /^\.wdetail\[data-detail="(.*)"(\s+i)?\]$/.exec(sel);
    if (m && DETAIL && DETAIL.dataset.detail.toLowerCase() === m[1].toLowerCase()) return DETAIL;
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
// Clarion data names are case-insensitive; the page keys this cache through nameKey (see debugger.html).
const nameKey = n => (n == null ? '' : String(n)).toLowerCase();
const cssEsc = s => s.replace(/["\\]/g, '\\$&');
const beginEdit = () => {};
// dtApply is REAL, not a stub: it inserts its own .vas tag next to the same cell and runs AFTER wireEdit,
// so on a DATE/TIME/integer row it sits between the cell and the pencil. Stubbing it out is precisely how a
// position-based pencil lookup passed this test while leaving a live pencil on every numeric row.
const dtModes = {};

// clearEditMeta exists only in the FIXED page; running this against the pre-fix one is the before/after proof
// editThreadSuffix names the thread an edit will write when the panels are showing a non-stopped thread;
// this suite has no thread selection, so it returns '' and the pencil keeps its plain tooltip.
const NEEDED = ['dtParseInt','fieldPart','fmtClarionDate','fmtClarionTime','dtDefault','dtModeFor','dtApply','dtCycle',
                'clearEditMeta','clearDtMeta','clearValueMeta','setEditMeta','applyNote','viewingOtherThread','editThreadSuffix','wireEdit',
                'applyValue','showTipFor'];
const missing = [];
const src = NEEDED.map(n => {
  try { return extract(n); }
  catch (e) { missing.push(n); return 'function ' + n + '(){}'; }
}).join('\n');
if (missing.length) {
  // A stub answers every call with `undefined`, so the checks that exercise it stop testing the page and
  // start testing the stub — and still exit 0. Refuse to run rather than report a pass nobody can trust.
  const what = missing.length + ' of ' + NEEDED.length + ' page function(s) not found in ' +
               pad.resolvePage(pagePath) + ': ' + missing.join(', ');
  if (!ALLOW_MISSING) {
    console.log('  FAIL  ' + what);
    console.log('        Renamed or moved? Update NEEDED in this file. Testing a pre-fix page on purpose?');
    console.log('        Re-run with --allow-missing, which stubs them and says so.');
    process.exit(1);
  }
  console.log('   (note: --allow-missing — stubbed ' + what + ')');
}
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
  return { text: v.textContent, cls: v.classList.toString(), va: v.dataset.va, pencil: !!btn, title: v.title,
           // the DATE/TIME view-as family: the tag handle, and the cached raw the tag re-renders from
           vas: !!v._vas, raw: v.dataset.raw, dtname: v.dataset.dtname, dtmode: v.dataset.dtmode,
           vasTitle: v._vas ? v._vas.title : undefined };
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
  // A no-va reply still CARRIES A VALUE (found:true), so the view-as tag belongs on the row — what must
  // not survive is a raw from the PREVIOUS reply. dtApply re-derives it, so this asserts it is current,
  // not that it is absent.
  check('view-as tag kept on a valued reply, raw refreshed from it', s.vas && s.raw === String(resolved),
        'raw=' + s.raw);

  applyValue(name, false, null, null, false, { error: ERR });
  s = state(row);
  console.log('   after a failed read:    ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('edit pencil removed', !s.pencil, 'siblings=[' + siblings(row) + ']');
  check('engine reason in the tooltip', s.title === ERR, 'title=' + JSON.stringify(s.title));
  // 77f84ca5: the miss branch used to return before dtApply, leaving the tag and its cached raw behind.
  check('view-as tag gone — nothing left to click', !s.vas && siblings(row) === 'vval',
        'siblings=[' + siblings(row) + ']');
  check('cached raw/dtname/dtmode gone', s.raw === undefined && s.dtname === undefined && s.dtmode === undefined,
        'raw=' + s.raw + ' dtname=' + s.dtname + ' dtmode=' + s.dtmode);
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

// ---- 77f84ca5: every READER of the DATE/TIME view-as state, after a reply that resolved to nothing ----
// The cell keeps that state in two places — the .vas tag (a live element with a click handler) and
// dataset.raw/dtname/dtmode (what the handler re-renders from). Six things read it, and a row-shaped
// assertion only reaches some of them, so each one gets its own check here.
console.log('9) a failed read leaves the view-as state with no reader able to resurrect the old value');
{
  const name = 'TIT:PUBDATE';
  const OLD = '80000', OLD_TEXT = '2020-01-09';
  const row = makeRow(name);
  applyValue(name, true, OLD, 'ULONG', true, { va: '0x847B40', typeCode: '0x12', size: 4, places: 0 });
  let s = state(row);
  check('precondition: the row really is carrying view-as state', s.vas && s.raw === OLD && s.text === OLD_TEXT,
        JSON.stringify({ vas: s.vas, raw: s.raw, text: s.text }));
  const tagBefore = row.querySelector('.vas');

  applyValue(name, false, null, null, false, { error: 'THR$GetInstance returned no instance' });
  s = state(row);
  console.log('   ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');

  // reader 1 — the row's value cell, reached by CLICKING the tag (dtCycle). This is the reported symptom:
  // the click re-rendered the cell from the stale raw and put the previous stop's value back on a row the
  // engine had just said it could not read.
  check('no tag left in the row to click', !row.querySelector('.vas') && siblings(row) === 'vval',
        'siblings=[' + siblings(row) + ']');
  // and the handler is inert even if something still holds the old tag: dtCycle re-reads the cell, and the
  // cell no longer has a raw to render. Drives the REAL dtCycle, through the real tag's own onclick.
  tagBefore.onclick({ stopPropagation(){} });
  check('clicking a detached tag cannot resurrect the value',
        state(row).text === '(unavailable)', 'text=' + JSON.stringify(state(row).text));

  // reader 2 — the tag's own title, which quoted the old thread's raw number independently of the cell
  check('no tag title quoting the old raw', state(row).vasTitle === undefined);

  // reader 3 — the edit path. beginEdit pre-fills its editor from dataset.raw; it is fenced off by
  // dataset.va, which clearEditMeta drops, so this asserts BOTH the guard and the value behind it.
  check('edit metadata gone, so the editor is refused', state(row).va === undefined && !state(row).pencil);
  check('and the raw it would have pre-filled from is gone', state(row).raw === undefined, 'raw=' + state(row).raw);

  // reader 4 — the cell tooltip, which dtApply owns for an ordinary value
  check('tooltip is the engine reason, not a raw hint', state(row).title === 'THR$GetInstance returned no instance');

  // reader 5 — the `values` cache, read by the hover tip and by the tip's Copy Value action. It has NO
  // DOM row behind it on a source identifier, so no row-shaped assertion above can reach it.
  const token = new El('span'); token.dataset.name = name;   // a source identifier: no .vval child
  showTipFor(token);
  console.log('   source-identifier tip: ' + JSON.stringify($('dtVal').textContent));
  check('source tip (no row) quotes neither the raw nor the formatted old value',
        !$('dtVal').textContent.includes(OLD) && !$('dtVal').textContent.includes(OLD_TEXT),
        'tip=' + JSON.stringify($('dtVal').textContent));

  // reader 6 — an OPEN Watch detail panel, which keeps showing whatever it was last given
  DETAIL = new El('div'); DETAIL.classList.add('wdetail'); DETAIL.dataset.detail = name; DETAIL.style.display = '';
  row.classList.add('watchrow');
  applyValue(name, true, OLD, 'ULONG', true, { va: '0x847B40', typeCode: '0x12', size: 4, places: 0 });
  applyValue(name, false, null, null, false, { error: 'THR$GetInstance returned no instance' });
  console.log('   open detail: ' + JSON.stringify(DETAIL.textContent));
  check('open detail shows the unavailable state, not the old value', DETAIL.textContent === '(unavailable)',
        'detail=' + JSON.stringify(DETAIL.textContent));
  DETAIL = null;
}

// ---- 77f84ca5: one function owns clear-on-reuse, so the thread-switch path cannot drift from it ----
// The defect was two call sites clearing different SUBSETS of the same state. Pin the shared owner
// directly: whatever invalidateThreadScopedState and applyValue disagree about, they cannot disagree
// about this.
console.log('10) clearValueMeta clears BOTH families, so its two callers cannot diverge');
{
  const row = makeRow('JOB:JOBID');
  applyValue('JOB:JOBID', true, '4711', 'LONG', true, { va: '0x847B20', typeCode: '0x11', size: 4, places: 0 });
  const v = row.querySelector('.vval');
  check('precondition: both families present', !!v.dataset.va && !!v._vas && v.dataset.raw === '4711');
  clearValueMeta(v);
  check('edit family cleared', v.dataset.va === undefined && !v._vedit && !v.classList.contains('editable'));
  check('view-as family cleared', !v._vas && v.dataset.raw === undefined && v.dataset.dtname === undefined
        && v.dataset.dtmode === undefined);
  check('and the tag is out of the row, not just unhooked', siblings(row) === 'vval',
        'siblings=[' + siblings(row) + ']');
}

// ---- ec45805f item 1: the THIRD clear site, and why it is not just a clearValueMeta call ----
// dtApply's "this value is not a number after all" branch was clearing the view-as family INLINE - the
// same three deletes and the same tag removal clearValueMeta does. Three copies of one clear is how
// 77f84ca5 happened. It cannot simply call clearValueMeta, though: dtApply runs AFTER wireEdit, so that
// would strip the edit metadata this very reply just set and silently close the write path on a cell the
// engine said IS writable.
//
// Said plainly, because a test name is a claim: this case PASSES against the pre-fix page too. The
// inline copy had the same behaviour - duplication was the defect, not a wrong answer. What it pins is
// the constraint that shaped the fix, so the next person to "simplify" dtApply into a clearValueMeta
// call gets a failure instead of a silently unwritable cell. Section 12 is the one that discriminates.
console.log('11) dtApply clears the view-as half ONLY, leaving the pencil this reply just wired');
{
  const row = makeRow('CUS:BALANCE');
  applyValue('CUS:BALANCE', true, '4711', 'LONG', true, { va: '0x9012A0', typeCode: '0x11', size: 4, places: 0 });
  const v = row.querySelector('.vval');
  check('precondition: both families present', !!v.dataset.va && !!v._vas && v.dataset.raw === '4711',
        'va=' + v.dataset.va + ' raw=' + v.dataset.raw);

  // The next stop answers the same row with something that does not parse as a number.
  dtApply(v, 'CUS:BALANCE', '<unreadable>');

  check('view-as family cleared', !v._vas && v.dataset.raw === undefined
        && v.dataset.dtname === undefined && v.dataset.dtmode === undefined,
        'raw=' + v.dataset.raw + ' mode=' + v.dataset.dtmode);
  // The .vas tag goes; the pencil STAYS. Section 10's clearValueMeta case leaves 'vval' alone precisely
  // because it takes both halves - the difference between these two sibling lists IS the decomposition.
  check('the stale cycle tag is out of the row, so dtCycle cannot resurrect 4711',
        !siblings(row).split(',').includes('vas'), 'siblings=[' + siblings(row) + ']');
  check('...while the pencil stays in the row beside it',
        siblings(row).split(',').includes('vedit-btn'), 'siblings=[' + siblings(row) + ']');
  // THE POINT. clearValueMeta here would have wiped all four of these.
  check('edit family UNTOUCHED: the address survives', v.dataset.va === '0x9012A0', v.dataset.va);
  check('...and the type, size and places with it',
        String(v.dataset.tc) === '0x11' && String(v.dataset.sz) === '4' && String(v.dataset.pl) === '0',
        'tc=' + v.dataset.tc + ' sz=' + v.dataset.sz + ' pl=' + v.dataset.pl);
  check('...and the cell is still marked editable', v.classList.contains('editable'), v.className);
  check('...and the pencil is still on the cell', !!v._vedit);
}

// The three clears are ONE implementation each. A future inline copy is the defect returning, and it
// would not fail any behavioural case above - only this.
console.log('12) no site re-implements the view-as clear inline');
{
  const page = require('fs').readFileSync(require('./pad-dom').resolvePage(process.argv.slice(2).find(a => !a.startsWith('--'))), 'utf8');
  const inline = (page.match(/delete\s+\w+\.dataset\.dtmode/g) || []).length;
  check('dataset.dtmode is deleted in exactly one place (clearDtMeta)', inline === 1,
        inline + ' site(s)');
  const dt = require('./pad-dom').extract(page, 'dtApply');
  check('dtApply delegates its null branch', /clearDtMeta\(/.test(dt) && !/delete\s+cell\.dataset\.dtmode/.test(dt),
        dt.replace(/\s+/g, ' ').slice(0, 100));
  const cvm = require('./pad-dom').extract(page, 'clearValueMeta');
  check('clearValueMeta is composed of the two halves, not a third copy',
        /clearEditMeta\(/.test(cvm) && /clearDtMeta\(/.test(cvm) && !/delete\s+cell\.dataset/.test(cvm),
        cvm.replace(/\s+/g, ' '));
}

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

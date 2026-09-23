// Regression check: the Call Stack thread picker, and what a THREAD SWITCH has to invalidate.
//
// The engine stops the PROCESS, so every thread is frozen and any of them can be read. The pad therefore
// has a selected thread (`selTid`) that is not always the thread execution stopped on (`stopTid`), and the
// hazard this file exists for is showing one thread's values under the other thread's name:
//   - a reply for the PREVIOUS thread, still in flight when the switch happened, must never repaint;
//   - every reader of a resolved value must be invalidated, not just the cell you can see — the tooltip,
//     the edit metadata (a va is an address in the OLD thread's instance), the DATE/TIME tag's raw value,
//     the `values` cache behind the hover tip, and any open Watch detail panel;
//   - a row must never be left on "…" when no reply can come;
//   - stepping or continuing must visibly snap the view back to the stopped thread.
//
// Runs the REAL functions out of debugger.html against the shared mini-DOM (tools/pad-dom.js). Point it at
// a pre-fix copy of the page and every thread check fails — that is the before/after proof.
//
//   node tools/test-pad-threads.js [path/to/debugger.html] [--allow-missing]
// Exit code 0 = all checks passed.
// --allow-missing stubs page functions this suite cannot find instead of refusing to run; it is only for
// the deliberate pre-fix comparison above.
const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const ALLOW_MISSING = argv.includes('--allow-missing');
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const El = pad.El;

// ---- scope the page's functions run in -------------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);
const window = { innerWidth: 1200, innerHeight: 800 };
const tip = new El('div');            // the hover data-tip container showTipFor positions
let tipTarget = null, tipTimer = null;

const SENT = [];                       // every web message the page posted to the host
const wv = { postMessage: s => SENT.push(JSON.parse(s)) };
function sentActions() { return SENT.map(s => s.action); }
function clearSent() { SENT.length = 0; }

const TOASTS = [], LOGGED = [];
function toast(m) { TOASTS.push(m); }
function logLine(level, text) { LOGGED.push(level + ': ' + text); }

// page state the extracted functions close over
let isPaused = true;
const values = new Map();
const watched = new Map();             // the Watch panel's rows, keyed as the user spelled them
const nameKey = n => (n == null ? '' : String(n)).toLowerCase();
const cssEsc = s => s.replace(/["\\]/g, '\\$&');
const dtModes = {};
let allSyms = [], lastModule = '', lastFrames = null, stackQ = '';
let lastLibState = null, lastLibError = null;
let _flSeq = 0; const _flCbs = {};
let _expandSeq = 0; const _expandCbs = {};
const STAR = '*';
let activeEdit = null;                 // the page's in-place editor handle (real beginEdit is under test)
// The real page waits PENDING_SWEEP_MS before giving up on a row still showing "…". Shortened here so the
// test doesn't sleep for four seconds; the assertion below keeps the page's own constant honest.
const PENDING_SWEEP_MS = 30;
// Same for the hover settle (the page's is 300 ms; section H asserts it is still defined and sane).
const HOVER_SETTLE_MS = 20;

// ---- collaborators that are NOT under test ---------------------------------------------------------
const CALLS = [];
const spy = name => (...a) => { CALLS.push(name); return undefined; };
function buildLocals() { CALLS.push('buildLocals'); }
function buildModuleData() { CALLS.push('buildModuleData'); }
function buildRegs(r) { CALLS.push('buildRegs:' + (r ? 'regs' : 'null')); }
function renderLibState() { CALLS.push('renderLibState'); }
function refreshLibState() { CALLS.push('refreshLibState'); }
function onLibState() { CALLS.push('onLibState'); }
function memReread() { CALLS.push('memReread'); } function onMem() { CALLS.push('onMem'); }   // Memory panel: tools/test-pad-memory.js
function renderModuleData() { }
function applyStackFilter() { }
function sortVars(x) { return x; }
function renderVarRow() { }
function setAbout() { } function setTarget() { } function setRunState() { } function setPaused(p) { isPaused = p; }
function buildVarTree() { } function collectSyms() { return []; } function buildBps() { } function buildProcs() { }
function buildSource() { } function clearSrc() { } function onVarSet() { } function setLayoutDirty() { }
function refreshWatchClipping() { }
function renderWatchList() { }   // builds rows with innerHTML; not what these checks are about
function saveWatches() { }       // localStorage persistence; covered by test-pad-watch-persist.js

// ---- the page's own code ---------------------------------------------------------------------------
const FNS = ['esc', 'send', 'resetThreadState', 'setSrcLocation', 'clearSrc',
  'dtParseInt', 'fieldPart', 'fmtClarionDate', 'fmtClarionTime', 'dtDefault', 'dtModeFor', 'dtApply', 'dtCycle',
  'clearEditMeta', 'clearDtMeta', 'clearValueMeta', 'setEditMeta', 'applyNote', 'wireEdit', 'applyValue', 'showTipFor',
  'stripEditQuotes', 'beginEdit', 'cancelActiveEdit',
  'tidAccepted', 'threadRowFor', 'threadName', 'threadProc', 'threadPickerOpen', 'closeThreadPicker',
  'toggleThreadPicker', 'requestThreads', 'renderThreadPicker', 'renderThreadUi', 'selectThread',
  'onThreads', 'onThreadSelected', 'onEngineError', 'rearmCurrentThread', 'beginThreadSwitch', 'invalidateThreadScopedState',
  'viewingOtherThread', 'editThreadSuffix', 'watchedKey', 'addWatchSilent', 'addWatch', 'removeWatch', 'syncRowWatch',
  'cancelPendingCallbacks', 'armPendingSweep', 'requestFrameLocals', 'requestExpand',
  'buildStack', 'renderStack', 'onMessage',
  'setHoverMode', 'cancelHoverSelect', 'hoverOnRunState', 'onHover', 'hoverSettle', 'renderHoverUi'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { missing.push(n); return 'function ' + n + '(){}'; }
}).join('\n');
// A function this suite cannot find is a HARD FAILURE, not a stub: a stub returns undefined for every
// call, so the checks that drive it pass vacuously and the run still exits 0.
if (missing.length) {
  const what = missing.length + ' of ' + FNS.length + ' page function(s) not found in ' +
               pad.resolvePage(pagePath) + ': ' + missing.join(', ');
  if (!ALLOW_MISSING) {
    console.log('  FAIL  ' + what);
    console.log('        Renamed or moved? Update FNS in this file. Testing a pre-fix page on purpose?');
    console.log('        Re-run with --allow-missing, which stubs them and says so.');
    process.exit(1);
  }
  console.log('   (note: --allow-missing — stubbed ' + what + ')');
}
eval(src);

// ---- reaching into the page's in-place editor from a test ----
function activeEditCell() { return activeEdit ? activeEdit.cell : null; }
// Type into the open editor and press Enter, through the page's own keydown handler — the commit path a
// user actually takes, rather than calling an internal the page does not expose.
function commitActiveEdit(text) {
  const cell = activeEditCell(); if (!cell) return false;
  const inp = cell.children.find(c => c.classList.contains('vedit')); if (!inp) return false;
  inp.value = text;
  inp.onkeydown({ key: 'Enter', preventDefault() { } });
  return true;
}

// the page's own thread state (declared with `let` in the page, so the tests own the bindings here)
let threadRows = [], stopTid = null, selTid = null, threadSwitching = false, switchGen = 0, stackPendingTid = null;
let hoverOn = false, hoverTid = null, hoverPaused = false, hoverTimer = null, hoverRunState = 'idle', hoverBaseline = false;

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- fixtures --------------------------------------------------------------------------------------
// tid 4812 = the frame thread the engine stopped on; tid 5140 = the MDI browse's thread, which is the one
// holding the loaded PUB: record buffer the developer is actually looking at.
const STOP_TID = 4812, BROWSE_TID = 5140;
const THREADS_EVENT = {
  type: 'threads', stopped: STOP_TID, selected: STOP_TID,
  threads: [
    { tid: STOP_TID, clarionThread: 1, proc: 'MAIN', module: 'clbrws.clw', line: 84, state: 'syscall', clarionFrames: 6, stopped: true, selected: true },
    { tid: BROWSE_TID, clarionThread: 2, proc: 'BrowsePublishers', module: 'clbrws011.clw', line: 142, state: 'syscall', clarionFrames: 9, stopped: false, selected: false },
  ],
};
// `stopped` defaults to the frame thread, which is the case the Owner hit; pass it when the scenario
// stops somewhere else, so the inventory and the pause event agree the way a real engine's would.
function freshThreadsEvent(sel, stopped) {
  const e = JSON.parse(JSON.stringify(THREADS_EVENT));
  e.selected = sel; e.stopped = stopped || STOP_TID;
  e.threads.forEach(t => { t.selected = t.tid === sel; t.stopped = t.tid === e.stopped; });
  return e;
}
// a Watch/Variables row, in a container, attached to the document so querySelectorAll can find it
function makeRow(name, opts) {
  opts = opts || {};
  const tree = new El('div'); doc.body.appendChild(tree);
  const row = new El('div'); row.className = 'row' + (opts.watch ? ' watchrow' : ''); row.dataset.name = name;
  const v = new El('span'); v.classList.add('vval', 'pending'); v.textContent = '…';
  row.append(v); tree.append(row);
  return row;
}
function cell(row) { return row.querySelector('.vval'); }
function state(row) {
  const v = cell(row);
  return { text: v.textContent, cls: v.classList.toString(), va: v.dataset.va, title: v.title,
           pencil: !!row.querySelector('.vedit-btn'), vas: !!v._vas };
}
const A_INSTANCE = { va: '0x847A76', typeCode: '0x18', size: 41, places: 0 };

function resetAll() {
  doc.body.children.slice().forEach(c => c.remove());
  values.clear(); clearSent(); CALLS.length = 0; TOASTS.length = 0; LOGGED.length = 0;
  threadRows = []; stopTid = null; selTid = null; threadSwitching = false; stackPendingTid = null;
  lastFrames = null; isPaused = true;
  if (hoverTimer !== null) clearTimeout(hoverTimer);
  hoverOn = false; hoverTid = null; hoverPaused = false; hoverTimer = null; hoverRunState = 'idle'; hoverBaseline = false;
}

(async function run() {

console.log('0) the page still carries the pieces these checks stand on');
check('PENDING_SWEEP_MS is defined in the page', /const\s+PENDING_SWEEP_MS\s*=\s*\d+/.test(html));
check('both lazy loaders handle a cancelled (null) reply',
      (html.match(/items===null/g) || []).length >= 2,
      (html.match(/items===null/g) || []).length + ' site(s)');
check('no page function was missing', missing.length === 0, missing.join(',') || 'all present');
if (missing.length) {
  // Pointed at a page that predates part of this work: say so once instead of throwing halfway through a
  // scenario, which reads like a broken test rather than the before/after proof it is.
  console.log('\nThis page predates ' + missing.length + ' piece(s) these checks cover. ' + failures + ' FAILURE(S)');
  process.exit(1);
}

console.log('\n1) the thread list names each thread by its TOP CLARION PROCEDURE, not a bare tid');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const rows = $('thList').children;
  console.log('   ' + rows.map(r => r.children.map(c => c.textContent).join(' ')).join('  |  '));
  check('both threads listed', rows.length === 2);
  check('the frame thread is named by its procedure', rows[0].children.some(c => c.textContent === 'MAIN'));
  check('the browse thread is named by its procedure', rows[1].children.some(c => c.textContent === 'BrowsePublishers'));
  check('module:line shown', rows[1].children.some(c => c.textContent === 'clbrws011.clw:142'));
  check('the Clarion thread number is used when the engine gives one',
        rows[1].children.some(c => c.textContent === 'Thread 2'));
  check('the stopped thread is marked', rows[0].classList.contains('stopped')
        && rows[0].children.some(c => c.textContent === 'STOPPED HERE'));
  check('the selected thread is marked', rows[0].classList.contains('sel') && !rows[1].classList.contains('sel'));
  check('no "viewing another thread" state while they are the same', !doc.body.classList.contains('viewing-other'));
}

console.log('\n2) a null Clarion thread number is never invented');
{
  resetAll();
  const e = freshThreadsEvent(STOP_TID);
  e.threads[1].clarionThread = null; e.threads[1].proc = null; e.threads[1].module = null; e.threads[1].clarionFrames = 0;
  onThreads(e);
  const r = $('thList').children[1];
  const txt = r.children.map(c => c.textContent).join(' ');
  console.log('   ' + txt);
  check('falls back to the raw tid', txt.includes('tid ' + BROWSE_TID) && !/Thread \d/.test(txt));
  check('says it has no Clarion frames rather than inventing a name', txt.includes('(no Clarion frames)'));
}

console.log('\n3) selecting a thread asks the engine, then re-reads everything for it');
{
  resetAll();
  onThreads(THREADS_EVENT);
  clearSent();
  selectThread(BROWSE_TID);
  check('sends `thread <tid>` and nothing else yet', sentActions().join(',') === 'selectthread'
        && SENT[0].data === String(BROWSE_TID), sentActions().join(','));
  check('the picker closes on choosing', !threadPickerOpen());

  clearSent(); CALLS.length = 0;
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  const acts = sentActions();
  console.log('   re-read: ' + acts.join(', '));
  check('stack re-read', acts.includes('stack'));
  check('module data re-read', acts.includes('moduledata'));
  check('watches re-resolved', acts.includes('rewatch'));
  check('registers re-read', acts.includes('regs'));
  check('the thread list is refreshed so its marks follow', acts.includes('threads'));
  check('frame-0 locals follow the new stack', CALLS.includes('buildLocals'));
  check('library state offered a refresh', CALLS.includes('refreshLibState'));
  check('the registers pane is cleared while the re-read is in flight', CALLS.includes('buildRegs:null'));

  check('selTid now names the browse thread', selTid === BROWSE_TID);
  check('the header chip names the thread AND its procedure',
        $('thSelText').textContent === 'Thread 2 · BrowsePublishers', $('thSelText').textContent);
  check('the chip flags that this is not the stopped thread', $('thSel').classList.contains('other'));
  check('the panel banner says so in words',
        $('thWarn').classList.contains('show') && $('thWarnText').textContent === 'viewing Thread 2 — not the stopped thread',
        $('thWarnText').textContent);
  check('the toolbar badge says so too (the Call Stack panel can be hidden)',
        doc.body.classList.contains('viewing-other') && $('thBadgeTop').textContent.includes('not the stopped thread'));
  check('the emptied stack says which thread it is waiting for',
        $('stackList').innerHTML.includes('Reading Thread 2'), $('stackList').innerHTML);
}

// "EVERY reader" is not something a test can prove — an unknown seventh reader would pass it silently.
// Six is a number the next person can check against the enumeration in invalidateThreadScopedState.
console.log('\n4) the switch invalidates all six readers of the old thread\'s value');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const name = 'PUB:PUB_NAME';
  const row = makeRow(name, { watch: true });
  const detail = new El('div'); detail.classList.add('wdetail'); detail.dataset.detail = name;
  detail.style.display = ''; row.parentElement.append(detail);
  const numRow = makeRow('PUB:PUBDATE');             // a DATE row, which also carries dtApply's .vas tag
  const untouched = makeRow('PUB:CITY');             // never answered: still "…" (a collapsed tree row)

  applyValue(name, true, "'Algodata Infosystems'", 'STRING(41)', true, A_INSTANCE);
  applyValue('PUB:PUBDATE', true, '80000', 'ULONG', true, { va: '0x847B40', typeCode: '0x12', size: 4, places: 0 });
  showTipFor(row);
  check('(setup) the row resolved, is editable, and the tip quotes it',
        state(row).va === A_INSTANCE.va && state(row).pencil && $('dtVal').textContent.includes('Algodata'));
  check('(setup) the DATE row carries its view-as tag', state(numRow).vas);
  check('(setup) the open Watch detail shows the value', detail.textContent.includes('Algodata'));

  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  const s = state(row), n = state(numRow), u = state(untouched);
  console.log('   row after the switch: ' + JSON.stringify(s));
  check('1. the value cell no longer shows the other thread\'s value', s.text === '…' && s.cls.includes('pending'));
  check('2. the tooltip is gone', s.title === undefined, 'title=' + JSON.stringify(s.title));
  check('3. the instance address and its pencil are gone', s.va === undefined && !s.pencil);
  check('4. the DATE/TIME tag (which carries the old raw value) is gone', !n.vas && n.text === '…');
  check('5. the values cache is emptied', values.size === 0, 'size=' + values.size);
  check('   …so the hover tip cannot quote the old thread either',
        (showTipFor(row), !$('dtVal').textContent.includes('Algodata')), $('dtVal').textContent);
  check('6. the open Watch detail panel follows', detail.textContent === '…', JSON.stringify(detail.textContent));
  check('a row that was never answered is left alone', u.text === '…');
}

console.log('\n5) a reply for the thread we are no longer showing is dropped');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const name = 'PUB:PUB_NAME';
  const row = makeRow(name, { watch: true });
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });

  // late reply from the FRAME thread, still in flight when the switch happened
  onMessage(JSON.stringify({ type: 'watch', name: name, found: true, value: "''", typeName: 'STRING(41)',
                             threaded: true, note: 'no thread instance — shared template value', tid: STOP_TID }));
  check('a late value for the old thread never lands', state(row).text === '…', state(row).text);

  // late stack for the old thread
  lastFrames = null;
  onMessage(JSON.stringify({ type: 'stack', frames: [{ frame: 0, proc: 'MAIN', module: 'clbrws.clw', line: 84, va: '0x1', ebp: '0x2' }], tid: STOP_TID }));
  check('a late stack for the old thread never lands', lastFrames === null || !lastFrames.length);

  // the reply that IS for the selected thread
  onMessage(JSON.stringify({ type: 'watch', name: name, found: true, value: "'Algodata Infosystems'",
                             typeName: 'STRING(41)', threaded: true, va: '0x9A1000', typeCode: '0x18', size: 41, tid: BROWSE_TID }));
  check('the selected thread\'s value lands', state(row).text === "'Algodata Infosystems'", state(row).text);
  check('…and re-arms editing against THIS thread\'s instance', state(row).va === '0x9A1000' && state(row).pencil);

  // an engine that does not stamp its replies at all must still work
  onMessage(JSON.stringify({ type: 'watch', name: name, found: true, value: "'New Moon Books'", typeName: 'STRING(41)', threaded: true }));
  check('an UNSTAMPED reply is treated as unscoped and accepted', state(row).text === "'New Moon Books'", state(row).text);
}

// The "not a second vocabulary" half of this claim is proved structurally in 9c (one function, both
// panels); this body only shows the states arrive and are rendered, so that is all the name says.
console.log('\n6) a watch row re-resolves into 50414e39\'s per-thread states');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const name = 'PUB:PUB_NAME';
  const row = makeRow(name, { watch: true });
  applyValue(name, true, "'Algodata Infosystems'", 'STRING(41)', true, Object.assign({ tid: BROWSE_TID }, A_INSTANCE));
  onThreadSelected({ type: 'threadselected', tid: STOP_TID, ok: true });

  onMessage(JSON.stringify({ type: 'watch', name: name, found: true, value: "''", typeName: 'STRING(41)',
                             threaded: true, note: 'no thread instance — shared template value', tid: STOP_TID }));
  let s = state(row);
  console.log('   ' + JSON.stringify(s));
  check('the qualified value resolves the row', s.text === "''" && !s.cls.includes('pending'));
  check('the caveat is shown and explained', s.cls.includes('noted') && s.title === 'no thread instance — shared template value');
  check('a shared template value is NOT editable', s.va === undefined && !s.pencil);

  onMessage(JSON.stringify({ type: 'watch', name: name, found: true, value: "''", typeName: 'STRING(41)',
                             threaded: true, note: 'not yet used on this thread — initial value', tid: STOP_TID }));
  s = state(row);
  check('the other 50414e39 state reads the same way', s.cls.includes('noted')
        && s.title === 'not yet used on this thread — initial value' && !s.pencil);
}

console.log('\n7) stepping snaps the view back — on the engine\'s REPLY, never on the command being sent');
{
  resetAll();
  onThreads(THREADS_EVENT);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  const row = makeRow('PUB:PUB_NAME');
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'Algodata'",
                             typeName: 'STRING(41)', threaded: true, tid: BROWSE_TID }));
  toggleThreadPicker();
  check('(setup) viewing the browse thread, showing its value', selTid === BROWSE_TID
        && doc.body.classList.contains('viewing-other') && state(row).text === "'Algodata'");

  clearSent();
  send('stepover');
  check('the step goes out', sentActions().includes('stepover'));
  // The host's Cmd* handlers are self-guarding: Run to Cursor returns without resuming when the editor's
  // cursor cannot be resolved, Pause/Start no-op in the wrong state. Relabelling here would put the
  // BROWSE thread's values on screen under the STOPPED thread's name for a command that never ran.
  check('the labelling does NOT move on dispatch', selTid === BROWSE_TID);
  check('…so the panels and their banner still agree with the values on screen',
        doc.body.classList.contains('viewing-other') && state(row).text === "'Algodata'");

  // a command the host dropped: no reply ever comes, and the pad must be exactly as it was
  clearSent();
  send('runtocursor');
  check('a dropped command leaves the view untouched', selTid === BROWSE_TID
        && doc.body.classList.contains('viewing-other') && state(row).text === "'Algodata'");
  check('and leaves no row stranded on "…"', state(row).text !== '…');

  // the engine's own resume echo is what actually snaps it back
  onMessage(JSON.stringify({ type: 'resumed', mode: 'stepover' }));
  check('the resume reply snaps the view back', selTid === null && stopTid === null && !threadRows.length);
  check('the banner is gone', !$('thWarn').classList.contains('show') && !doc.body.classList.contains('viewing-other'));
  check('the picker is closed', !threadPickerOpen());
  check('…and the next stop\'s replies are not gated by a stale selection', tidAccepted({ tid: 99999 }) === true);
}

console.log('\n7b) an edit committed during a switch never writes the old thread\'s address');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('PUB:PUB_NAME', { watch: true });
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  check('(setup) the row is editable, bound to the stopped thread\'s instance', state(row).va === A_INSTANCE.va);

  // the user opens the editor, then picks another thread before committing
  beginEdit(cell(row));
  check('(setup) an editor is open', !!activeEditCell());
  clearSent();
  selectThread(BROWSE_TID);
  check('the open editor is cancelled by the request itself', !activeEditCell());
  check('the stale instance address is dropped BEFORE the request goes out',
        state(row).va === undefined && !state(row).pencil);
  check('only the selection request was sent', sentActions().join(',') === 'selectthread', sentActions().join(','));

  // and a fresh edit attempt in the gap cannot start one either
  beginEdit(cell(row));
  check('a new edit cannot be started against the old address', !activeEditCell());
  check('no write was sent in the gap', !sentActions().includes('editvar'), sentActions().join(','));
}

console.log('\n7c) a write names the thread its address was read on');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('PUB:PUB_NAME', { watch: true });
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  clearSent();
  beginEdit(cell(row));
  commitActiveEdit('New Moon Books');
  const wrote = SENT.find(s => s.action === 'editvar');
  console.log('   ' + (wrote ? wrote.data : '(nothing sent)'));
  check('the write carries the selected thread', !!wrote && JSON.parse(wrote.data).tid === STOP_TID);
  // the host reads the FIRST "key": it finds anywhere in the text, and `value` is the one field the user
  // typed — a value containing its own "tid" must not be the one that gets read
  check('tid appears before the user-typed value', !!wrote && wrote.data.indexOf('"tid"') < wrote.data.indexOf('"value"'));
}

console.log('\n7e) an edit on another thread is allowed, and says whose copy it writes');
{
  // The Owner's ruling: allow it — it is real data for that thread, and refusing would remove a
  // legitimate capability — but nothing on screen said WHICH thread's copy a commit would write. No
  // prompt: the naming has to be in the affordance and in the confirmation, not in a dialog.
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('PUB:PUB_NAME', { watch: true });

  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  const plainTitle = row.querySelector('.vedit-btn').title;
  console.log('   on the stopped thread: ' + JSON.stringify(plainTitle));
  check('no thread noise in the ordinary case', plainTitle === 'Edit value', plainTitle);
  clearSent(); TOASTS.length = 0;
  beginEdit(cell(row)); commitActiveEdit('New Moon Books');
  check('…and no thread named on the commit either', !TOASTS.some(t => /Thread|tid/.test(t)),
        TOASTS.join('|') || '(silent)');
  check('the write still goes out', sentActions().includes('editvar'));

  // now switch to the browse thread and let its own value arrive
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'New Moon Books'",
                             typeName: 'STRING(41)', threaded: true, va: '0x9A1000', typeCode: '0x18',
                             size: 41, tid: BROWSE_TID }));
  const otherTitle = row.querySelector('.vedit-btn').title;
  console.log('   viewing another thread: ' + JSON.stringify(otherTitle));
  check('editing is still OFFERED on a non-stopped thread', !!row.querySelector('.vedit-btn')
        && state(row).va === '0x9A1000');
  check('the pencil names whose copy it writes', otherTitle === "Edit value — writes Thread 2's copy", otherTitle);

  clearSent(); TOASTS.length = 0;
  beginEdit(cell(row));
  check('the open editor names it too', (cell(row).children.find(c => c.classList.contains('vedit')) || {}).title
        === "Editing — writes Thread 2's copy");
  commitActiveEdit('Binnet & Hardley');
  console.log('   on commit: ' + JSON.stringify(TOASTS));
  check('the commit says whose copy was written', TOASTS.some(t => t.includes("Thread 2's copy")), TOASTS.join('|'));
  check('…and names the field, so it is checkable', TOASTS.some(t => t.includes('PUB:PUB_NAME')), TOASTS.join('|'));
  const wrote = SENT.find(s => s.action === 'editvar');
  check('the write carries that thread', !!wrote && JSON.parse(wrote.data).tid === BROWSE_TID);
  check('no confirmation was asked for', sentActions().filter(a => a === 'editvar').length === 1);
}

console.log('\n7d) an engine error answers a switch that is in flight');
{
  resetAll();
  onThreads(THREADS_EVENT);
  selectThread(BROWSE_TID);
  check('(setup) the chip says a switch is in flight', $('thSelText').textContent === 'switching…');
  clearSent();
  onMessage(JSON.stringify({ type: 'engineerror', message: 'thread 5140 is not readable' }));
  check('the chip stops claiming a request is in flight', $('thSelText').textContent !== 'switching…',
        $('thSelText').textContent);
  check('the selection stays where the engine has it', selTid === STOP_TID);
  check('the pad resyncs from the engine', sentActions().includes('threads'));
}

console.log('\n8) a new stop starts from the stopped thread, whatever was selected before');
{
  resetAll();
  onThreads(THREADS_EVENT);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  onMessage(JSON.stringify({ type: 'paused', proc: 'MAIN', module: 'clbrws.clw', line: 84, regs: null }));
  check('the previous stop\'s selection is dropped', selTid === null && stopTid === null);
  check('the "not the stopped thread" state is cleared', !doc.body.classList.contains('viewing-other'));
  check('every reply for the new stop is accepted until the list arrives', tidAccepted({ tid: STOP_TID }));
  onThreads(freshThreadsEvent(STOP_TID));
  check('the inventory re-points the pad at the stopped thread', selTid === STOP_TID && stopTid === STOP_TID);
  check('and the chip names it again', $('thSelText').textContent === 'Thread 1 · MAIN', $('thSelText').textContent);
}

console.log('\n8b) the pause event may name its own thread (additive) — the marker is right before the list arrives');
{
  resetAll();
  onThreads(THREADS_EVENT);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  // new stop, and this time the engine names the thread it stopped on
  onMessage(JSON.stringify({ type: 'paused', proc: 'BROWSEPUBLISHERS', module: 'clbrws011.clw', line: 142,
                             regs: null, tid: BROWSE_TID }));
  check('the stopped thread is known from the stop itself', stopTid === BROWSE_TID && selTid === BROWSE_TID);
  check('so nothing claims we are off the stopped thread', !doc.body.classList.contains('viewing-other'));
  check('a reply for the stopped thread lands', tidAccepted({ tid: BROWSE_TID }));
  check('a reply for any OTHER thread is already gated', !tidAccepted({ tid: STOP_TID }));
  check('the chip names it even with no inventory yet',
        $('thSelText').textContent === 'tid ' + BROWSE_TID, $('thSelText').textContent);
  // the inventory refines the label; it agrees with the stop about which thread that was
  onThreads(freshThreadsEvent(BROWSE_TID, BROWSE_TID));
  check('the inventory adds the readable name', $('thSelText').textContent === 'Thread 2 · BrowsePublishers',
        $('thSelText').textContent);
  check('and agrees about the stopped thread', stopTid === BROWSE_TID && !doc.body.classList.contains('viewing-other'));

  // an engine that does NOT name it behaves exactly as before
  onMessage(JSON.stringify({ type: 'paused', proc: 'MAIN', module: 'clbrws.clw', line: 84, regs: null }));
  check('an unstamped pause leaves the pad unscoped, as before', stopTid === null && selTid === null);
  check('…so it accepts whatever the stop pushes', tidAccepted({ tid: STOP_TID }) && tidAccepted({ tid: BROWSE_TID }));
}

console.log('\n9) a refused selection leaves the pad on the thread it actually has');
{
  resetAll();
  onThreads(THREADS_EVENT);
  clearSent();
  selectThread(BROWSE_TID);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: false, error: 'thread 5140 has exited' });
  check('the selection does not move', selTid === STOP_TID, 'selTid=' + selTid);
  check('the reason is surfaced', TOASTS.some(t => t.includes('has exited')), TOASTS.join('|'));
  // The panels ARE re-read (9d: the refusal has to give the rows their editing back) — what matters is
  // that the re-read is for the thread we still have, and that nothing from the thread we did not get can
  // paint. A "no re-read at all" check used to stand here; it was guarding the second half by accident.
  check('the re-read is for the thread we still have', selTid === STOP_TID && tidAccepted({ tid: STOP_TID }));
  check('and a reply from the thread we did not get still cannot land', !tidAccepted({ tid: BROWSE_TID }));
  check('the pad resyncs from the engine', sentActions().includes('threads'));
  check('the chip is not left saying "switching…"', $('thSelText').textContent !== 'switching…', $('thSelText').textContent);
}

console.log('\n9b) a refusal names the thread that was ASKED FOR — it is never read as a selection');
{
  // Protocol amendment 3: on ok:false the tid is the REQUESTED thread and the engine's selection is
  // unchanged. Nothing in the reply may move the pad's own selection; the authoritative one comes from
  // the `threads` resync. A malformed request carries NO tid at all — absent, never 0.
  resetAll();
  onThreads(THREADS_EVENT);
  selectThread(BROWSE_TID);
  onMessage(JSON.stringify({ type: 'threadselected', tid: BROWSE_TID, ok: false, error: 'unknown or exited thread ' + BROWSE_TID }));
  check('the REQUESTED thread is what the message names', TOASTS.some(t => t.startsWith('Thread ' + BROWSE_TID + ':')),
        TOASTS.join('|'));
  check('the pad keeps the selection it already had', selTid === STOP_TID, 'selTid=' + selTid);

  // a malformed request: no tid member at all
  resetAll();
  onThreads(THREADS_EVENT);
  selectThread(BROWSE_TID);
  onMessage(JSON.stringify({ type: 'threadselected', ok: false, error: "thread expects: thread <tid>" }));
  check('no tid is invented in the message', TOASTS.some(t => t === 'thread expects: thread <tid>'), TOASTS.join('|'));
  check('the selection still does not move', selTid === STOP_TID, 'selTid=' + selTid);
  check('the chip is not left saying "switching…"', $('thSelText').textContent !== 'switching…');
  check('and it never reads an absent tid as thread 0', !TOASTS.some(t => t.indexOf('Thread 0') >= 0), TOASTS.join('|'));

  // ok with no tid tells us nothing about what we are looking at: ask, do not assume
  resetAll();
  onThreads(THREADS_EVENT);
  selectThread(BROWSE_TID);
  clearSent();
  onMessage(JSON.stringify({ type: 'threadselected', ok: true }));
  check('an ok with no tid is not taken as a selection', selTid === STOP_TID, 'selTid=' + selTid);
  check('…it asks the engine what is actually selected', sentActions().includes('threads'), sentActions().join(','));
}

// Not only a refusal: one of the three cases is an ok that names no thread, which is not one.
console.log('\n9d) a switch that did NOT happen gives the rows their editing back');
{
  // The TOCTOU guard strips every editable row at REQUEST time, before anyone knows the answer. When the
  // answer is "no", the selection never moved and the values on screen are still right — but nothing has
  // re-armed them, so editing would stay dead for the rest of the stop. The user asked to look elsewhere,
  // was told no, and quietly lost the ability to edit the thread they are still on.
  const REPLY = { type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'Algodata'", typeName: 'STRING(41)',
                  threaded: true, va: A_INSTANCE.va, typeCode: '0x18', size: 41, tid: STOP_TID };
  function refusalScenario(label, deliverRefusal) {
    console.log('   ' + label);
    resetAll();
    onThreads(THREADS_EVENT);
    const row = makeRow('PUB:PUB_NAME', { watch: true });
    applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
    selectThread(BROWSE_TID);
    check('   (setup) the request stripped the row, as the TOCTOU fix requires',
          state(row).va === undefined && !state(row).pencil);
    clearSent();
    deliverRefusal();
    const acts = sentActions();
    check('   the still-current thread is re-read', acts.includes('rewatch') && acts.includes('moduledata')
          && acts.includes('stack'), acts.join(','));
    check('   the values on screen were NOT blanked to "…" to do it', state(row).text === "'Algodata'",
          state(row).text);
    // and the reply that re-read produces puts the editing back
    onMessage(JSON.stringify(REPLY));
    check('   editing is alive again on the thread we never left',
          state(row).va === A_INSTANCE.va && state(row).pencil);
    check('   the selection still never moved', selTid === STOP_TID);
  }
  refusalScenario('the engine refuses the switch:', () =>
    onMessage(JSON.stringify({ type: 'threadselected', tid: BROWSE_TID, ok: false, error: 'unknown or exited thread' })));
  refusalScenario('an engine error answers it instead:', () =>
    onMessage(JSON.stringify({ type: 'engineerror', message: 'thread is not readable' })));
  refusalScenario('an ok that names no thread:', () =>
    onMessage(JSON.stringify({ type: 'threadselected', ok: true })));
}

console.log('\n9c) a module-data row says the same thing about a thread as a Watch row does');
{
  // The engine can now qualify a moduledata row the way it qualifies a watch reply. Dropping the note in
  // the Variables tree would show a ,THREAD module symbol's shared template value as though it were this
  // thread's own — while a Watch row for the SAME name at the SAME stop says otherwise. One function now
  // does the marking for both panels, so they cannot drift into two vocabularies for one fact.
  const NOTE = 'no thread instance — shared template value';
  const c = new El('span'); c.classList.add('vval'); c.textContent = '0';
  check('the caveat is marked and explained, not just underlined',
        applyNote(c, NOTE) && c.classList.contains('noted') && c.title === NOTE,
        JSON.stringify({ cls: c.classList.toString(), title: c.title }));

  const plain = new El('span'); plain.classList.add('vval'); plain.textContent = '1';
  applyNote(plain, undefined);
  check('a row with no caveat is left alone', !plain.classList.contains('noted') && plain.title === undefined);

  // dtApply owns the title on a numeric row, so the caveat has to be applied AFTER it or the explanation
  // is overwritten by 'raw: N' and the dotted underline is left with nothing behind it. The Watch panel's
  // ordering is proved end to end by tools/test-pad-editmeta.js; this keeps the tree's the same way round.
  const tree = pad.extract(html, 'renderVarRow');
  check('the Variables tree applies it AFTER dtApply', tree.indexOf('dtApply(') < tree.indexOf('applyNote('),
        'dtApply@' + tree.indexOf('dtApply(') + ' applyNote@' + tree.indexOf('applyNote('));
  check('and the Watch panel uses the same function',
        pad.extract(html, 'applyValue').indexOf('applyNote(') > 0);
}

console.log('\n9e) one Clarion name, however it is spelled, is one variable');
{
  // The Owner's screenshot: after a switch the WATCH row for a field sat on "…" while the VARIABLES tree
  // row for the SAME field showed its value. Clarion names are case-insensitive and the engine echoes the
  // spelling it was ASKED for, so the two rows were two spellings of one name — and the host's watch set
  // collapses them, so only one was ever re-requested. Every name comparison in the page now goes through
  // nameKey(); these are the four places that compared with === .
  const TREE = 'PUB:PUB_NAME', TYPED = 'Pub:Pub_Name';
  resetAll();
  onThreads(THREADS_EVENT);
  const treeRow = makeRow(TREE);                       // keyed from the engine's symbol table
  const watchRow = makeRow(TYPED, { watch: true });    // keyed from what the developer typed into the box

  // 1. a reply for one spelling resolves the rows keyed in the other
  onMessage(JSON.stringify({ type: 'watch', name: TREE, found: true, value: "'GA'", typeName: 'STRING(41)',
                             threaded: true, va: A_INSTANCE.va, typeCode: '0x18', size: 41, tid: STOP_TID }));
  console.log('   reply for ' + TREE + ' -> tree ' + JSON.stringify(state(treeRow).text)
              + ', watch ' + JSON.stringify(state(watchRow).text));
  check('the tree row resolves', state(treeRow).text === "'GA'");
  check('and so does the Watch row keyed in another case', state(watchRow).text === "'GA'",
        state(watchRow).text);
  check('both get the edit metadata, not just the one that matched', state(watchRow).va === A_INSTANCE.va);

  // 2. the values cache, read by the hover tip under the spelling of whatever is hovered. A tip over a ROW
  //    would fall back to the cell's own text and pass whatever the cache did, so this hovers a SOURCE
  //    IDENTIFIER — no row, no cell, nothing but the cache — which is the reader that actually depends on it.
  const token = new El('span'); token.dataset.name = TYPED;   // the source spells it as the developer wrote it
  doc.body.appendChild(token);
  showTipFor(token);
  check('the hover tip over a source identifier in another case finds the value',
        $('dtVal').textContent.includes('GA'), $('dtVal').textContent);

  // 3. the Watch panel cannot hold one variable twice
  watched.clear(); TOASTS.length = 0;
  addWatch(TYPED);                       // the developer types it into the box
  addWatch(TREE);                        // …then pins the same field from the tree, in its spelling
  console.log('   watch panel holds: ' + JSON.stringify([...watched.keys()]));
  check('a second spelling is not a second row', watched.size === 1, JSON.stringify([...watched.keys()]));
  check('…and the user is told it is already there', TOASTS.some(t => t.includes('already watched')),
        TOASTS.join('|'));

  // 4. a tree row scrolling out of view must not unwatch what the Watch panel is holding. This is the path
  //    that makes the bug reachable with NO thread switch at all, so it is driven, not inferred: the
  //    decision renderSymRow's setVisible makes is syncRowWatch, called here with the tree's spelling
  //    while the Watch panel holds the typed one. (The closure itself cannot be driven — renderSymRow
  //    builds its rows with innerHTML, which the mini-DOM does not parse.)
  check('the tree spelling resolves to the row the panel holds', watchedKey(TREE) === TYPED,
        String(watchedKey(TREE)));
  clearSent();
  const sentOnHide = syncRowWatch(TREE, false);
  check('a tree row scrolling out of view sends NO unwatch for a name the panel holds',
        sentOnHide === false && !sentActions().includes('unwatch'), sentActions().join(',') || '(nothing sent)');
  clearSent();
  syncRowWatch(TREE, true);
  check('…and no redundant watch when it scrolls back in', !sentActions().includes('watch'),
        sentActions().join(',') || '(nothing sent)');

  // a name the Watch panel does NOT hold still follows visibility, or tree rows would never resolve at all
  clearSent();
  const sentForUnheld = syncRowWatch('PUB:CITY', true);
  check('an unheld name is still watched on becoming visible',
        sentForUnheld === true && SENT[0] && SENT[0].action === 'watch' && SENT[0].data === 'PUB:CITY');
  clearSent();
  syncRowWatch('PUB:CITY', false);
  check('…and unwatched on leaving view', SENT[0] && SENT[0].action === 'unwatch');
}

console.log('\n9f) a watch the engine will never answer is answered here');
{
  // Host-side (ClarionDebuggerWebView.WatchOrExplain): the service refuses a name it cannot put on the
  // line/space-split wire and sends NOTHING, so no reply can ever come. The page must still see a miss.
  // This checks the page half — that such a reply resolves the row and explains itself.
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('BAD NAME', { watch: true });
  onMessage(JSON.stringify({ type: 'watch', name: 'BAD NAME', found: false, outOfScope: false,
                             error: 'not a data name the debugger can read — letters, digits and _ : $ . only, up to 128 characters' }));
  const s = state(row);
  console.log('   ' + JSON.stringify(s));
  check('the row resolves instead of waiting forever', s.text === '(unavailable)' && !s.cls.includes('pending'));
  check('and says why, where the user will look', (s.title || '').includes('letters, digits'), s.title);
}

console.log('\n10) a row is never left on "…" when no reply can come');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const answered = makeRow('PUB:PUB_NAME', { watch: true });
  const never = makeRow('PUB:CITY');                       // collapsed tree row: nobody is watching it
  // An EXPANDED Watch panel is a second face of the same row, and only a REPLY ever refills it — so it is
  // the half the sweep used to leave behind. A CLOSED one next to it proves the sweep respects the same
  // open-check applyValue does, rather than writing into hidden panels.
  const openDet = new El('div'); openDet.classList.add('wdetail');
  openDet.dataset.detail = 'PUB:PUB_NAME'; openDet.style.display = '';
  answered.parentElement.append(openDet);
  const shutDet = new El('div'); shutDet.classList.add('wdetail');
  shutDet.dataset.detail = 'PUB:CITY'; shutDet.style.display = 'none'; shutDet.textContent = 'stale';
  never.parentElement.append(shutDet);

  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  check('(setup) the open detail shows the value', openDet.textContent === "'Algodata'", openDet.textContent);

  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  check('(setup) both rows read "…" right after the switch',
        state(answered).text === '…' && state(never).text === '…');
  check('(setup) and the open detail was blanked to "…" too', openDet.textContent === '…', openDet.textContent);

  await sleep(PENDING_SWEEP_MS + 40);
  const a = state(answered), n = state(never);
  console.log('   answered-before: ' + JSON.stringify(a) + '\n   never-answered:  ' + JSON.stringify(n));
  console.log('   open detail: ' + JSON.stringify(openDet.textContent) +
              '   closed detail: ' + JSON.stringify(shutDet.textContent));
  check('a row that had a value and got no reply stops pretending to load',
        a.text === '(no reply)' && a.cls.includes('unavail') && !a.cls.includes('pending'));
  check('…and says which thread did not answer', (a.title || '').includes(String(BROWSE_TID)), a.title);
  check('a row nobody asked about is left alone', n.text === '…' && n.cls.includes('pending'));
  check('the console records it', LOGGED.some(l => l.includes('got no reply')), LOGGED.join('|'));
  // ab4b3fcf item 11: the panel used to sit on "…" for the rest of the session while its own row said
  // "(no reply)" — the two halves of one watch disagreeing.
  check('the OPEN detail stops pretending to load, with the row', openDet.textContent === '(no reply)',
        'detail=' + JSON.stringify(openDet.textContent));
  check('a CLOSED detail is not written into', shutDet.textContent === 'stale',
        'detail=' + JSON.stringify(shutDet.textContent));
}

console.log('\n11) the sweep never fires over a newer switch, nor once the target has resumed');
{
  // armPendingSweep gives up on a row still showing "…" — but only for the switch that armed it, and only
  // while the target is still stopped. Both halves are guarantees this name claims, so both are exercised:
  // the name used to promise the resume half while nothing in the body resumed anything.
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('PUB:PUB_NAME');
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  onThreads(freshThreadsEvent(BROWSE_TID, BROWSE_TID));
  onThreadSelected({ type: 'threadselected', tid: STOP_TID, ok: true });   // switched again straight away
  // the reply for the SECOND switch arrives
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'Algodata'",
                             typeName: 'STRING(41)', threaded: true, tid: STOP_TID }));
  await sleep(PENDING_SWEEP_MS + 40);
  check('the first switch\'s sweep does not overwrite the second switch\'s value',
        state(row).text === "'Algodata'", state(row).text);

  // the target resumes before the sweep is due: the row is mid-switch and still on "…", and marking it
  // "(no reply)" would blame a thread for not answering a question nobody can answer while it runs
  resetAll();
  onThreads(THREADS_EVENT);
  const row2 = makeRow('PUB:PUB_NAME');
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  check('(setup) the row is mid-switch, waiting on a reply', state(row2).text === '…');
  onMessage(JSON.stringify({ type: 'resumed', mode: 'continue' }));
  await sleep(PENDING_SWEEP_MS + 40);
  check('a resumed target is never told a thread failed to answer',
        state(row2).text === '…' && !state(row2).cls.includes('unavail'), state(row2).text);

  // …and the !isPaused clause on its own, with the switch generation left intact, since a real resume
  // trips the generation guard too and would hide it
  resetAll();
  onThreads(THREADS_EVENT);
  const row3 = makeRow('PUB:PUB_NAME');
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  isPaused = false;                       // running again; the sweep for this same switch is still armed
  await sleep(PENDING_SWEEP_MS + 40);
  check('the paused check alone is enough to hold the sweep back',
        state(row3).text === '…' && !state(row3).cls.includes('unavail'), state(row3).text);
  isPaused = true;
}

console.log('\n11b) a thread id near the top of the DWORD range is a normal id, not "unknown"');
{
  // Win32 thread ids are DWORDs. An id above Int32.MaxValue used to parse as null on the way through the
  // add-in, and null means UNSCOPED — so a reply the engine HAD stamped would be accepted as if it were
  // for whatever thread is on screen. That is the absent-means-unknown rule broken from the other side,
  // and it would hit roughly one thread id in two. (The parse itself is covered by tools/test-addin-json.ps1;
  // this is the consequence on the page.)
  const HIGH = 4294967295, HIGH2 = 3221225472;
  resetAll();
  onThreads({ type: 'threads', stopped: HIGH, selected: HIGH, threads: [
    { tid: HIGH, clarionThread: 1, proc: 'MAIN', module: 'clbrws.clw', line: 84, state: 'syscall', clarionFrames: 6, stopped: true, selected: true },
    { tid: HIGH2, clarionThread: 2, proc: 'BrowsePublishers', module: 'clbrws011.clw', line: 142, state: 'syscall', clarionFrames: 9, stopped: false, selected: false },
  ] });
  check('a high id is listed and marked as the stopped thread', stopTid === HIGH && selTid === HIGH
        && $('thList').children[0].children.some(c => c.textContent === 'Thread 1'));
  check('its own reply lands', tidAccepted({ tid: HIGH }));
  check('the OTHER high id is still gated out', !tidAccepted({ tid: HIGH2 }),
        'a stamped reply must never be mistaken for an unscoped one');

  const row = makeRow('PUB:PUB_NAME');
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'wrong thread'",
                             typeName: 'STRING(41)', threaded: true, tid: HIGH2 }));
  check('a value from the other high-id thread never paints', state(row).text === '…', state(row).text);
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'Algodata'",
                             typeName: 'STRING(41)', threaded: true, tid: HIGH }));
  check('the selected high-id thread\'s value does paint', state(row).text === "'Algodata'");
  check('selecting one sends the id unmangled',
        (clearSent(), selectThread(HIGH2), SENT[0] && SENT[0].data === String(HIGH2)), SENT[0] && SENT[0].data);
}

console.log('\n12) replies keyed by request id are cancelled, not left hanging');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const seen = [];
  requestFrameLocals({ va: '0x401000', ebp: '0x18ff00' }, items => seen.push(items));
  requestExpand({ module: 'clbrws.clw', typeRef: 7, addr: '0x847A76' }, items => seen.push(items));
  check('(setup) two replies are outstanding', Object.keys(_flCbs).length === 1 && Object.keys(_expandCbs).length === 1);

  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  check('both callbacks were told the reply is cancelled', seen.length === 2 && seen.every(s => s === null),
        JSON.stringify(seen));
  check('no callback is left registered for the old thread',
        Object.keys(_flCbs).length === 0 && Object.keys(_expandCbs).length === 0);

  // a late reply for one of them must now be a no-op rather than running a stale renderer
  const before = CALLS.length;
  onMessage(JSON.stringify({ type: 'framelocals', reqId: '1', items: [{ name: 'X', value: '1' }], tid: STOP_TID }));
  check('a late frame-locals reply does nothing', CALLS.length === before);
}

// ---- 87c66af6: the run-state band under the header is gone; its location detail moved to the header ----
// The band duplicated the run-state indicator and could contradict it. What it did NOT duplicate was the
// paused location, and a `source` reply does not always follow a pause — so these check the header now
// carries it in both cases, rather than trusting that the source panel will.
console.log('\n13) the paused location survives the removal of the run-state band');
{
  resetAll();
  check('the band itself is gone from the page', !/locbar/.test(html));
  check('and nothing still writes to it', html.indexOf("$('locbar')") < 0);

  // paused with NO source reply behind it — the case the source panel cannot cover
  onMessage(JSON.stringify({ type: 'paused', proc: 'BrowseCustomers', module: 'CUST.CLW', line: 412, tid: STOP_TID }));
  const h = $('srchdrText').innerHTML;
  console.log('   header after a bare pause: ' + JSON.stringify(h));
  check('the header names the module', h.includes('CUST.CLW'), h);
  check('…the line, which was the band\'s only unique detail', h.includes('412'), h);
  check('…and the procedure', h.includes('BrowseCustomers'), h);

  // and when the snippet does arrive, it must not say the location a different way
  onMessage(JSON.stringify({ type: 'source', file: 'CUST.CLW', proc: 'BrowseCustomers',
                             startLine: 410, lines: ['a', 'b', 'c'], current: 412 }));
  console.log('   header after the source reply: ' + JSON.stringify($('srchdrText').innerHTML));
  check('the source reply renders the identical header', $('srchdrText').innerHTML === h,
        JSON.stringify($('srchdrText').innerHTML) + ' vs ' + JSON.stringify(h));

  // NOT tested here: that going idle still calls clearSrc(). setRunState is a no-op stub in this suite
  // (line 74), so a check here would be testing the stub. It is asserted in test-pad-watch-persist.js,
  // which extracts the real one.
}

// ---- ec45805f item 13: a resume and a new stop end a cached value, same as a thread switch ----------
// invalidateThreadScopedState cleared the `values` cache; resetThreadState did not, and it is the one
// that runs at a resume and at every new pause. So a value cached at stop 1 stayed readable through
// stop 2 for any name the engine did not answer again.
//
// Driven per READER, because the cache's readers are not all visible cells a fresh reply would repaint,
// and the reader that actually breaks has no cell at all. Enumerated: (a) the tip's value, (b) the tip's
// type, (c) the tip's engine note, (d) the tip's Copy Value, (e) an expanded Watch .wdetail, and (f) the
// tip over a SOURCE identifier, where the cache is the only value that has ever existed.
console.log('\nX) a resume and a new stop clear the values cache, for every reader of it');
{
  resetAll();
  const NAME = 'CUS:STATE';
  const row = makeRow(NAME);
  // Stop 1 answers it, with a type and an engine caveat, so every field the tip can read is populated.
  applyValue(NAME, true, "'CA'", 'STRING(2)', true,
             { va: A_INSTANCE.va, typeCode: '0x18', size: 2, places: 0, note: 'shared template' });
  check('precondition: stop 1 cached a value, a type and a note', values.size === 1
        && values.get(nameKey(NAME)).value === "'CA'" && values.get(nameKey(NAME)).type === 'STRING(2)'
        && values.get(nameKey(NAME)).note === 'shared template',
        JSON.stringify(values.get(nameKey(NAME))));

  // (f) FIRST - the reader with no row behind it. A source identifier the developer hovers.
  const token = new El('span'); token.dataset.name = NAME; doc.body.appendChild(token);
  showTipFor(token);
  check('CONTROL: while stop 1 stands, the source-identifier tip shows its value',
        $('dtVal').textContent.includes('CA'), $('dtVal').textContent);

  // The target runs on. THIS is the boundary that was not closing the cache.
  onMessage(JSON.stringify({ type: 'resumed' }));
  check('a resume empties the cache', values.size === 0, 'size=' + values.size);

  showTipFor(token);
  check('(f) the source-identifier tip no longer quotes stop 1\'s value',
        !$('dtVal').textContent.includes('CA'), $('dtVal').textContent);
  check('(a) it offers the not-watched prompt instead of a stale number',
        $('dtVal').textContent.includes('not watched'), $('dtVal').textContent);
  check('(b) the type is not carried over either', $('dtType').textContent === '', $('dtType').textContent);
  check('(c) and neither is the engine note', !$('dtVal').textContent.includes('shared template'),
        $('dtVal').textContent);
  // (d) Copy Value copies whatever the tip resolved, so it cannot disagree with what was just checked -
  // named as the reader it is rather than re-asserted, because $('dtCopy') is wired by page code this
  // suite does not extract.
  check('(d) Copy Value copies the tip\'s own text, so it inherits (a)',
        /copyText\(tipTarget\.val\)/.test(html) && /tipTarget=\{name,type,val\}/.test(html));

  // (e) an expanded .wdetail reads the cache when it is OPENED, so it is a reader of a later moment.
  const det = new El('div'); det.className = 'wdetail'; det.dataset.detail = NAME; det.style.display = '';
  doc.body.appendChild(det);
  det.textContent = values.has(nameKey(NAME)) ? values.get(nameKey(NAME)).value : '';
  check('(e) a panel opened after the resume has no cached value to show', det.textContent === '',
        JSON.stringify(det.textContent));

  // And the same boundary at a NEW STOP, not only at a resume - resetThreadState owns both paths.
  applyValue(NAME, true, "'CA'", 'STRING(2)', true, { va: A_INSTANCE.va, typeCode: '0x18', size: 2, places: 0 });
  check('precondition: a value is cached again', values.size === 1, 'size=' + values.size);
  onMessage(JSON.stringify({ type: 'paused', module: 'CUST.CLW', proc: 'BrowseCustomers', line: 412,
                             tid: STOP_TID, regs: null }));
  check('a NEW STOP empties it too', values.size === 0, 'size=' + values.size);
  showTipFor(token);
  check('…so the source-identifier tip does not carry stop 1 into stop 2',
        !$('dtVal').textContent.includes('CA'), $('dtVal').textContent);

  // ISOLATION: the clear is tied to the episode boundary, not to "the tip shows nothing any more".
  // A value answered AFTER the new stop must be readable exactly as before.
  applyValue(NAME, true, "'NV'", 'STRING(2)', true, { va: A_INSTANCE.va, typeCode: '0x18', size: 2, places: 0 });
  showTipFor(token);
  check('CONTROL: this stop\'s own answer is shown normally', $('dtVal').textContent.includes('NV'),
        $('dtVal').textContent);
  check('   and the row still carries it', state(row).text === "'NV'", state(row).text);
}

console.log('\nH) identify thread by window (f6e547ce): report while running, settle-then-select while paused');
{
  const OTHER_TID = 6012;   // a third thread, so a hover can target something other than the switch in flight
  function threeThreads(sel) {
    const e = freshThreadsEvent(sel);
    e.threads.push({ tid: OTHER_TID, clarionThread: 3, proc: 'BrowseAuthors', module: 'clbrws012.clw', line: 88,
                     state: 'syscall', clarionFrames: 7, stopped: false, selected: false });
    return e;
  }
  const selects = () => SENT.filter(m => m.action === 'selectthread').map(m => m.data);
  const hov = (tid, paused) => onMessage(JSON.stringify(tid == null ? { type: 'hover', on: true, paused }
                                                                    : { type: 'hover', on: true, paused, tid }));
  const settle = () => sleep(HOVER_SETTLE_MS + 30);

  const m = html.match(/const\s+HOVER_SETTLE_MS\s*=\s*(\d+)/);
  check('HOVER_SETTLE_MS is defined in the page, long enough to be a debounce (>= 150 ms, the poll)',
        !!m && +m[1] >= 150, m ? m[1] : 'missing');

  // H1. the toggle is what reaches the host
  resetAll();
  setHoverMode(true);
  check('H1 turning it on sends hover/on', SENT.length === 1 && SENT[0].action === 'hover' && SENT[0].data === 'on',
        JSON.stringify(SENT));
  check('   and the toggle shows it is on', $('thHover').classList.contains('on'));
  clearSent(); setHoverMode(false);
  check('   turning it off sends hover/off', SENT.length === 1 && SENT[0].data === 'off', JSON.stringify(SENT));
  check('   and the label empties', $('thHoverText').textContent === '', $('thHoverText').textContent);

  // H2. running: REPORT only
  resetAll(); hoverOn = true; isPaused = false;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(BROWSE_TID, false);
  check('H2 running: the label names the window\'s thread', $('thHoverText').textContent === 'Thread 2',
        $('thHoverText').textContent);
  check('   and says it cannot switch until paused', /Pause to read/.test($('thHover').title), $('thHover').title);
  await settle();
  check('   and never selects, however long the pointer rests', selects().length === 0, JSON.stringify(SENT));
  // CONTROL: the same answer, paused, DOES select - so H2 is not passing because selection is broken.
  isPaused = true; hov(BROWSE_TID, true); await settle();
  check('   CONTROL: the same thread while paused is selected', selects().join() === String(BROWSE_TID), selects().join());

  // H2b. the other race: the engine answered while RUNNING, and the answer lands after the page saw the
  // stop. It describes a window from before the stop, so it reports and does not select.
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(BROWSE_TID, false); await settle();
  check('H2b a running-time answer landing on a paused page selects nothing', selects().length === 0, selects().join());

  // H3. paused: debounce. A pass over several threads selects only the one the pointer settles on.
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(BROWSE_TID, true);
  check('H3 no switch the moment a hover arrives', selects().length === 0, JSON.stringify(SENT));
  hov(OTHER_TID, true); hov(null, true); hov(BROWSE_TID, true);
  await settle();
  check('   one switch, to the thread it settled on, after a pass over three answers',
        selects().join() === String(BROWSE_TID), selects().join() || 'none');

  // H4. none (the IDE on top, or empty desktop) selects nothing and says so
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(BROWSE_TID, true); hov(null, true);
  await settle();
  check('H4 moving off the program cancels the pending switch', selects().length === 0, selects().join());
  check('   and the label shows none', $('thHoverText').textContent === '—', $('thHoverText').textContent);

  // H5. the thread already shown is not re-selected (a re-read would only flicker)
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(STOP_TID, true); await settle();
  check('H5 hovering the thread already selected sends nothing', SENT.length === 0, JSON.stringify(SENT));

  // H6. the in-flight guard: no second switch over one that has not answered
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID));
  selectThread(BROWSE_TID); clearSent();
  check('H6 precondition: a switch is in flight', threadSwitching === true);
  hov(OTHER_TID, true); await settle(); await settle();
  check('   a settled hover does not start a second switch while it is', selects().length === 0, selects().join());
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  check('   precondition: the first switch has landed', threadSwitching === false && selTid === BROWSE_TID);
  clearSent(); await settle();
  check('   and once it lands, the hover still under the pointer is honoured',
        selects().join() === String(OTHER_TID), selects().join() || 'none');

  // H7. a resume, a new stop, or turning the mode off each cancels a pending switch
  for (const [what, act] of [
    ['a resume', () => onMessage(JSON.stringify({ type: 'resumed' }))],
    ['a new stop', () => onMessage(JSON.stringify({ type: 'paused', module: 'CUST.CLW', proc: 'Main', line: 1, tid: STOP_TID, regs: null }))],
    ['turning it off', () => setHoverMode(false)],
  ]) {
    resetAll(); hoverOn = true;
    onThreads(threeThreads(STOP_TID));
    hov(BROWSE_TID, true); act(); clearSent();
    await settle();
    check('H7 ' + what + ' before the pointer settles cancels the switch', selects().length === 0, selects().join());
  }

  // H7b. a paused:true answer that lands after the page has seen the resume (the engine polled just before
  // it resumed) must not switch a page that is no longer paused.
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); isPaused = false; clearSent();
  hov(BROWSE_TID, true); await settle();
  check('H7b a stale paused answer after the resume selects nothing', selects().length === 0, selects().join());

  // H7c. an answer still in flight when the toggle went off is shown nowhere and selects nothing
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID));
  setHoverMode(false); clearSent();
  hov(BROWSE_TID, true); await settle();
  check('H7c a late answer after turning it off selects nothing', selects().length === 0, selects().join());

  // H12. a NEW STOP never pulls the view off the stopped thread by itself (pipeline run 1). The engine
  // sends one fresh answer per stop; the page takes it as the baseline, and only a later change selects.
  // Two step lengths, which must behave the same: SHORT (under the 150 ms poll, so no running answer came
  // between the stops) and LONG (a running answer for the same window came first).
  const stopEv = () => onMessage(JSON.stringify({ type: 'paused', module: 'CUST.CLW', proc: 'Main', line: 1,
                                                  tid: STOP_TID, regs: null }));
  const stepThenStop = long => {
    onMessage(JSON.stringify({ type: 'resumed' }));
    if (long) hov(BROWSE_TID, false);
    stopEv(); onThreads(threeThreads(STOP_TID));
    hov(BROWSE_TID, true);                          // the stop's one fresh answer: the pointer rests on B
  };
  for (const long of [false, true]) {
    const what = long ? 'LONG step' : 'SHORT step';
    resetAll(); hoverOn = true;
    stopEv(); onThreads(threeThreads(STOP_TID));
    hov(BROWSE_TID, true);                          // stop 1's baseline
    clearSent(); await settle();
    check('H12 ' + what + ': the first answer at a stop does not select', selects().length === 0, selects().join());
    stepThenStop(long); clearSent(); await settle();
    check('   and after the ' + what + ' the next stop\'s first answer does not select either',
          selects().length === 0 && selTid === STOP_TID, selects().join() + ' sel=' + selTid);
    hov(OTHER_TID, true); await settle();
    check('   a CHANGE of the hovered thread while paused does select',
          selects().join() === String(OTHER_TID), selects().join() || 'none');
  }

  // H8. a window whose thread is not in this stop's list earns no request (and so no refusal toast)
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID)); clearSent();
  hov(99991, true); await settle();
  check('H8 a thread missing from the list is not requested', selects().length === 0, selects().join());

  // H9. the event is NOT gated by tidAccepted: its tid is rarely the selected thread, and that is the point.
  resetAll(); hoverOn = true;
  onThreads(threeThreads(STOP_TID));
  check('H9 precondition: tidAccepted WOULD drop this tid', !tidAccepted({ tid: BROWSE_TID }));
  hov(BROWSE_TID, true);
  check('   but the hover event still lands', hoverTid === BROWSE_TID && $('thHoverText').textContent === 'Thread 2',
        $('thHoverText').textContent);

  // H10. the engine's on:false clears the report
  hov(BROWSE_TID, false);
  onMessage(JSON.stringify({ type: 'hover', on: false, paused: false }));
  check('H10 on:false from the engine clears the thread', hoverTid === null && $('thHoverText').textContent === '—',
        $('thHoverText').textContent);

  // H11. a new engine starts with hover off: re-arm it at session start, and only then
  resetAll(); hoverOn = true; clearSent();
  const hoverSends = () => SENT.filter(x => x.action === 'hover').length;
  onMessage(JSON.stringify({ type: 'runstate', state: 'launching' }));
  check('H11 a session start re-arms the engine', hoverSends() === 1, JSON.stringify(SENT));
  onMessage(JSON.stringify({ type: 'runstate', state: 'running' }));
  onMessage(JSON.stringify({ type: 'runstate', state: 'paused' }));
  onMessage(JSON.stringify({ type: 'runstate', state: 'running' }));
  check('   but a resume inside the session does not resend it', hoverSends() === 1, JSON.stringify(SENT));
  onMessage(JSON.stringify({ type: 'runstate', state: 'idle' }));
  onMessage(JSON.stringify({ type: 'runstate', state: 'launching' }));
  check('   and the next session re-arms it again', hoverSends() === 2, JSON.stringify(SENT));
  hoverOn = false; onMessage(JSON.stringify({ type: 'runstate', state: 'idle' }));
  onMessage(JSON.stringify({ type: 'runstate', state: 'launching' }));
  check('   CONTROL: with the toggle off nothing is sent', hoverSends() === 2, JSON.stringify(SENT));
}

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);
})();

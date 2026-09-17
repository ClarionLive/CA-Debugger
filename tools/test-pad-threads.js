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
//   node tools/test-pad-threads.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const html = pad.readPage(process.argv[2]);
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

// ---- collaborators that are NOT under test ---------------------------------------------------------
const CALLS = [];
const spy = name => (...a) => { CALLS.push(name); return undefined; };
function buildLocals() { CALLS.push('buildLocals'); }
function buildModuleData() { CALLS.push('buildModuleData'); }
function buildRegs(r) { CALLS.push('buildRegs:' + (r ? 'regs' : 'null')); }
function renderLibState() { CALLS.push('renderLibState'); }
function refreshLibState() { CALLS.push('refreshLibState'); }
function onLibState() { CALLS.push('onLibState'); }
function renderModuleData() { }
function applyStackFilter() { }
function sortVars(x) { return x; }
function renderVarRow() { }
function setAbout() { } function setTarget() { } function setRunState() { } function setPaused(p) { isPaused = p; }
function buildVarTree() { } function collectSyms() { return []; } function buildBps() { } function buildProcs() { }
function buildSource() { } function clearSrc() { } function onVarSet() { } function setLayoutDirty() { }
function refreshWatchClipping() { }

// ---- the page's own code ---------------------------------------------------------------------------
const FNS = ['esc', 'send', 'resetThreadState',
  'dtParseInt', 'fieldPart', 'fmtClarionDate', 'fmtClarionTime', 'dtDefault', 'dtModeFor', 'dtApply', 'dtCycle',
  'clearEditMeta', 'setEditMeta', 'applyNote', 'wireEdit', 'applyValue', 'showTipFor',
  'stripEditQuotes', 'beginEdit', 'cancelActiveEdit',
  'tidAccepted', 'threadRowFor', 'threadName', 'threadProc', 'threadPickerOpen', 'closeThreadPicker',
  'toggleThreadPicker', 'requestThreads', 'renderThreadPicker', 'renderThreadUi', 'selectThread',
  'onThreads', 'onThreadSelected', 'onEngineError', 'beginThreadSwitch', 'invalidateThreadScopedState',
  'cancelPendingCallbacks', 'armPendingSweep', 'requestFrameLocals', 'requestExpand',
  'buildStack', 'renderStack', 'onMessage'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { missing.push(n); return 'function ' + n + '(){}'; }
}).join('\n');
if (missing.length) console.log('   (note: absent from this page — pre-fix? ' + missing.join(', ') + ')');
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

console.log('\n4) the switch invalidates EVERY reader of the old thread\'s value');
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

console.log('\n6) a watch row re-resolves into 50414e39\'s per-thread states, not a second vocabulary');
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
  check('no panel is re-read against a thread we did not get',
        !sentActions().includes('stack') && !sentActions().includes('rewatch'), sentActions().join(','));
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

console.log('\n10) a row is never left on "…" when no reply can come');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const answered = makeRow('PUB:PUB_NAME');
  const never = makeRow('PUB:CITY');                       // collapsed tree row: nobody is watching it
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);

  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  check('(setup) both rows read "…" right after the switch',
        state(answered).text === '…' && state(never).text === '…');

  await sleep(PENDING_SWEEP_MS + 40);
  const a = state(answered), n = state(never);
  console.log('   answered-before: ' + JSON.stringify(a) + '\n   never-answered:  ' + JSON.stringify(n));
  check('a row that had a value and got no reply stops pretending to load',
        a.text === '(no reply)' && a.cls.includes('unavail') && !a.cls.includes('pending'));
  check('…and says which thread did not answer', (a.title || '').includes(String(BROWSE_TID)), a.title);
  check('a row nobody asked about is left alone', n.text === '…' && n.cls.includes('pending'));
  check('the console records it', LOGGED.some(l => l.includes('got no reply')), LOGGED.join('|'));
}

console.log('\n11) the sweep never fires over a newer switch or a resumed target');
{
  resetAll();
  onThreads(THREADS_EVENT);
  const row = makeRow('PUB:PUB_NAME');
  applyValue('PUB:PUB_NAME', true, "'Algodata'", 'STRING(41)', true, A_INSTANCE);
  onThreadSelected({ type: 'threadselected', tid: BROWSE_TID, ok: true });
  onThreads(freshThreadsEvent(BROWSE_TID));
  onThreadSelected({ type: 'threadselected', tid: STOP_TID, ok: true });   // switched again straight away
  // the reply for the SECOND switch arrives
  onMessage(JSON.stringify({ type: 'watch', name: 'PUB:PUB_NAME', found: true, value: "'Algodata'",
                             typeName: 'STRING(41)', threaded: true, tid: STOP_TID }));
  await sleep(PENDING_SWEEP_MS + 40);
  check('the first switch\'s sweep does not overwrite the second switch\'s value',
        state(row).text === "'Algodata'", state(row).text);
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

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);
})();

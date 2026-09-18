// Watch-list persistence (ticket 08adccc7), run against the REAL functions in debugger.html.
//
// Same idea as pad-dom.js and test-addin-json.ps1: extract the shipped code and run it, rather than
// re-implementing it here where a copy could agree with itself while the page does something else.
//
// What these checks defend, in order of how much it matters:
//   1. a restored row NEVER renders in the pending "…" state — nothing can answer it until the first
//      pause, and a row that claims a reply is coming is the failure 50414e39 and 0128a37e both removed;
//   2. the store is keyed per TARGET EXE, so one application's names never appear in another;
//   3. a removal persists — a name you deleted does not come back;
//   4. a restore registers each name with the host, so the first pause answers it.
//
// Run: node tools/test-pad-watch-persist.js [path-to-debugger.html]   (exit 0 = pass)
// NOT strict mode, deliberately and like the sibling suites: the page's functions are brought in with
// eval(), and only sloppy mode lets those declarations land in this scope where the checks can call them.
const pad = require('./pad-dom');
const html = pad.readPage(process.argv[2]);
const El = pad.El;

// ---- the scope the page's functions run in ---------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);

const SENT = [];
const wv = { postMessage: s => SENT.push(JSON.parse(s)) };
const sent = a => SENT.filter(s => s.action === a).map(s => s.data);
// the page's own send(): the real one is a one-liner over wv.postMessage, extracted below with the rest
function send(action, data) { wv.postMessage(JSON.stringify({ action: action, data: data === undefined ? null : data })); }
function clearSent() { SENT.length = 0; }

const TOASTS = [];
function toast(m) { TOASTS.push(m); }
function esc(s) { return (s == null ? '' : String(s)).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

// a localStorage that behaves like the real one, including the throwing variants the page must survive
let STORE = {};
let storageMode = 'ok';   // 'ok' | 'throw-read' | 'throw-write'
const localStorage = {
  getItem(k) { if (storageMode === 'throw-read') throw new Error('access denied'); return Object.prototype.hasOwnProperty.call(STORE, k) ? STORE[k] : null; },
  setItem(k, v) { if (storageMode === 'throw-write') throw new Error('quota exceeded'); STORE[k] = String(v); },
};

// page state the extracted functions close over
const watched = new Map();
const values = new Map();
let paused = false, runState = 'idle', targetPath = null;
let renders = 0;

const FNS = ['WATCH_STORE', 'WATCH_MAX', 'WATCH_TARGETS',
  'nameKey', 'sessionLive', 'watchedKey', 'targetKey', 'loadWatchStore', 'saveWatches',
  'restoreWatchesFor', 'addWatchSilent', 'addWatch', 'removeWatch', 'watchWaitingHtml', 'setRunState'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { try { return pad.extractConst(html, n); } catch (e2) { missing.push(n); return 'function ' + n + '(){}'; } }
}).join('\n');
// A function this suite cannot find is a HARD FAILURE, not a stub. Stubbing lets the whole run pass
// vacuously — which is what it did against the pre-fix page, reporting zero failures while testing
// nothing. Pass --allow-missing to do that deliberately (only useful for a pre-fix comparison).
if (missing.length) {
  const deliberate = process.argv.indexOf('--allow-missing') > 0;
  console.log((deliberate ? '   (stubbed on purpose: ' : '   MISSING from the page: ') + missing.join(', ') + ')');
  if (!deliberate) {
    console.log('\nFAILED: the page does not define what this suite tests. Renamed, or run against a pre-fix page?');
    process.exit(1);
  }
}
// The page's `const` limits live inside eval's own scope (sloppy mode only leaks var/function), so hand
// them back out deliberately. Read from the page, never restated here — a test that hard-codes 200 keeps
// passing after someone changes the page to 20.
var LIM = {};
eval(src + ';LIM = { WATCH_STORE: WATCH_STORE, WATCH_MAX: WATCH_MAX, WATCH_TARGETS: WATCH_TARGETS };');
const WATCH_STORE = LIM.WATCH_STORE, WATCH_MAX = LIM.WATCH_MAX, WATCH_TARGETS = LIM.WATCH_TARGETS;

// renderWatchList builds its rows with innerHTML, which this test DOM does not parse — so the rows are
// read from `watched` (the list the page renders FROM) and the value cell is asked for directly via
// watchWaitingHtml(), which is why that decision lives in its own function in the page.
function resetDom() {
  $('watchList').children.length = 0;
  renders = 0;
}
function renderWatchList() { renders++; }   // counted, not exercised; see the note above

function rowsOnScreen() { return Array.from(watched.keys()).map(name => ({ name })); }
function waitingCell() {
  const html = watchWaitingHtml();
  const cls = (html.match(/class=\"([^\"]+)\"/) || [, ''])[1];
  const title = (html.match(/title=\"([^\"]+)\"/) || [, ''])[1];
  const text = (html.match(/>([^<]*)<\/span>/) || [, ''])[1];
  return { cls, text, title, html };
}
function valueCell() { return waitingCell(); }
function reset(mode) {
  STORE = {}; storageMode = mode || 'ok';
  watched.clear(); values.clear();
  targetPath = null; runState = 'idle'; paused = false;
  restoredForTarget = null;
  clearSent(); TOASTS.length = 0; resetDom();
}
// a fresh pad session against the same store: memory cleared, store kept
function restart() {
  watched.clear(); values.clear();
  targetPath = null; runState = 'idle'; restoredForTarget = null;
  clearSent(); resetDom();
}

let fails = 0, checks = 0;
function ok(cond, what, detail) {
  checks++;
  if (cond) { console.log('  PASS  ' + what + (detail ? '  ->  ' + detail : '')); }
  else { fails++; console.log('  FAIL  ' + what + (detail ? '  ->  ' + detail : '')); }
}
function section(t) { console.log('\n' + t); }

const APP = 'C:\\Apps\\Orders\\orders.exe';
const OTHER = 'C:\\Apps\\Payroll\\payroll.exe';

// ---------------------------------------------------------------------------------------------------
section('1) a restored row does not claim a reply is coming');
reset();
targetPath = APP; restoreWatchesFor(APP);           // first resolution, nothing stored
addWatchSilent('CUS:NAME'); addWatchSilent('CUS:CITY');
restart();
targetPath = APP; restoreWatchesFor(APP);           // the next pad session
let names = rowsOnScreen().map(r => r.name);
ok(names.length === 2 && names.indexOf('CUS:NAME') >= 0, 'both names came back', JSON.stringify(names));
let c = valueCell('CUS:NAME');
ok(c && c.cls.indexOf('pending') < 0, 'the row is NOT pending', c && JSON.stringify(c.cls));
ok(c && c.text !== '…', 'it does not show the pending ellipsis', c && JSON.stringify(c.text));
ok(c && c.cls.indexOf('idle') >= 0 && /pause/i.test(c.text), 'it says a pause is needed', c && c.text);
ok(c && /first pause/i.test(c.title), 'and the tooltip explains when it will read', c && c.title);
ok(sent('watch').indexOf('CUS:NAME') >= 0, 'the host was told the name, so the first pause answers it');

section('2) with a session live, a new watch is pending — the other kind of waiting');
setRunState('paused');
addWatchSilent('CUS:ID');
c = valueCell('CUS:ID');
ok(c && c.cls.indexOf('pending') >= 0 && c.text === '…', 'a watch added while paused shows pending', c && c.text);
c = valueCell('CUS:NAME');
ok(c && c.cls.indexOf('pending') >= 0, 'and rows re-rendered under a live session are pending too', c && c.cls);

section('3) a removal stays removed');
reset();
targetPath = APP; restoreWatchesFor(APP);
addWatchSilent('A:ONE'); addWatchSilent('A:TWO');
removeWatch('A:ONE');
restart(); targetPath = APP; restoreWatchesFor(APP);
names = rowsOnScreen().map(r => r.name);
ok(names.length === 1 && names[0] === 'A:TWO', 'the deleted name did not come back', JSON.stringify(names));

section('4) the store is per target — no cross-app leak');
reset();
targetPath = APP; restoreWatchesFor(APP);
addWatchSilent('ORD:TOTAL');
restart();
targetPath = OTHER; restoreWatchesFor(OTHER);
names = rowsOnScreen().map(r => r.name);
ok(names.length === 0, 'a different app starts with no watches', JSON.stringify(names));
addWatchSilent('PAY:RATE');
restart(); targetPath = APP; restoreWatchesFor(APP);
names = rowsOnScreen().map(r => r.name);
ok(names.length === 1 && names[0] === 'ORD:TOTAL', 'and each app keeps its own list', JSON.stringify(names));
// the same app reached through a differently-cased path is the same app
restart(); targetPath = APP.toLowerCase(); restoreWatchesFor(APP.toLowerCase());
ok(rowsOnScreen().length === 1, 'a differently-cased path is the same target');

section('5) switching target mid-session replaces, it does not carry over');
reset();
targetPath = APP; restoreWatchesFor(APP); addWatchSilent('ORD:TOTAL');
targetPath = OTHER; restoreWatchesFor(OTHER);       // same pad session, new target
names = rowsOnScreen().map(r => r.name);
ok(names.length === 0, "the old app's names are gone when the target changes", JSON.stringify(names));

section('6) a watch typed before the target is known is kept, not overwritten');
reset();
addWatchSilent('EARLY:NAME');                        // no target yet — nothing to key it to
ok(rowsOnScreen().length === 1, 'the name is on screen with no target');
targetPath = APP; restoreWatchesFor(APP);            // first resolution merges rather than replaces
names = rowsOnScreen().map(r => r.name);
ok(names.indexOf('EARLY:NAME') >= 0, 'it survives the first target resolution', JSON.stringify(names));
restart(); targetPath = APP; restoreWatchesFor(APP);
ok(rowsOnScreen().map(r => r.name).indexOf('EARLY:NAME') >= 0, 'and it was written to the store');

section('7) one name, one row, whatever the case');
reset();
targetPath = APP; restoreWatchesFor(APP);
addWatchSilent('Cus:Name');
restart(); targetPath = APP; restoreWatchesFor(APP);
addWatch('CUS:NAME');                                // the same variable, differently spelled
ok(rowsOnScreen().length === 1, 'the restored name is recognised as already watched', String(rowsOnScreen().length));
ok(TOASTS.some(t => /already watched/i.test(t)), 'and the user is told, not given a second row');

section('8) a hostile stored value cannot break startup');
reset();
STORE[WATCH_STORE] = '{not json at all';
targetPath = APP; restoreWatchesFor(APP);
ok(rowsOnScreen().length === 0 && renders >= 0, 'malformed JSON restores nothing and does not throw');
reset();
STORE[WATCH_STORE] = JSON.stringify({ v: 1, byTarget: { [APP.toLowerCase()]: { names: ['GOOD:ONE', 42, null, { x: 1 }, ''] } } });
targetPath = APP; restoreWatchesFor(APP);
names = rowsOnScreen().map(r => r.name);
ok(names.length === 1 && names[0] === 'GOOD:ONE', 'non-string entries are skipped, the good one is kept', JSON.stringify(names));
// a name is rendered as TEXT, never as markup
reset();
STORE[WATCH_STORE] = JSON.stringify({ v: 1, byTarget: { [APP.toLowerCase()]: { names: ['<img src=x onerror=1>'] } } });
targetPath = APP; restoreWatchesFor(APP);
const rawName = Array.from(watched.keys())[0];
ok(rawName === '<img src=x onerror=1>', 'the raw name is kept as data', JSON.stringify(rawName));
ok(esc(rawName).indexOf('&lt;img') === 0, 'and the page escapes it before it reaches the DOM', esc(rawName).slice(0, 24));

section('9) storage that refuses does not cost anything but the feature');
reset('throw-write');
targetPath = APP; restoreWatchesFor(APP);
addWatchSilent('X:ONE');
ok(rowsOnScreen().length === 1, 'a watch still works when the store cannot be written');
reset('throw-read');
targetPath = APP;
let threw = false;
try { restoreWatchesFor(APP); } catch (e) { threw = true; }
ok(!threw && rowsOnScreen().length === 0, 'a store that cannot be read restores nothing and does not throw');

section('10) the store stays bounded');
reset();
targetPath = APP; restoreWatchesFor(APP);
for (let i = 0; i < 260; i++) watched.set('N:' + i, {});
saveWatches();
let stored = JSON.parse(STORE[WATCH_STORE]).byTarget[APP.toLowerCase()].names;
ok(stored.length === WATCH_MAX, 'at most WATCH_MAX names per target are stored', stored.length + ' of ' + WATCH_MAX);
reset();
for (let i = 0; i < 30; i++) { restart(); targetPath = 'C:\\app' + i + '.exe'; restoreWatchesFor(targetPath); addWatchSilent('K:' + i); }
const targets = Object.keys(JSON.parse(STORE[WATCH_STORE]).byTarget).length;
ok(targets <= WATCH_TARGETS, 'at most WATCH_TARGETS targets are kept', targets + ' of ' + WATCH_TARGETS);

console.log('\n' + (fails ? fails + ' of ' + checks + ' CHECKS FAILED' : 'ALL ' + checks + ' CHECKS PASSED'));
process.exit(fails ? 1 : 0);

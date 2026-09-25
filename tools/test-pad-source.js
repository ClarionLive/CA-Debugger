// Regression check: a pause with NO source file must not leave the PREVIOUS stop's code on screen.
//
// 87c66af6 moved the location caption into the source header and made the 'paused' handler always write it
// through setSrcLocation. But the host's SendSource returned silently when the .clw path could not be
// resolved, so no `source` message followed that pause and $('src'), curFile and curLine kept the previous
// stop's file, listing and highlight. The header then named location B over listing A.
//
// curFile is the load-bearing one. The page sends run-to-cursor as `curFile + ':' + line`, so a curFile
// left over from the last stop arms a breakpoint in a file the user is no longer stopped in - a breakpoint
// they did not ask for, in code they are not looking at.
//
// The fix gives "no source for this stop" ONE owner: the host always posts a `source` message, with an
// empty `lines` array when there is nothing to read, and buildSource is the single writer of the listing
// and of curFile/curLine - the same shape 87c66af6 gave the location caption.
//
// Runs the REAL page functions out of debugger.html against the shared mini-DOM (tools/pad-dom.js). Point
// it at a pre-fix copy of the page and the no-source scenario fails; that is the before/after proof.
//
// THE MESSAGES BELOW ARE NOT HAND-WRITTEN. They are the exact strings the shipped SendSource produced,
// captured in tools/fixtures/host-source-messages.json by tools/test-addin-json.ps1, which brace-matches
// that method out of ClarionDebuggerWebView.cs, compiles it, runs it and fails when this file no longer
// matches its output. Both halves of the no-source contract are therefore pinned to ONE artefact: a host
// change that put a placeholder line in the empty `lines` array breaks the PowerShell suite until the
// fixture is regenerated, and regenerating it breaks scenario 2 here. Two hand-written fixtures on either
// side of a contract verify nothing, because they cannot contradict each other.
//
//   node tools/test-pad-source.js [path/to/debugger.html] [--host-source=path/to/fixture.json]
// Exit code 0 = all checks passed.
const fs = require('fs');
const path = require('path');
const pad = require('./pad-dom');
const args = process.argv.slice(2);
const pagePath = args.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const El = pad.El;

const fxArg = args.find(a => a.startsWith('--host-source='));
const fxPath = fxArg ? fxArg.slice('--host-source='.length)
                     : path.join(__dirname, 'fixtures', 'host-source-messages.json');
let HOST;
try {
  HOST = JSON.parse(fs.readFileSync(fxPath, 'utf8'));
} catch (e) {
  // Falling back to a hand-written message here is exactly the failure this file exists to prevent, so
  // there is no fallback.
  console.log('  FAIL  cannot read the host-output fixture ' + fxPath + ': ' + e.message
              + '\n        regenerate it with: pwsh -NoProfile -File tools/test-addin-json.ps1 -UpdateHostSourceFixture');
  process.exit(1);
}
for (const k of ['noSource', 'withSource']) {
  if (typeof HOST[k] !== 'string') {
    console.log('  FAIL  the host-output fixture has no ' + k + ' message: ' + fxPath);
    process.exit(1);
  }
}

// ---- scope the page's functions run in -------------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);
const window = { innerWidth: 1200, innerHeight: 800 };

const SENT = [];
const wv = { postMessage: s => SENT.push(JSON.parse(s)) };

// ---- collaborators that are NOT under test ---------------------------------------------------------
function attachTip() { }
function setAbout() { } function setTarget() { } function setRunState() { } function setPaused() { }
function resetThreadState() { } function buildRegs() { } function refreshLibState() { }
function memReread() { } function onMem() { }   // Memory panel: tools/test-pad-memory.js
function renderLibState() { } function onLibState() { } function buildVarTree() { }
function collectSyms() { return []; } function onThreads() { } function onThreadSelected() { }
function onEngineError() { } function tidAccepted() { return true; } function buildStack() { }
function applyValue() { } function onVarSet() { } function buildBps() { } function buildProcs() { }
function buildModuleData() { } function logLine() { } function toast() { }
function send() { }

// page state the extracted functions close over
let curFile = null, curLine = 0;
let allSyms = [], bps = [];
// the thread selection buildSource labels the header from (section 6); null = no selection, as at startup
let selTid = null, stopTid = null, threadRows = [];
let lastLibState = null, lastLibError = null;
const _flCbs = {}, _expandCbs = {};

// ---- the page's own code ---------------------------------------------------------------------------
const FNS = ['esc', 'reEsc', 'setSrcLocation', 'clearSrc', 'buildSource', 'renderBpDots', 'onMessage',
             'viewingOtherThread', 'threadName', 'threadRowFor'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { missing.push(n); return 'function ' + n + '(){}'; }
}).join('\n');
if (missing.length) {
  // A missing function stubbed away returns undefined for every call, so the scenarios below would pass
  // vacuously and the run would still exit 0. Refuse instead.
  console.log('  FAIL  ' + missing.length + ' of ' + FNS.length + ' page function(s) not found in '
              + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
eval(src);

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}
function slines() { return $('src').querySelectorAll('.sline'); }
// The header as markup: the location setSrcLocation writes as innerHTML, then what buildSource appends with
// DOM APIs (the thread label, 730ef328), serialised the way a browser would read it back.
function headerText() {
  const h = $('srchdrText');
  const tail = h.children.map(c => c.tag === '#text' ? esc(c.textContent)
    : '<' + c.tag + (c.className ? ' class="' + c.className + '"' : '') + '>' + esc(c.textContent) + '</' + c.tag + '>').join('');
  return (h.innerHTML || h.textContent) + tail;
}

// ---- fixtures: what the host really posts -----------------------------------------------------------
// Read out of the captured host messages rather than declared here, so nothing below can assert against a
// value the writer does not actually send.
const A = JSON.parse(HOST.withSource);          // a stop the host HAD a .clw for
const B = JSON.parse(HOST.noSource);            // a stop it could not resolve a path for
const A_FILE = A.file, A_LINE = A.current, A_LINES = A.lines;
const B_MODULE = B.file, B_LINE = B.current;

function pausedAt(module, proc, line) {
  onMessage(JSON.stringify({ type: 'paused', module: module, proc: proc, line: line, regs: null }));
}
// The host's own string, byte for byte, straight into the page's real handler.
function hostSource(which) { onMessage(HOST[which]); }

console.log('0) the captured host messages are the two cases this file claims to cover');
// Named as CONTROLS: without them a fixture regenerated from a changed writer could quietly stop being a
// with-source / no-source pair, and every scenario below would still "pass".
{
  check('the with-source message carries a listing', A_LINES.length > 0, A_LINES.length + ' line(s)');
  check('...and its file is a .clw the host read, not a module it fell back to',
        /\.clw$/.test(A_FILE) && A.startLine === A_LINE - 12, A_FILE + ' startLine=' + A.startLine);
  // THE HOST HALF OF THE RULE, stated here as well as in the PowerShell suite: no source means NO lines.
  check('the no-source message carries an EMPTY lines array', Array.isArray(B.lines) && B.lines.length === 0,
        JSON.stringify(B.lines));
  check('...and names the stop by its module, with startLine 0',
        typeof B_MODULE === 'string' && B_MODULE.length > 0 && B.startLine === 0,
        B_MODULE + ' startLine=' + B.startLine);
  check('the two cases are different files, so scenario 2 can tell them apart', A_FILE !== B_MODULE,
        A_FILE + ' vs ' + B_MODULE);
}

console.log('\n1) a stop WITH source renders it, and records which file the page is showing');
{
  pausedAt(A_FILE, 'BROWSEPUBLISHERS', A_LINE);
  check('the pause alone names the location in the header', headerText().indexOf(A_FILE) >= 0, headerText());
  check('...and it does NOT invent a listing for it', slines().length === 0, slines().length + ' line(s)');
  hostSource('withSource');
  check('the snippet renders every line the host sent (' + A_LINES.length + ')',
        slines().length === A_LINES.length, slines().length + ' line(s)');
  check('the current line is the highlighted one',
        (slines().filter(d => d.classList.contains('cur')).map(d => d.dataset.line)).join() === String(A_LINE),
        slines().filter(d => d.classList.contains('cur')).map(d => d.dataset.line).join() || 'none');
  check('curFile is the file being shown', curFile === A_FILE, String(curFile));
  check('curLine is the line being highlighted', curLine === A_LINE, String(curLine));
}

console.log('\n2) THE RULE: a stop with no source file for it leaves none of the previous stop behind');
{
  // Exactly what the host posts for such a stop, captured from the shipped writer: the module as `file`,
  // so the header can still say where the stop is, and an empty `lines` array, which is what says there is
  // no listing for it.
  pausedAt(B_MODULE, 'MAIN', B_LINE);
  hostSource('noSource');

  check('the header names the NEW location', headerText().indexOf(B_MODULE) >= 0, headerText());
  check('...and no longer names the old one', headerText().indexOf(A_FILE) < 0, headerText());
  check('not one line of the previous stop is left in the listing', slines().length === 0,
        slines().length + ' line(s) survived');
  // The load-bearing one: run-to-cursor is sent as curFile + ':' + line.
  check('curFile is cleared, so run-to-cursor cannot arm a breakpoint in the old file', curFile === null,
        String(curFile));
  check('curLine is cleared too, so nothing claims a highlighted line', curLine === 0, String(curLine));
  // The user has to be told, or an empty pane reads as a broken pad.
  const paneText = $('src').innerHTML + ' ' + $('src').children.map(c => c.textContent).join(' ');
  check('the pane says why it is empty', /[Nn]o source/.test(paneText), paneText.trim() || '(nothing at all)');
  check('...and names the module it has no source for', paneText.indexOf(B_MODULE) >= 0, paneText.trim());
}

console.log('\n3) and a stop WITH source after one without still works (the clear is not sticky)');
{
  pausedAt(A_FILE, 'BROWSEPUBLISHERS', A_LINE);
  hostSource('withSource');
  check('the listing comes back', slines().length === A_LINES.length, slines().length + ' line(s)');
  check('and curFile with it', curFile === A_FILE, String(curFile));
}

console.log('\n4) the actions that depend on curFile are gated on it');
// These two are STRUCTURAL claims about the page text, not behaviour: the run-to-cursor menu handler is an
// assigned arrow function, not a named one, so it cannot be brace-matched out and driven. Said plainly
// rather than dressed up as a behavioural check. What IS behavioural is scenario 2 above: with curFile
// null, both of these early-return.
{
  check('the run-to-cursor menu item refuses to send without a curFile',
        /if\(!paused\|\|rtcLine==null\|\|isNaN\(rtcLine\)\|\|!curFile\)\s*return;/.test(html));
  check('...and it is curFile that names the file in the message it would send',
        /send\('runtocursor',\s*curFile\+':'\+rtcLine\)/.test(html));
  check('the source right-click also refuses without a curFile',
        /closest\('\.sline'\);\s*if\(!sl\|\|!curFile\)\s*return;/.test(html));
}

console.log('\n5) buildSource is the ONE writer of the listing and of curFile/curLine');
// 87c66af6's lesson, applied to the listing: the location had two writers and they disagreed. Any second
// place that assigns curFile would be able to disagree with buildSource the same way. clearSrc is the
// session-reset writer ('clear' tears the whole pad down) and is allowed - it only ever clears.
{
  const body = pad.extract(html, 'buildSource');
  const clear = pad.extract(html, 'clearSrc');
  // Everything OUTSIDE those two and the declaration must not assign curFile at all. Counting assignments
  // instead would just pin today's number; this says where they are allowed to be.
  const rest = html.replace(body, '').replace(clear, '').replace(/let\s+curFile\s*=\s*null\s*,\s*curLine\s*=\s*0\s*;/, '');
  const stray = (rest.match(/curFile\s*=[^=]/g) || []).length;
  check('nothing outside buildSource, clearSrc and the declaration assigns curFile', stray === 0,
        stray + ' stray assignment(s)');
  check('buildSource sets it when there IS a listing', /curFile\s*=\s*file/.test(body));
  check('...and clears it when there is not', /curFile\s*=\s*null/.test(body));
  check('clearSrc, the session-reset writer, only ever clears', /curFile\s*=\s*null/.test(clear)
        && !/curFile\s*=\s*(?!null)/.test(clear));
  check('clearSrc clears the highlighted line as well', /curLine\s*=\s*0/.test(clear));
  check('buildSource handles an empty lines array itself', /lines\.length|!lines/.test(body));
  // The 'paused' arm must NOT try to own the listing - it writes the header only.
  const onMsg = pad.extract(html, 'onMessage');
  const pausedArm = onMsg.slice(onMsg.indexOf("case 'paused':"), onMsg.indexOf("case 'resumed':"));
  check("the 'paused' arm writes the header and nothing about the listing",
        /setSrcLocation\(/.test(pausedArm) && !/curFile|buildSource|clearSrc/.test(pausedArm),
        pausedArm.replace(/\s+/g, ' ').slice(0, 90) + '...');

  // ---- the idle prompt: the markup ships one, clearSrc puts one back, and they must be the SAME one ----
  // A torn-down session has to look like one that never started. These are two different writers of
  // #srchdrText (ec45805f item 8: setSrcLocation owns the location wording, clearSrc owns the empty
  // state), so the shared text is the part that can silently drift - reword the markup and only a user
  // who has actually stopped and torn down a session ever sees the other one.
  const idleConst = /const\s+SRC_IDLE_TEXT\s*=\s*'([^']*)'/.exec(html);
  check('the idle prompt has one home (SRC_IDLE_TEXT)', !!idleConst,
        idleConst ? '' : 'no SRC_IDLE_TEXT constant found');
  check('clearSrc writes the constant, not a copy of the words',
        /srchdrText'\)\.textContent\s*=\s*SRC_IDLE_TEXT/.test(clear),
        clear.replace(/\s+/g, ' ').slice(0, 110));
  const markup = /<span id="srchdrText">([^<]*)<\/span>/.exec(html);
  check('the markup ships that exact text, so startup and teardown agree',
        !!markup && !!idleConst && markup[1] === idleConst[1],
        markup && idleConst ? JSON.stringify(markup[1]) + ' vs ' + JSON.stringify(idleConst[1])
                            : 'markup span or constant not found');
}

console.log('\n6) after a thread switch the header names the thread the source belongs to (0955b29f)');
// The host sends the SELECTED thread's source after a switch and adds no tid to the message, so the page
// says which thread it is, from the two tids it already holds. The label is the page's own threadName.
{
  const empty = () => { const c = $('src').children[0]; return c ? c.textContent : ''; };
  function at(sel, stop, rows) { selTid = sel; stopTid = stop; threadRows = rows || []; }

  at(100, 100); hostSource('withSource');
  check('the stopped thread selected: the header carries no thread label', !/\(Thread |\(tid /.test(headerText()), headerText());
  at(null, 100); hostSource('withSource');
  check('no selection (unscoped): no thread label either', !/\(Thread |\(tid /.test(headerText()), headerText());

  at(200, 100, [{ tid: 200, clarionThread: 2 }]); hostSource('withSource');
  check('another thread selected: the header ends with its name, in the threads list\'s words',
        /\(Thread 2\)<\/span>$/.test(headerText()), headerText());
  check('...after the location, which is still written', headerText().indexOf(A_FILE) >= 0 && headerText().indexOf(A_FILE) < headerText().indexOf('(Thread 2)'));
  at(200, 100, []); hostSource('withSource');
  check('a thread with no Clarion number is named by its tid, as the threads list does', /\(tid 200\)<\/span>$/.test(headerText()), headerText());

  at(200, 100, [{ tid: 200, clarionThread: 2 }]); hostSource('noSource');
  check("no source on another thread: \"No source for this thread's location\"",
        /^No source for this thread's location( \(.*\))?\.$/.test(empty()), empty());
  check('...and the header still names the thread', /\(Thread 2\)<\/span>$/.test(headerText()), headerText());
  at(100, 100); hostSource('noSource');
  check('no source on the stopped thread keeps "No source for this stop"',
        /^No source for this stop( \(.*\))?\.$/.test(empty()), empty());

  // 730ef328: the label is a DOM node, not markup concatenated onto innerHTML, and it has a style rule.
  at(200, 100, [{ tid: 200, clarionThread: 2 }]); hostSource('withSource');
  const lbl = $('srchdrText').querySelector('.srcthread');
  check('the label is an appended element whose textContent is the name', !!lbl && lbl.textContent === '(Thread 2)',
        lbl ? JSON.stringify(lbl.textContent) : 'no .srcthread child');
  check('...and nothing appends markup to the header', !/srchdrText'\)\.innerHTML\s*\+=/.test(html));
  check('.srcthread has a CSS rule', /\.srchdr \.srcthread \{[^}]*color:/.test(html));
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

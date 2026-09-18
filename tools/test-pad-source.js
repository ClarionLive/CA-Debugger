// Regression check: a pause with NO source file must not leave the PREVIOUS stop's code on screen.
//
// 87c66af6 moved the location caption into the source header and made the 'paused' handler always write it
// through setSrcHeader. But the host's SendSource returned silently when the .clw path could not be
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
//   node tools/test-pad-source.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const El = pad.El;

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
function renderLibState() { } function onLibState() { } function buildVarTree() { }
function collectSyms() { return []; } function onThreads() { } function onThreadSelected() { }
function onEngineError() { } function tidAccepted() { return true; } function buildStack() { }
function applyValue() { } function onVarSet() { } function buildBps() { } function buildProcs() { }
function buildModuleData() { } function logLine() { } function toast() { }
function send() { }

// page state the extracted functions close over
let curFile = null, curLine = 0;
let allSyms = [], bps = [];
let lastLibState = null, lastLibError = null;
const _flCbs = {}, _expandCbs = {};

// ---- the page's own code ---------------------------------------------------------------------------
const FNS = ['esc', 'reEsc', 'setSrcHeader', 'clearSrc', 'buildSource', 'renderBpDots', 'onMessage'];
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
function headerText() { return $('srchdrText').innerHTML || $('srchdrText').textContent; }

// ---- fixtures: what the host really posts -----------------------------------------------------------
// A stop the pad HAS source for. 25 lines centred on the current one is what SendSource sends (+/-12).
const A_FILE = 'clbrws011.clw', A_LINE = 42;
const A_LINES = [];
for (let i = 0; i < 25; i++) A_LINES.push('  line ' + (A_LINE - 12 + i) + ' of ' + A_FILE);

// A stop the pad has NO source for: the engine resolved the module and line, the host could not resolve a
// path, so the listing is empty and the module name is all there is to name the location by.
const B_MODULE = 'clbrws026.clw', B_LINE = 7;

function pausedAt(module, proc, line) {
  onMessage(JSON.stringify({ type: 'paused', module: module, proc: proc, line: line, regs: null }));
}
function sourceFor(file, proc, startLine, lines, current) {
  onMessage(JSON.stringify({ type: 'source', file: file, proc: proc, startLine: startLine,
                             lines: lines, current: current }));
}

console.log('1) a stop WITH source renders it, and records which file the page is showing');
{
  pausedAt(A_FILE, 'BROWSEPUBLISHERS', A_LINE);
  check('the pause alone names the location in the header', headerText().indexOf(A_FILE) >= 0, headerText());
  check('...and it does NOT invent a listing for it', slines().length === 0, slines().length + ' line(s)');
  sourceFor(A_FILE, 'BROWSEPUBLISHERS', A_LINE - 12, A_LINES, A_LINE);
  check('the snippet renders all 25 lines', slines().length === 25, slines().length + ' line(s)');
  check('the current line is the highlighted one',
        (slines().filter(d => d.classList.contains('cur')).map(d => d.dataset.line)).join() === String(A_LINE),
        slines().filter(d => d.classList.contains('cur')).map(d => d.dataset.line).join() || 'none');
  check('curFile is the file being shown', curFile === A_FILE, String(curFile));
  check('curLine is the line being highlighted', curLine === A_LINE, String(curLine));
}

console.log('\n2) THE RULE: a stop with no source file for it leaves none of the previous stop behind');
{
  // Exactly what the host now posts for such a stop: the module as `file`, so the header can still say
  // where the stop is, and an empty `lines` array, which is what says there is no listing for it.
  pausedAt(B_MODULE, 'MAIN', B_LINE);
  sourceFor(B_MODULE, 'MAIN', 0, [], B_LINE);

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
  sourceFor(A_FILE, 'BROWSEPUBLISHERS', A_LINE - 12, A_LINES, A_LINE);
  check('the listing comes back', slines().length === 25, slines().length + ' line(s)');
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
        /setSrcHeader\(/.test(pausedArm) && !/curFile|buildSource|clearSrc/.test(pausedArm),
        pausedArm.replace(/\s+/g, ' ').slice(0, 90) + '...');
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

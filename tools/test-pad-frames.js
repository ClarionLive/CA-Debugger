// Regression check: which Call Stack frame the pad treats as "the frame with locals" (70b58a1a).
//
// After an ordinary stop, frame 0 is a Clarion procedure and its locals are the ones to show. After a
// Pause, frame 0 is the OS call the event loop idles in: it carries the thread's EBP but has NO procedure,
// so asking the engine for its locals answers "(no locals)" and the Variables pane's "Local Variables"
// section stays empty while a real Clarion frame sits right under it. The pad must use the FIRST frame
// with both a procedure and a non-zero frame base, for:
//   - the twisty: a frame without a procedure (or with ebp 0x0) gets none;
//   - the auto-expanded row in the Call Stack (and so the framelocals request it sends);
//   - the Variables pane mirror (buildStack -> requestFrameLocals -> buildLocals), whose header names the
//     frame when it is not frame 0;
// and when no frame qualifies, nothing is requested and the Local Variables section is cleared.
//
// Runs the REAL functions out of debugger.html against the shared mini-DOM (tools/pad-dom.js). Point it at
// a copy of the page from before 70b58a1a (main ef3b7ff) and the Pause and empty-stack checks fail --
// that is the before/after proof.
//
//   node tools/test-pad-frames.js [path/to/debugger.html] [--allow-missing]
// Exit code 0 = all checks passed; the last line is "ALL N CHECKS PASSED" (run-all keys on it).
// --allow-missing stubs page functions this suite cannot find instead of refusing to run; it is only for
// a deliberate pre-fix comparison.
const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const ALLOW_MISSING = argv.includes('--allow-missing');
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const El = pad.El;

const TWISTY_CLOSED = '\u25b8', TWISTY_OPEN = '\u25be', DASH = '\u2014';

// ---- scope the page's functions run in -------------------------------------------------------------
// pad-dom does not parse innerHTML. renderStack writes a frame row's twisty as `<span class="ar">..</span>`
// markup and then reaches it with el.querySelector('.ar'), so this suite's elements materialise exactly
// that one span from the markup (and nothing else). The twisty the test reads is then the one the page
// rendered, and later textContent writes through querySelector('.ar') land on the same child.
class FrameEl extends El {
  set innerHTML(v) {
    super.innerHTML = v;
    const m = /<span class="ar">([^<]*)<\/span>/.exec(String(v));
    if (m) { const ar = new FrameEl('span'); ar.className = 'ar'; ar.textContent = m[1]; this.appendChild(ar); }
  }
  get innerHTML() { return super.innerHTML; }
}
const doc = pad.makeDocument();
doc.createElement = t => new FrameEl(t);
const document = doc;
const $ = id => doc.id(id);

const SENT = [];                       // every web message the page posted to the host
const wv = { postMessage: s => SENT.push(JSON.parse(s)) };
const flSent = () => SENT.filter(s => s.action === 'framelocals').map(s => s.data);

// page state the extracted functions close over
let lastFrames = null, stackQ = '', stackPendingTid = null;
let lastLocals = null, lastLocalsProc = '';
let _flSeq = 0; const _flCbs = {};

// ---- collaborators that are NOT under test ---------------------------------------------------------
const CALLS = [];
// renderLocals is the Variables pane repaint; recording what buildLocals left behind is how a check sees
// which proc/items the mirror delivered.
const LOCALS_RENDERS = [];
function renderLocals() { LOCALS_RENDERS.push({ proc: lastLocalsProc, items: lastLocals }); }
function renderVarRow() { CALLS.push('renderVarRow'); }
function sortVars(x) { return x; }
function threadRowFor() { return null; }
function threadName(t, tid) { return 'Thread ' + tid; }
function applyVarFilter() { }

// ---- the page's own code ---------------------------------------------------------------------------
const FNS = ['esc', 'send', 'requestFrameLocals', 'buildStack', 'renderStack', 'applyStackFilter', 'buildLocals'];
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
  console.log('   (note: --allow-missing -- stubbed ' + what + ')');
}
eval(src);

let failures = 0, checks = 0;
function check(label, cond, detail) {
  checks++;
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

function resetAll() {
  $('stackList').innerHTML = ''; $('stackCount').textContent = '';
  SENT.length = 0; CALLS.length = 0; LOCALS_RENDERS.length = 0;
  lastFrames = null; stackQ = ''; stackPendingTid = null;
  lastLocals = 'untouched'; lastLocalsProc = 'untouched';
  Object.keys(_flCbs).forEach(k => delete _flCbs[k]);
}
const frameRows = () => $('stackList').querySelectorAll('.frame');
const twisty = row => { const ar = row && row.querySelector('.ar'); return ar ? ar.textContent : '(no .ar)'; };
// The mirror request is the LAST framelocals buildStack sends: renderStack's auto-expand (if any) goes
// first, then buildStack asks for the same frame for the Variables pane.
const lastFlId = () => { const d = flSent(); return d.length ? +d[d.length - 1].split('|')[0] : null; };

console.log('0) the page still carries the pieces these checks stand on');
check('no page function was missing', missing.length === 0, missing.join(',') || 'all present');

console.log('\n1) Pause: frame 0 is an OS call (no proc, real ebp) -- the Clarion frame under it has the locals');
{
  resetAll();
  const frames = [
    { proc: null, ebp: '0x35FFDD0', va: '0x75AB11DC' },
    { proc: 'SPLASHSCREEN', ebp: '0x0', uncertain: true, va: '0x4754FE', module: 'clbrws026.clw', line: 43 },
    { proc: 'SPLASHSCREEN', ebp: '0x35FFEB8', va: '0x4756A3', module: 'clbrws026.clw', line: 88 },
  ];
  buildStack(frames);
  const reqs = flSent();
  check('1a every framelocals request carries frame 2 (0x4756A3|0x35FFEB8)',
        reqs.length > 0 && reqs.every(d => d.endsWith('|0x4756A3|0x35FFEB8')), reqs.join(' ; ') || 'none sent');
  check('1b no framelocals request carries frame 0 (0x75AB11DC / 0x35FFDD0)',
        !reqs.some(d => d.includes('0x75AB11DC') || d.includes('0x35FFDD0')), reqs.join(' ; ') || 'none sent');
  const rows = frameRows();
  check('1c three frame rows rendered', rows.length === 3, String(rows.length));
  check('1d frame 0 (no proc) has no twisty', twisty(rows[0]) === '', JSON.stringify(twisty(rows[0])));
  check('1e frame 1 (ebp 0x0) has no twisty', twisty(rows[1]) === '', JSON.stringify(twisty(rows[1])));
  check('1f frame 2 is the auto-expanded row (twisty open)', twisty(rows[2]) === TWISTY_OPEN,
        JSON.stringify(twisty(rows[2])));
  check('1g frame 2 is marked open and frame 0 is not', !!(rows[2] && rows[2]._open) && !(rows[0] && rows[0]._open));
  const id = lastFlId(), cb = id != null ? _flCbs[id] : null;
  check('1h (setup) the mirror request has a stored reply callback', typeof cb === 'function', 'id ' + id);
  if (typeof cb === 'function') cb([{ name: 'LOC:X', value: '1' }]);
  check('1i the mirror reply names the frame: lastLocalsProc is "SPLASHSCREEN ' + DASH + ' frame 2"',
        lastLocalsProc === 'SPLASHSCREEN ' + DASH + ' frame 2', JSON.stringify(lastLocalsProc));
  check('1j the mirror reply delivered its items to the Local Variables section',
        Array.isArray(lastLocals) && lastLocals.length === 1 && lastLocals[0].name === 'LOC:X');
}

console.log('\n2) ordinary stop: frame 0 is a Clarion procedure with a frame base');
{
  resetAll();
  buildStack([
    { proc: 'MAIN', ebp: '0x19FF20', va: '0x401234', module: 'app.clw', line: 12 },
    { proc: 'CALLER', ebp: '0x19FF80', va: '0x401500', module: 'app.clw', line: 40 },
  ]);
  const reqs = flSent();
  check('2a the mirror request is for frame 0 (0x401234|0x19FF20)',
        reqs.length > 0 && reqs[reqs.length - 1].endsWith('|0x401234|0x19FF20'), reqs.join(' ; ') || 'none sent');
  const rows = frameRows();
  check('2b frame 0 is the auto-expanded row', twisty(rows[0]) === TWISTY_OPEN, JSON.stringify(twisty(rows[0])));
  check('2c frame 1 has a closed twisty', twisty(rows[1]) === TWISTY_CLOSED, JSON.stringify(twisty(rows[1])));
  const id = lastFlId(), cb = id != null ? _flCbs[id] : null;
  if (typeof cb === 'function') cb([{ name: 'LOC:A', value: '2' }]);
  check('2d lastLocalsProc is "MAIN" with no frame suffix', lastLocalsProc === 'MAIN', JSON.stringify(lastLocalsProc));
}

console.log('\n3) no frame qualifies (no proc, or ebp 0x0)');
{
  resetAll();
  buildStack([
    { proc: null, ebp: '0x35FFDD0', va: '0x75AB11DC' },
    { proc: 'SPLASHSCREEN', ebp: '0x0', va: '0x4754FE', module: 'clbrws026.clw', line: 43 },
    { proc: null, ebp: '0x35FFF00', va: '0x77001000' },
  ]);
  check('3a no framelocals request is sent', flSent().length === 0, flSent().join(' ; '));
  check('3b buildLocals ran with [] items (section cleared)',
        LOCALS_RENDERS.length === 1 && Array.isArray(LOCALS_RENDERS[0].items) && LOCALS_RENDERS[0].items.length === 0,
        JSON.stringify(LOCALS_RENDERS));
  const rows = frameRows();
  check('3c no frame row has a twisty', rows.length === 3 && rows.every(r => twisty(r) === ''),
        rows.map(r => JSON.stringify(twisty(r))).join(','));
}

console.log('\n4) empty stack');
{
  resetAll();
  lastFrames = [];
  const r = renderStack();
  check('4a renderStack returns -1 for no frames', r === -1, String(r));
  resetAll();
  buildStack([]);
  check('4b buildStack([]) sends nothing', SENT.length === 0, JSON.stringify(SENT));
}

console.log('\n' + (failures ? failures + ' OF ' + checks + ' CHECK(S) FAILED' : 'ALL ' + checks + ' CHECKS PASSED'));
process.exit(failures ? 1 : 0);

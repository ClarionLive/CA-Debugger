// The pad side of "Set next statement" (task a77abd94): the source-view menu item, its gate, the one-time
// hazard warning, and the refusal toast.
//
// Runs the REAL page functions out of debugger.html (setIpAllowed, setIpFromMenu, onSetIp,
// viewingOtherThread) with the page's collaborators replaced by recorders. What it does NOT cover: that the
// engine's refusal sentence is right (ProtocolCheck.SetIp.cs), or that the host relays it (the add-in has no
// suite that runs OnSvcSetIpResult).
//
//   node tools/test-pad-setip.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);

let failures = 0;
function check(label, ok, detail) {
  console.log((ok ? '  PASS  ' : '  FAIL  ') + label + (ok || detail === undefined ? '' : '  ->  ' + detail));
  if (!ok) failures++;
}

// ---- the page's scope, with recorders for what the functions call ----
const doc = pad.makeDocument();
const $ = id => doc.id(id);
const SENT = [], LOG = [], TOASTS = [];
function send(action, data) { SENT.push(action + ' ' + data); }
function logLine(level, text) { LOG.push(level + ': ' + text); }
function toast(m) { TOASTS.push(m); }
let paused = false, selTid = null, stopTid = null, rtcLine = null, curFile = null, setIpWarned = false;

const FNS = ['viewingOtherThread', 'setIpAllowed', 'setIpFromMenu', 'onSetIp'];
const missing = [];
const src = FNS.map(n => { try { return pad.extract(html, n); } catch (e) { missing.push(n); return ''; } }).join('\n');
if (missing.length) {
  // A missing function is a hard failure, never a stub: a stub would make every check below vacuous.
  console.log('  FAIL  page function(s) not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
eval(src);

function reset() { SENT.length = 0; LOG.length = 0; TOASTS.length = 0; }

// ---- the markup and the dispatch: the item exists in the source-view menu, and the host's reply is routed
check('the source-view menu carries a "Set next statement" item',
      /<div class="ctxmenu" id="srcMenu">[^\n]*id="miSetIp"[^\n]*Set next statement/.test(html));
check('the menu item is wired to setIpFromMenu', /\$\('miSetIp'\)\.onclick\s*=\s*setIpFromMenu\s*;/.test(html));
check("onMessage routes the host's `setip` reply to onSetIp", /case 'setip':\s*onSetIp\(m\);/.test(html));

// ---- the gate: paused AND on the stopped thread
paused = false; selTid = 10; stopTid = 10;
check('not paused: the item is disabled', setIpAllowed() === false);
paused = true; selTid = 20; stopTid = 10;
check('paused, viewing another thread: the item is disabled', setIpAllowed() === false);
paused = true; selTid = 10; stopTid = 10;
check('paused on the stopped thread: the item is enabled', setIpAllowed() === true);

// ---- a click sends module:line, and says the hazard once
reset(); rtcLine = 44; curFile = 'clbrws026.clw'; setIpWarned = false;
setIpFromMenu();
check('a click sends setip module:line', SENT.length === 1 && SENT[0] === 'setip clbrws026.clw:44', JSON.stringify(SENT));
check('the first use in a session warns about skipped / repeated code', LOG.length === 1 && /OPEN/.test(LOG[0]), JSON.stringify(LOG));
reset(); rtcLine = 45;
setIpFromMenu();
check('a second use sends again', SENT.length === 1 && SENT[0] === 'setip clbrws026.clw:45', JSON.stringify(SENT));
check('...and does NOT warn again', LOG.length === 0, JSON.stringify(LOG));

// ---- a click that must send nothing
reset(); selTid = 20;
setIpFromMenu();
check('viewing another thread: a click sends nothing', SENT.length === 0, JSON.stringify(SENT));
reset(); selTid = 10; paused = false;
setIpFromMenu();
check('not paused: a click sends nothing', SENT.length === 0, JSON.stringify(SENT));
reset(); paused = true; curFile = null;
setIpFromMenu();
check('no source file on screen: a click sends nothing', SENT.length === 0, JSON.stringify(SENT));
reset(); curFile = 'clbrws026.clw'; rtcLine = NaN;
setIpFromMenu();
check('no line under the cursor: a click sends nothing', SENT.length === 0, JSON.stringify(SENT));

// ---- the reply
reset();
onSetIp({ ok: false, reason: 'accept-boundary', error: "Can't move across an ACCEPT loop boundary" });
check("a refusal toasts the engine's own sentence", TOASTS.length === 1 && TOASTS[0] === "Can't move across an ACCEPT loop boundary", JSON.stringify(TOASTS));
reset();
onSetIp({ ok: false, reason: 'prologue' });
check('a refusal with no sentence still names its code', TOASTS.length === 1 && /prologue/.test(TOASTS[0]), JSON.stringify(TOASTS));
reset();
onSetIp({ ok: true, module: 'clbrws026.clw', line: 44 });
check('a success toasts nothing (the paused that follows repaints the stop)', TOASTS.length === 0, JSON.stringify(TOASTS));

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

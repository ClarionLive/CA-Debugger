// The pad side of "Attach to a running process" (ticket 3f2d747f part C): the Attach… button's gate, the
// picker that lists processes and sends back a pid, the Stop tooltip while attached, and - the point of
// most of this file - that a process's NAME and PATH are rendered as TEXT and never as markup.
//
// The names and paths are the running processes' own strings. A process can be named anything its author
// likes, so the picker must create no element from them: every one goes through textContent / title, the
// same rule ticket e1dea0d9 audits across the page.
//
// Runs the REAL page functions out of debugger.html (openAttach, closeAttach, attachOpen, selectAttachRow,
// attachPick, renderProcs, setAttachMode, cmdTip, setRunState) against the mini-DOM in pad-dom.js, with the
// page's other collaborators replaced by recorders. What it does NOT cover: that the host lists only what
// the engine sent and attaches only to a pid it listed (tools/test-addin-attach.ps1 does), or real layout.
//
//   node tools/test-pad-attach.js [path/to/debugger.html]
// Exit code 0 = all checks passed.

const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);

let failures = 0, checks = 0;
function check(label, ok, detail) {
  checks++;
  console.log((ok ? '  PASS  ' : '  FAIL  ') + label + (ok || detail === undefined ? '' : '  ->  ' + detail));
  if (!ok) failures++;
}

// ---- the page's scope, with recorders for what the functions call ----
const doc = pad.makeDocument();
// Count every element the page creates, so "no element from a hostile string" is a number, not a hope.
let created = 0;
const realCreate = doc.createElement;
doc.createElement = t => { created++; return realCreate(t); };
const document = doc;   // the extracted functions call document.createElement / document.body
const $ = id => doc.id(id);
const SENT = [], TOASTS = [];
function send(action, data) { SENT.push(data === undefined ? action : action + ' ' + data); }
function toast(m) { TOASTS.push(m); }
function settingsOpen() { return false; }
function renderSettings() { }
// setRunState's other collaborators (the Watch list and the source view have their own suites)
function settleWaitingCells() { }
function clearSrc() { }
let paused = false, runState = 'idle';

// KB_CMDS is a multi-line const, so it is lifted by bracket matching rather than extractConst.
function extractArrayConst(src, name) {
  const i = src.indexOf('const ' + name + ' = [');
  if (i < 0) throw new Error('not found: const ' + name);
  let depth = 0;
  for (let j = src.indexOf('[', i); j < src.length; j++) {
    if (src[j] === '[') depth++;
    else if (src[j] === ']') { depth--; if (depth === 0) return src.slice(i, src.indexOf(';', j) + 1); }
  }
  throw new Error('unterminated: ' + name);
}

const FNS = ['cmdTip', 'attachOpen', 'openAttach', 'closeAttach', 'selectAttachRow', 'attachPick', 'renderProcs',
             'setAttachMode', 'setRunState'];
const missing = [];
let src = '';
try { src += extractArrayConst(html, 'KB_CMDS') + '\n'; } catch (e) { missing.push('KB_CMDS'); }
for (const c of ['STOP_TIP_ATTACHED']) { try { src += pad.extractConst(html, c) + '\n'; } catch (e) { missing.push(c); } }
for (const n of FNS) { try { src += pad.extract(html, n) + '\n'; } catch (e) { missing.push(n); } }
if (missing.length) {
  // A missing function is a hard failure, never a stub: a stub would make every check below vacuous.
  console.log('  FAIL  page function(s) not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
let attachMode = false, attachSel = null;
// `const` declarations stay inside eval's own scope in sloppy mode, so the two the checks need are handed out.
let KB = null, STOP_ATTACHED = null;
eval(src + ';KB = KB_CMDS; STOP_ATTACHED = STOP_TIP_ATTACHED;');

function reset() { SENT.length = 0; TOASTS.length = 0; }
function rows() { return $('attachList').querySelectorAll('.ap-row'); }
function subtree(el) { const out = []; el.walk(c => out.push(c)); return out; }

// ---- markup and dispatch: the pieces exist and are wired where the functions assume
check('the toolbar carries an Attach… button wired to openAttach',
      /<button class="tbtn" id="btnAttach"[^\n]*onclick="openAttach\(\)"[^\n]*Attach…<\/button>/.test(html));
check('the button is gated on body.idle (greyed and unclickable otherwise)',
      /#btnAttach \{ opacity:\.4; pointer-events:none; \}/.test(html) && /body\.idle #btnAttach \{ opacity:1; pointer-events:auto; \}/.test(html));
check('the picker markup has its list, status, Refresh and Attach controls',
      ['attachBackdrop', 'attachList', 'attachStatus', 'attachRefresh', 'attachGo', 'attachCancel'].every(id => html.includes('id="' + id + '"')));
check("onMessage routes the host's `procs` reply to renderProcs", /case 'procs':\s*renderProcs\(m\);/.test(html));
check("onMessage routes `attachmode` to setAttachMode, and only a literal true turns it on",
      /case 'attachmode':\s*setAttachMode\(m\.on===true\);/.test(html));
check('Refresh asks the host again', /\$\('attachRefresh'\)\.onclick=\(\)=>\{[^\n]*send\('procs'\)/.test(html));
check('the Attach button picks the selected row', /\$\('attachGo'\)\.onclick=\(\)=>attachPick\(attachSel\);/.test(html));
check('Esc closes the picker, and debug shortcuts stay inert while it is open',
      /if\(attachOpen\(\)\)\{ if\(e\.key==='Escape'\)\{ e\.preventDefault\(\); closeAttach\(\); \} return; \}/.test(html));
check("a key bound to Attach… opens the picker instead of sending a bare `attach` (the host needs a listed pid)",
      /if\(c\.id==='attach'\)\{ openAttach\(\); return; \}[^\n]*\n\s*send\(c\.id\);/.test(html));
check('KB_CMDS carries the attach entry', KB.some(c => c.id === 'attach'));

// ---- the gate: the picker opens only with no session
reset(); runState = 'running';
openAttach();
check('running: opening the picker sends nothing', SENT.length === 0, JSON.stringify(SENT));
check('...and says why', TOASTS.length === 1 && /Stop the current session/.test(TOASTS[0]), JSON.stringify(TOASTS));
check('...and the picker stays closed', !attachOpen());
reset(); runState = 'idle';
openAttach();
check('idle: opening the picker asks the host for `procs`', SENT.length === 1 && SENT[0] === 'procs', JSON.stringify(SENT));
check('...and shows it', attachOpen());
check('...with the Attach button disabled until a row is picked', $('attachGo').disabled === true);

// ---- hostile names and paths render as TEXT, and create nothing
const HOSTILE_NAME = '<img src=x onerror="send(\'attach\',\'4\')">evil.exe';
const HOSTILE_PATH = 'C:\\"><script>alert(1)</script>\\<b>x</b>.exe';
const AMP_NAME = 'a&amp;b &lt;i&gt;.exe';
const procsMsg = { type: 'procs', procs: [
  { pid: 4242, name: HOSTILE_NAME, path: HOSTILE_PATH },
  { pid: 77, name: AMP_NAME, path: 'C:\\Apps\\ab.exe' },
  { pid: '99', name: 'string-pid.exe', path: 'C:\\x' },      // a pid that is not a number is not shown
  { pid: -3, name: 'negative.exe', path: 'C:\\x' },
  { pid: 1.5, name: 'fraction.exe', path: 'C:\\x' },
  { pid: 0, name: 'zero.exe', path: 'C:\\x' },
  null,
], error: null };
created = 0;
renderProcs(procsMsg);
const rs = rows();
check('only the two rows with a positive integer pid are shown', rs.length === 2, rs.length + ' row(s)');
check('each row creates exactly four elements (row, name, pid, path) - nothing from the strings', created === 8, created + ' created');
const hostileRow = rs.find(r => r.dataset.pid === '4242');
const nameEl = hostileRow && hostileRow.querySelector('.ap-name');
const pathEl = hostileRow && hostileRow.querySelector('.ap-path');
check('the hostile name is the name cell\'s TEXT, byte for byte', nameEl && nameEl.textContent === HOSTILE_NAME, nameEl && nameEl.textContent);
check('the hostile path is the path cell\'s TEXT, byte for byte', pathEl && pathEl.textContent === HOSTILE_PATH, pathEl && pathEl.textContent);
check('the row\'s tooltip is the raw path, set as a property', hostileRow && hostileRow.title === HOSTILE_PATH, hostileRow && hostileRow.title);
const all = subtree($('attachList'));
check('no element in the list was given innerHTML', all.every(e => e.innerHTML === ''), all.filter(e => e.innerHTML !== '').map(e => e.innerHTML).join(' | '));
check('no text cell has children of its own', all.filter(e => /ap-(name|path|pid)/.test(e.className)).every(e => e.children.length === 0));
const ampRow = rs.find(r => r.dataset.pid === '77');
check('an entity-looking name is shown as typed, not decoded', ampRow && ampRow.querySelector('.ap-name').textContent === AMP_NAME);
check('the pid cell shows the pid', ampRow && ampRow.querySelector('.ap-pid').textContent === 'pid 77');
check('the status counts what is shown', /^2 running app/.test($('attachStatus').textContent), $('attachStatus').textContent);

// ---- selecting and attaching
reset();
selectAttachRow(4242);
check('a click selects that row, and only that row', hostileRow.classList.contains('sel') && !ampRow.classList.contains('sel'));
check('...and enables Attach', $('attachGo').disabled === false);
attachPick(attachSel);
check('Attach sends `attach` with the pid as a decimal string', SENT.length === 1 && SENT[0] === 'attach 4242', JSON.stringify(SENT));
check('...and closes the picker', !attachOpen());
reset(); runState = 'launching';
attachPick(77);
check('a pick after a session started sends nothing', SENT.length === 0, JSON.stringify(SENT));
reset(); runState = 'idle';
attachPick(null);
check('nothing selected: Attach sends nothing', SENT.length === 0, JSON.stringify(SENT));

// ---- a re-list replaces the rows and the selection; an error is shown as text
selectAttachRow(77);
created = 0;
renderProcs({ type: 'procs', procs: [], error: '<b>access denied</b>' });
check('a new list drops the old rows', rows().length === 0);
check('...and the selection', attachSel === null && $('attachGo').disabled === true);
check('an error is shown as text in the status line', $('attachStatus').textContent === 'Could not list processes: <b>access denied</b>', $('attachStatus').textContent);
check('...and creates no element', created === 0, created + ' created');
renderProcs({ type: 'procs', procs: [] });
check('an empty list says so', /No running app with Clarion debug info/.test($('attachStatus').textContent), $('attachStatus').textContent);
renderProcs({ type: 'procs' });
check('a reply with no procs array renders no rows and does not throw', rows().length === 0);

// ---- Stop says "detach" while attached, and going idle ends attach mode
const stop = KB.find(c => c.id === 'stop');
check('CONTROL: Stop\'s tip normally says it terminates the target', /Terminate/.test(cmdTip(stop)), cmdTip(stop));
setAttachMode(true);
check('attached: Stop\'s tip says it detaches and the app keeps running', cmdTip(stop) === 'Detach (the app keeps running)', cmdTip(stop));
check('...a constant the page defines once', STOP_ATTACHED === 'Detach (the app keeps running)');
check('...and only Stop\'s tip changes', cmdTip(KB.find(c => c.id === 'continue')) === KB.find(c => c.id === 'continue').tip);
check('...and the run-state indicator says so too', /Detach \(the app keeps running\)/.test($('runstate').title || ''), $('runstate').title);
check('the Settings rows take their tips through cmdTip', /l\.title=cmdTip\(c\)/.test(html));
$('runtext');   // setRunState writes the indicator text
setRunState('running');
check('a session still running keeps attach mode', attachMode === true);
check('...and body.idle is off, which greys Attach…', !doc.body.classList.contains('idle'));
setRunState('idle');
check('going idle ends attach mode', attachMode === false && cmdTip(stop) === stop.tip);
check('...and sets body.idle, which enables Attach…', doc.body.classList.contains('idle'));

console.log(failures ? `\n${failures} of ${checks} CHECKS FAILED` : `\nALL ${checks} CHECKS PASSED`);
process.exit(failures ? 1 : 0);

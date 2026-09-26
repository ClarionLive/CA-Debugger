// Breakpoint rows that name their image: the page half of the FROZEN contract C2 (1be3b82e #3, wave 7).
//
// The host adds "image" to every {"type":"bplist"} row: the engine's ownerPath for that row, or null when
// it is not known yet (pending, pre-launch). One source line compiled into two images gives two rows with
// the same module:line, and until now the pane showed them as identical twins. The contract:
//   - rows whose module+line is UNIQUE (module compared case-insensitively) render exactly as before;
//   - rows that SHARE a module+line each get a small label: the image's FILE NAME (basename of "image",
//     "(pending)" when null), set with textContent, with the title
//     "<full path> - hit counts are per image; remove/edit applies to every image".
//   - remove / edit / jump are unchanged.
//
// buildBps is driven for real against the mini-DOM (tools/pad-dom.js). Its base row is innerHTML, which the
// mini-DOM does not parse, but the label is appended with DOM APIs, so the label - the thing under test -
// is fully visible here. The pathState and duplicate-key parts of the row are covered by
// tools/test-pad-bpstate.js and are not re-tested.
//
//   node tools/test-pad-bpimage.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

// ---- scope the page's functions run in -------------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);
const SENT = [];
function send(c, a) { SENT.push(c + ' ' + a); }
function bpOwner() { return null; }              // no symbols loaded: the row carries no procedure crumb
function buildBpEditor() { const e = doc.createElement('div'); e.className = 'bpedit'; return e; }
function renderBpDots() { }
let curFile = null;
let bps = [];

const FNS = ['BP_PATH_STATES', 'esc', 'bpPathState', 'bpPathDeclines', 'bpActionKey', 'bpAmbiguousActionKeys',
             'bpLineKey', 'bpSharedLines', 'bpImageName', 'bpImageLabel', 'badge', 'hitLabel', 'buildBps'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { try { return pad.extractConst(html, n); } catch (e2) { missing.push(n); return ''; } }
}).join('\n');
if (missing.length) {
  console.log('  FAIL  not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
eval(src);

const TAIL = ' - hit counts are per image; remove/edit applies to every image';
function render(list) { buildBps(list); return $('bpList').children.map(w => w.children[0]); }
function label(row) { return row.querySelector('.bpimg'); }
function row(module, line, image, extra) {
  return Object.assign({ module: module, line: line, requested: line, pathState: 'unknown', path: null, image: image }, extra || {});
}

console.log('1) a unique row renders exactly as before: no label');
{
  const rows = render([row('clbrws011.clw', 50, 'H:\\App\\clbrws.exe'), row('clbrws011.clw', 51, 'H:\\App\\clbrws.exe')]);
  check('two rows rendered', rows.length === 2, String(rows.length));
  check('neither carries a label', rows.every(r => !label(r)));
  const one = render([row('clbrws011.clw', 50, null)]);
  check('a unique pending row carries no label either', one.length === 1 && !label(one[0]));
}

console.log('\n2) two rows on one module+line are labelled with their image file names');
{
  const a = 'H:\\App\\clbrws.exe', b = 'H:\\App\\Dll1\\clbrwsd.dll';
  const rows = render([row('clbrws011.clw', 50, a), row('clbrws011.clw', 50, b), row('other.clw', 9, a)]);
  check('both shared rows are labelled', !!label(rows[0]) && !!label(rows[1]));
  check('the first names its EXE', !!label(rows[0]) && label(rows[0]).textContent === 'clbrws.exe',
        label(rows[0]) && label(rows[0]).textContent);
  check('the second names its DLL', !!label(rows[1]) && label(rows[1]).textContent === 'clbrwsd.dll',
        label(rows[1]) && label(rows[1]).textContent);
  check('the tooltip is the full path plus the contract sentence',
        !!label(rows[1]) && label(rows[1]).title === b + TAIL, label(rows[1]) && label(rows[1]).title);
  check('the unrelated unique row stays unlabelled', !label(rows[2]));
}

console.log('\n3) module is compared case-insensitively; line is not ignored');
{
  const rows = render([row('CLBRWS011.CLW', 50, 'C:\\x\\a.exe'), row('clbrws011.clw', 50, 'C:\\x\\b.dll')]);
  check('two spellings of one module share a line', !!label(rows[0]) && !!label(rows[1]));
  const diff = render([row('clbrws011.clw', 50, 'C:\\x\\a.exe'), row('clbrws011.clw', 60, 'C:\\x\\b.dll')]);
  check('same module, different lines: no labels', !label(diff[0]) && !label(diff[1]));
}

console.log('\n4) basenames split on both separators; null is "(pending)"');
{
  const rows = render([row('m.clw', 5, 'C:/Apps/x/fwd.dll'), row('m.clw', 5, 'C:\\Apps\\x/mixed\\bk.exe'),
                       row('m.clw', 5, null), row('m.clw', 5, 'bare.dll')]);
  check('forward slashes', label(rows[0]).textContent === 'fwd.dll', label(rows[0]).textContent);
  check('mixed separators', label(rows[1]).textContent === 'bk.exe', label(rows[1]).textContent);
  check('null shows "(pending)"', label(rows[2]).textContent === '(pending)', label(rows[2]).textContent);
  check('...with "(pending)" in the tooltip too', label(rows[2]).title === '(pending)' + TAIL, label(rows[2]).title);
  check('a bare file name is its own basename', label(rows[3]).textContent === 'bare.dll', label(rows[3]).textContent);
  const miss = render([row('m.clw', 5, undefined), row('m.clw', 5, '')]);
  check('an absent or empty image is pending too', label(miss[0]).textContent === '(pending)' && label(miss[1]).textContent === '(pending)');
}

console.log('\n5) hostile image strings render as text');
{
  const evil = 'C:\\x\\"><img src=x onerror=alert(1)>.dll', evil2 = "C:/y/<b onclick='q'>\"x\".dll";
  const rows = render([row('m.clw', 5, evil), row('m.clw', 5, evil2)]);
  check('the label is the basename verbatim', label(rows[0]).textContent === '"><img src=x onerror=alert(1)>.dll',
        label(rows[0]).textContent);
  check('the tooltip is the full string verbatim', label(rows[0]).title === evil + TAIL);
  check('the second label is text too', label(rows[1]).textContent === "<b onclick='q'>\"x\".dll", label(rows[1]).textContent);
  check('nothing was written as markup', rows.every(r => label(r).innerHTML === '' && label(r).children.length === 0));
}

console.log('\n6) the actions are unchanged');
{
  // The existing duplicate-key rule (bpAmbiguousActionKeys) still decides the controls; the label adds none.
  const rows = render([row('m.clw', 5, 'a.exe'), row('m.clw', 5, 'b.dll')]);
  check('a labelled row installs no onclick of its own', rows.every(r => !label(r).onclick));
  const rm = rows[0].querySelector('.rm');
  check('the shared rows keep the existing disabled remove', !!rm && rm.classList.contains('disabled'));
  const uniq = render([row('m.clw', 5, 'a.exe')]);
  const urm = uniq[0].querySelector('.rm');
  SENT.length = 0; if (urm && urm.onclick) urm.onclick({ stopPropagation() { } });
  check('a unique row still removes by module:line', SENT[0] === 'bpremove m.clw:5', SENT[0]);
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

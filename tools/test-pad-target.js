// The target bar's page half of the FROZEN contract C4 (0214f33a #1, wave 7).
//
// The host sends {"type":"target","path":"...","exists":bool,"state":"auto"|"manual"|"unconfirmed"|"none",
// "note":"..."}. `unconfirmed` is a path the host kept to retry but could NOT confirm for the current
// solution, so the page must not present it as the answer: dimmed, a warning mark, the note. `none` keeps
// today's "No target resolved" text plus the note. A message with NO state is an older host and renders
// exactly as before. A state this page does not know is read as unconfirmed, never as authoritative.
//
// setTarget is pulled out of debugger.html and driven against the mini-DOM (tools/pad-dom.js) with the
// contract's literal message shapes. Everything it renders is built with textContent and spans, so the
// mini-DOM sees the real result; nothing here depends on innerHTML being parsed.
//
//   node tools/test-pad-target.js [path/to/debugger.html]
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
const RESTORED = [];
function restoreWatchesFor(p) { RESTORED.push(p); }

const missing = [];
let src = '';
const tsm = /var TARGET_STATES\s*=\s*[^;\n]+;/.exec(html);
if (tsm) src += tsm[0] + '\n'; else missing.push('TARGET_STATES');
['targetState', 'setTarget'].forEach(n => {
  try { src += pad.extract(html, n) + '\n'; } catch (e) { missing.push(n); }
});
if (missing.length) {
  // A stub renders nothing, so every "renders as today" check below would compare nothing to nothing.
  console.log('  FAIL  not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
var targetPath = null;
eval(src);

const el = $('exePath');
const NONE = 'No target resolved — open a project, or build the app.';
function show(m) { RESTORED.length = 0; setTarget(m); return el; }
function kids() { return el.children.map(c => c.className + '=' + c.textContent).join(' | '); }
function part(cls) { return el.children.find(c => c.classList.contains(cls)) || null; }
const PATH = 'H:\\Apps\\Browse\\clbrws.exe';

console.log('1) an older host (no "state") renders exactly as before');
{
  show({ type: 'target', path: PATH, exists: true });
  check('found: plain path, clickable', el.className === 'path' && el.textContent === PATH && el.children.length === 0,
        el.className + ' / ' + el.textContent);
  check('found: the reveal title', el.title === 'Click to show in File Explorer', el.title);
  check('found: the watch list is restored for it', RESTORED.length === 1 && RESTORED[0] === PATH);
  show({ type: 'target', path: PATH, exists: false });
  check('not on disk: the missing look', el.className === 'path missing' && el.textContent === PATH);
  show({ type: 'target', path: '', exists: false });
  check('no path: the "No target resolved" text', el.className === 'path none' && el.textContent === NONE && el.title === '',
        el.textContent);
  check('...and targetPath is cleared', targetPath === null);
}

console.log('\n2) auto and manual render as the older host does');
['auto', 'manual'].forEach(st => {
  show({ type: 'target', path: PATH, exists: true, state: st, note: 'ignored for ' + st });
  check(st + ': plain path, no mark, no note', el.className === 'path' && el.textContent === PATH && el.children.length === 0,
        el.className + ' / ' + el.textContent + ' / ' + kids());
  check(st + ': the reveal title', el.title === 'Click to show in File Explorer', el.title);
  check(st + ': targetPath is the path', targetPath === PATH);
});

console.log('\n3) unconfirmed reads as NOT confirmed: dimmed, a warning mark, the note');
{
  const note = 'Kept from the last solution - could not confirm it belongs to this one';
  show({ type: 'target', path: PATH, exists: true, state: 'unconfirmed', note: note });
  check('the unconfirmed class, not the plain path class', el.classList.contains('unconfirmed') && el.className !== 'path',
        el.className);
  check('a warning mark comes first', el.children.length > 0 && el.children[0].classList.contains('tmark')
        && el.children[0].textContent === '⚠', kids());
  check('the path is shown', !!part('tpath') && part('tpath').textContent === PATH, kids());
  check('the note is shown', !!part('tnote') && part('tnote').textContent === note, kids());
  check('the title says it is NOT confirmed', /NOT confirmed/.test(el.title || ''), el.title);
  check('the title carries the note', (el.title || '').indexOf(note) >= 0, el.title);
  check('the path is still the click target (Start is unchanged)', targetPath === PATH);
  show({ type: 'target', path: PATH, exists: true, state: 'unconfirmed' });
  check('no note: no empty note span', !part('tnote') && !!part('tmark') && !!part('tpath'), kids());
  show({ type: 'target', path: PATH, exists: false, state: 'unconfirmed' });
  check('not on disk: the title says so', /Not on disk/.test(el.title || ''), el.title);
}

console.log('\n4) a state this page does not know is NOT authoritative');
['Auto', 'confirmed', 3].forEach(st => {
  show({ type: 'target', path: PATH, exists: true, state: st });
  check(JSON.stringify(st) + ' renders as unconfirmed', el.classList.contains('unconfirmed') && !!part('tmark'),
        el.className + ' / ' + kids());
});

console.log('\n5) none: today\'s text, plus the note when present');
{
  show({ type: 'target', path: '', exists: false, state: 'none' });
  check('no note: exactly the old text', el.className === 'path none' && el.textContent === NONE, el.textContent);
  const note = 'Several EXEs in this solution - pick one';
  show({ type: 'target', path: '', exists: false, state: 'none', note: note });
  check('with a note: the old text, then the note', el.className === 'path none' && el.textContent === NONE + ' ' + note,
        el.textContent);
  // none is none even if a path rides along: a path the host just told us is not the target must not
  // become the click target or the Watch-list key.
  show({ type: 'target', path: PATH, exists: true, state: 'none' });
  check('none with a stray path still renders none', el.className === 'path none' && el.textContent === NONE,
        el.className + ' / ' + el.textContent);
  check('...and does not become targetPath', targetPath === null, String(targetPath));
  check('...and restores no Watch list', RESTORED.length === 0);
  // After an unconfirmed render left spans behind, a none must clear them.
  show({ type: 'target', path: PATH, exists: true, state: 'unconfirmed', note: 'n' });
  show({ type: 'target', path: '', exists: false, state: 'none' });
  check('none after unconfirmed leaves no spans behind', el.children.length === 0 && el.textContent === NONE, kids());
}

console.log('\n6) hostile strings render as text');
{
  const evilPath = 'C:\\"><img src=x onerror=alert(1)>\\a.exe';
  const evilNote = '<b>"bold"</b> & \'quoted\'';
  show({ type: 'target', path: evilPath, exists: true, state: 'unconfirmed', note: evilNote });
  check('the path span holds the string verbatim', !!part('tpath') && part('tpath').textContent === evilPath);
  check('the note span holds the string verbatim', !!part('tnote') && part('tnote').textContent === evilNote);
  check('nothing was written as markup', el.innerHTML === '' && el.children.every(c => c.innerHTML === ''),
        JSON.stringify(el.innerHTML));
  show({ type: 'target', path: '', exists: false, state: 'none', note: evilNote });
  check('none: the note is text', el.textContent === NONE + ' ' + evilNote && el.innerHTML === '');
}

console.log('\n7) the unconfirmed look uses the theme tokens');
{
  const css = r => { const m = new RegExp(r.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\{([^}]*)\\}').exec(html); return m ? m[1] : null; };
  const pathRule = css('.exebar .path.unconfirmed');
  check('.path.unconfirmed is dimmed with --fg-dim', !!pathRule && /color\s*:\s*var\(--fg-dim\)/.test(pathRule), pathRule);
  const mark = css('.exebar .tmark'), note = css('.exebar .tnote');
  check('the mark is painted with --warn', !!mark && /color\s*:\s*var\(--warn\)/.test(mark), mark);
  check('the note is painted with --warn', !!note && /color\s*:\s*var\(--warn\)/.test(note), note);
  // --warn is the token the caution states use and is themed in both blocks (tools/test-pad-contrast.js
  // measures it); the target bar sits on --titlebar, so measure it there.
  function lum(hex) {
    const v = [0, 1, 2].map(i => parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255)
      .map(c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
  }
  function ratio(a, b) { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); }
  function tok(sel, name) {
    const i = html.indexOf(sel); const blk = i < 0 ? '' : html.slice(i, html.indexOf('}', i));
    const m = new RegExp('--' + name + '\\s*:\\s*(#[0-9a-fA-F]{6})').exec(blk); return m ? m[1] : null;
  }
  [[':root {', 'dark'], ['body.light {', 'light']].forEach(([sel, name]) => {
    const w = tok(sel, 'warn'), t = tok(sel, 'titlebar');
    const r = w && t ? ratio(w, t) : 0;
    check(name + ': --warn on --titlebar clears AA 4.5:1', r >= 4.5, r.toFixed(2) + ':1');
  });
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

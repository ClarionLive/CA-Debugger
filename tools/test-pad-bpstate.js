// What the page does with a breakpoint row's pathState — the page half of the FROZEN contract, 49538b78
// item 5. The host half is Quinn-2's (SendBps / GutterPathFor); tools/test-addin-bpident.ps1 covers that.
//
// THE DEFECT. The host can already tell three states apart: GutterPathsByModuleLine builds
// (module|line) -> path, and ClaimGutterPath POISONS a key that more than one DIFFERENT file claims. So a
// row is resolved, contested, or unmapped. It used to emit `path: null` for BOTH of the last two, and the
// page rendered either as an ordinary blue link that fell back to send('jump', module:line) — the basename
// lookup the host had withheld the path precisely to avoid. On a contested row that opens ONE of several
// real, equally plausible files, with nothing saying it guessed. A plausible wrong answer becomes the
// developer's belief about their own program, which is this project's recurring defect class.
//
// THE CONTRACT. Every bplist row carries `pathState`: "ok" | "ambiguous" | "unknown", always present, with
// the invariant (pathState === "ok") === (path != null).
//   ok        -> unchanged: filename is a link, click opens `path`.
//   unknown   -> unchanged: send('jump', module:line). With no gutter information at all a best effort IS
//                the honest answer, and this is deliberately today's behaviour.
//   ambiguous -> MUST NOT be a normal link and MUST NOT fall back to the basename jump.
//
// WHAT THIS FILE CAN AND CANNOT DRIVE, said plainly. buildBps builds its row with innerHTML, and the pad's
// mini-DOM stores innerHTML without parsing it (tools/pad-dom.js), so `d.querySelector('.bplink')` finds
// nothing and the row cannot be driven end to end here. So the split is:
//   - bpPathState is the DECISION, it is a pure function, and it is driven for real below.
//   - the RENDER is pinned structurally, by where the calls sit relative to the branch that owns them,
//     never by matching their text. A text check accepts `if (false) send(...)`.
//
//   node tools/test-pad-bpstate.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

// ---- the decision, driven for real ------------------------------------------------------------------
const FNS = ['BP_PATH_STATES', 'bpPathState'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) {
    try { return pad.extractConst(html, n); }
    catch (e2) { missing.push(n); return /^[A-Z0-9_]+$/.test(n) ? ('var ' + n + ' = undefined;') : ('function ' + n + '(){}'); }
  }
}).join('\n');
if (missing.length) {
  // A stub answers undefined for every call, so every case below would "pass" while nothing was tested.
  console.log('  FAIL  not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
// A `const` declared inside a sloppy-mode eval stays in the eval's own scope — only var and function leak
// — so the page's list is handed back out deliberately. Read from the page, never restated here: a test
// that hard-codes the three tokens keeps passing after someone changes the page to two.
var STATES = null;
eval(src + ';STATES = BP_PATH_STATES;');

console.log('1) the three contract states resolve to themselves');
{
  check('a resolved row is ok', bpPathState({ pathState: 'ok', path: 'H:\\App\\Dll1\\clbrws011.clw' }) === 'ok');
  check('a contested row is ambiguous', bpPathState({ pathState: 'ambiguous', path: null }) === 'ambiguous');
  check('an unmapped row is unknown', bpPathState({ pathState: 'unknown', path: null }) === 'unknown');
}

console.log('\n2) an older host, which sends no pathState at all, degrades to the BEST EFFORT');
// The deliberate direction. An absent field must not become "ambiguous" and lose the fallback that has
// always worked; it must become "unknown", which keeps it.
{
  check('absent reads as unknown', bpPathState({ path: null }) === 'unknown');
  check('explicitly undefined reads as unknown', bpPathState({ pathState: undefined, path: null }) === 'unknown');
  check('explicitly null reads as unknown', bpPathState({ pathState: null, path: null }) === 'unknown');
}

console.log('\n3) the invariant is ASSERTED by the page, not trusted');
// (pathState === "ok") === (path != null) is the host's guarantee. A row breaking it is a broken payload:
// there is nothing to open, and nothing says the basename fallback is safe either, so it declines.
{
  check('"ok" with a null path is not ok', bpPathState({ pathState: 'ok', path: null }) === 'ambiguous');
  check('"ok" with an empty path is not ok', bpPathState({ pathState: 'ok', path: '' }) === 'ambiguous');
  check('...and a real path with "ok" still is', bpPathState({ pathState: 'ok', path: 'x.clw' }) === 'ok');
}

console.log('\n4) a token this page does not know DECLINES rather than guessing');
// Case matters: these are JSON tokens. Quinn-2 found the host-side harness passing against "OK" because
// PowerShell's -eq is case-insensitive; the page compares with === and must not quietly accept the variant.
{
  check('"OK" is not "ok"', bpPathState({ pathState: 'OK', path: 'x.clw' }) === 'ambiguous');
  check('"Ambiguous" is not "ambiguous"', bpPathState({ pathState: 'Ambiguous', path: null }) === 'ambiguous');
  check('"Unknown" is not "unknown" — and does NOT get the fallback',
        bpPathState({ pathState: 'Unknown', path: null }) === 'ambiguous');
  check('an unheard-of token declines', bpPathState({ pathState: 'contested', path: null }) === 'ambiguous');
  check('a non-string declines', bpPathState({ pathState: 3, path: null }) === 'ambiguous');
  check('a missing row declines', bpPathState(null) === 'ambiguous');
  check('the contract names exactly three states', Array.isArray(STATES) && STATES.length === 3
        && STATES.join(',') === 'ok,ambiguous,unknown', String(STATES));
}

// Strip comments before applying any rule about CODE. Written because the first version of section 5
// failed against a correct page: the arm's own comment says `send('jump', module:line)` while explaining
// why it must not call it, and a text scan cannot tell the explanation from the call. That is the same
// comment-vs-code fragility tools/test-engine-session.ps1 section 5 was fixed for; the difference is only
// that PowerShell ships a parser and node does not.
// String literals are respected so a `//` inside one is not mistaken for a comment. Regex literals are
// not, because none appear in the code under test — if one ever does, this needs a real tokenizer.
function codeOnly(js) {
  let out = '', i = 0; const n = js.length;
  while (i < n) {
    const c = js[i];
    if (c === '/' && js[i + 1] === '/') { while (i < n && js[i] !== '\n') i++; continue; }
    if (c === '/' && js[i + 1] === '*') { i += 2; while (i + 1 < n && !(js[i] === '*' && js[i + 1] === '/')) i++; i += 2; continue; }
    if (c === '"' || c === "'" || c === '`') {
      const q = c; out += c; i++;
      while (i < n) {
        if (js[i] === '\\') { out += js.slice(i, i + 2); i += 2; continue; }
        out += js[i];
        if (js[i] === q) { i++; break; }
        i++;
      }
      continue;
    }
    out += c; i++;
  }
  return out;
}

console.log('\n5) the render: the ambiguous arm offers no action, pinned by POSITION');
// Structure, not text. The claim is about which statements live inside which branch, so a disabled or
// relocated call fails even though its text is still present somewhere in the function.
{
  const body = codeOnly(pad.extract(html, 'buildBps'));
  const i = body.indexOf("pstate==='ambiguous'");
  check('buildBps branches on the ambiguous state', i > 0, i > 0 ? '' : 'no ambiguous branch found');

  // The arm runs from its own `if` to the `else if` that ends it.
  const armEnd = body.indexOf('else if', i);
  const arm = i > 0 && armEnd > i ? body.slice(i, armEnd) : '';
  check('the arm was located', arm.length > 0, arm.replace(/\s+/g, ' ').slice(0, 80));
  // THE RULE, twice over: no click handler at all, and specifically neither action.
  check('the ambiguous arm installs NO onclick', !/\.onclick\s*=/.test(arm));
  check("the ambiguous arm never sends 'jump'", !/send\(\s*'jump'/.test(arm));
  check("the ambiguous arm never sends 'openbp'", !/send\(\s*'openbp'/.test(arm));
  check('it marks the link so it cannot look clickable', /classList\.add\('ambig'\)/.test(arm));
  // The explanation is the affordance that replaces the link, so its absence is a silent decline.
  check('it explains itself in a title', /\.title\s*=/.test(arm));
  // ...assigned as a DOM property and never interpolated into innerHTML: b.module comes from the
  // debuggee's TSWD info and esc() does not escape quotes.
  check('the title is assigned as a property, not written into innerHTML',
        /lk\.title\s*=/.test(arm) && !/innerHTML/.test(arm));

  // ISOLATION: the other two arms must still act, or "no action on ambiguous" would be satisfied just as
  // well by a function that does nothing at all.
  const rest = i > 0 ? body.slice(armEnd) : '';
  check('the ok arm still opens the resolved path', /send\(\s*'openbp'/.test(rest));
  check('the unknown arm still falls back to jump', /send\(\s*'jump'/.test(rest));

  // CONTROL for the stripper itself: it must remove the arm's explanatory comment (which NAMES both
  // actions) while leaving the code that does them. Without this, every rule above could be passing
  // because codeOnly had emptied the arm.
  const rawArm = pad.extract(html, 'buildBps').slice(
    pad.extract(html, 'buildBps').indexOf("pstate==='ambiguous'"));
  check('CONTROL: the raw arm DOES name jump in prose, so the stripper is doing the work',
        /send\(\s*'jump'/.test(rawArm.slice(0, rawArm.indexOf('else if'))));
  check('CONTROL: ...and the stripper left the arm non-empty', arm.trim().length > 40, arm.trim().length + ' chars');
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

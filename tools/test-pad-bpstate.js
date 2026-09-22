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
  check('"ok" with a null path declines', bpPathState({ pathState: 'ok', path: null }) === 'declined');
  check('"ok" with an empty path declines', bpPathState({ pathState: 'ok', path: '' }) === 'declined');
  check('...and a real path with "ok" still is', bpPathState({ pathState: 'ok', path: 'x.clw' }) === 'ok');
}

console.log('\n4) a token this page does not know DECLINES rather than guessing');
// Case matters: these are JSON tokens. Quinn-2 found the host-side harness passing against "OK" because
// PowerShell's -eq is case-insensitive; the page compares with === and must not quietly accept the variant.
{
  check('"OK" is not "ok"', bpPathState({ pathState: 'OK', path: 'x.clw' }) === 'declined');
  check('"Ambiguous" is not "ambiguous"', bpPathState({ pathState: 'Ambiguous', path: null }) === 'declined');
  check('"Unknown" is not "unknown" — and does NOT get the fallback',
        bpPathState({ pathState: 'Unknown', path: null }) === 'declined');
  check('an unheard-of token declines', bpPathState({ pathState: 'contested', path: null }) === 'declined');
  check('a non-string declines', bpPathState({ pathState: 3, path: null }) === 'declined');
  check('a missing row declines', bpPathState(null) === 'declined');
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
  // Located by the BRANCH CONDITION, which is the declining predicate - not by the contested wording,
  // which also appears in the title's ternary INSIDE the arm. (It was `pstate==='ambiguous'` until the
  // fourth state landed; that then matched the ternary first and silently truncated the slice, so four
  // checks failed against a correct page. Anchor on the thing that opens the block.)
  const i = body.indexOf('bpPathDeclines(pstate)');
  check('buildBps branches on the declining predicate', i > 0, i > 0 ? '' : 'no declining branch found');

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
    pad.extract(html, 'buildBps').indexOf('bpPathDeclines(pstate)'));
  check('CONTROL: the raw arm DOES name jump in prose, so the stripper is doing the work',
        /send\(\s*'jump'/.test(rawArm.slice(0, rawArm.indexOf('else if'))));
  check('CONTROL: ...and the stripper left the arm non-empty', arm.trim().length > 40, arm.trim().length + ' chars');
}

// ---- 6) remove and properties decline when two breakpoints share a module:line ---------------------
// A DIFFERENT ambiguity from pathState, and the distinction is the fix. `pathState == "ambiguous"` means
// two FILES claim this module|line in the gutter; THIS means two ENGINE BREAKPOINTS share it. They only
// partly overlap: if just one of the two files is bookmarked the gutter key is not poisoned, pathState is
// "ok", and remove is STILL ambiguous at the engine. Keying the guard on pathState would leave the hole
// half open while looking closed, which is why the predicate is page-local instead.
//
// The hazard: `bpremove` sends module:line and the engine's RemoveBreakpoint takes the FIRST match, so
// clicking x on one row could delete the OTHER image's breakpoint. Interim guard - the real fix is an
// owner-stable identifier carried end to end, filed separately.
const dupFns = ['bpActionKey', 'bpAmbiguousActionKeys'];
const dupMissing = [];
const dupSrc = dupFns.map(n => { try { return pad.extract(html, n); } catch (e) { dupMissing.push(n); return 'function ' + n + '(){}'; } }).join('\n');
if (dupMissing.length) {
  console.log('  FAIL  not found in ' + pad.resolvePage(pagePath) + ': ' + dupMissing.join(', '));
  process.exit(1);
}
eval(dupSrc);

console.log('\n5b) all four declining inputs decline — but only ONE may claim the contested reason');
// bpPathState collapses four situations into a declined action, and that is right. The MESSAGE is not
// interchangeable: "more than one file claims module:line" is a fact about the user's PROGRAM, true only
// when the host SAID the key is contested. For the other three the honest statement is "the host did not
// say which file this is". Asserting the action alone would pass a fix that gave all four the contested
// wording — a fabricated fact arriving through the UI instead of the wire — so the title is the check
// that matters here.
{
  const declineFns = ['bpPathDeclines'];
  const dm = [];
  const ds = declineFns.map(n => { try { return pad.extract(html, n); } catch (e) { dm.push(n); return 'function ' + n + '(){}'; } }).join('\n');
  if (dm.length) { console.log('  FAIL  not found: ' + dm.join(', ')); process.exit(1); }
  eval(ds);

  const cases = [
    { name: 'genuinely contested',        row: { pathState: 'ambiguous', path: null }, state: 'ambiguous', claimsContested: true },
    { name: 'invariant broken (ok/null)', row: { pathState: 'ok', path: null },        state: 'declined',  claimsContested: false },
    { name: 'unrecognised token',         row: { pathState: 'contested', path: null }, state: 'declined',  claimsContested: false },
    { name: 'no row at all',              row: null,                                   state: 'declined',  claimsContested: false },
  ];
  for (const c of cases) {
    const st = bpPathState(c.row);
    check('' + c.name + ' -> ' + c.state, st === c.state, st);
    check('   ...and the action is DECLINED', bpPathDeclines(st) === true, String(bpPathDeclines(st)));
  }
  // ISOLATION: bpPathDeclines must not simply answer true for everything, or every assertion above is free.
  check('   CONTROL: an ok row does NOT decline', bpPathDeclines(bpPathState({ pathState: 'ok', path: 'x.clw' })) === false);
  check('   CONTROL: an unknown row does NOT decline (it keeps the best-effort fallback)',
        bpPathDeclines(bpPathState({ pathState: 'unknown', path: null })) === false);

  // THE WORDING, pinned where the render chooses it: the contested sentence must be reachable ONLY on
  // pstate === 'ambiguous'.
  const arm = codeOnly(pad.extract(html, 'buildBps'));
  const i = arm.indexOf('more than one file claims');
  check('the contested sentence exists in the render', i > 0);
  const before = arm.slice(Math.max(0, i - 220), i);
  check('...and is guarded on pstate === ambiguous, not on the declining predicate',
        /pstate\s*===\s*'ambiguous'\s*\?/.test(before), before.replace(/\s+/g, ' ').slice(-80));
  check('the generic sentence is the other branch', /did not say which file this is/.test(arm));
}

console.log('\n6) the duplicate-action predicate: the key is the PAIR, not the module');
{
  const D1 = { module: 'clbrws011.clw', line: 50, requested: 50 };
  const D2 = { module: 'clbrws011.clw', line: 50, requested: 50 };   // same file name in a second DLL
  const U  = { module: 'clbrws026.clw', line: 42, requested: 42 };

  // THE RULE: two rows sharing module AND line are both ambiguous for remove/properties.
  const dup = bpAmbiguousActionKeys([D1, D2, U]);
  check('two rows sharing module:line are flagged', !!dup[bpActionKey(D1)] && !!dup[bpActionKey(D2)],
        JSON.stringify(Object.keys(dup)));
  // THE CONTROL: a guard that flagged everything would pass the line above on its own.
  check('a row with a UNIQUE module:line is NOT flagged', !dup[bpActionKey(U)], bpActionKey(U));

  // THE NEAR-MISS: same module, DIFFERENT lines. Grouping on the module alone would disable actions on
  // every breakpoint in a file that has more than one - which is most files.
  const S1 = { module: 'clbrws011.clw', line: 50, requested: 50 };
  const S2 = { module: 'clbrws011.clw', line: 60, requested: 60 };
  const sameFile = bpAmbiguousActionKeys([S1, S2]);
  check('same module, DIFFERENT lines: neither is flagged', Object.keys(sameFile).length === 0,
        JSON.stringify(Object.keys(sameFile)));

  // The key follows the same (requested||line) fallback the two senders use, or the guard would be
  // computed over a different identity than the one that gets sent.
  const R = { module: 'x.clw', line: 99, requested: 12 };
  check('the key uses requested when present, like bpremove and bpprops do',
        bpActionKey(R) === 'x.clw:12', bpActionKey(R));
  const P = { module: 'x.clw', line: 99 };
  check('...and falls back to the planted line when it is absent', bpActionKey(P) === 'x.clw:99', bpActionKey(P));
  // Three rows on one key is still one group, not two.
  const T = bpAmbiguousActionKeys([D1, D2, { module: 'clbrws011.clw', line: 50, requested: 50 }]);
  check('three rows on one key is one flagged group', Object.keys(T).length === 1, JSON.stringify(Object.keys(T)));
}

console.log('\n7) the render: a flagged row offers neither action, pinned by POSITION');
{
  const body = codeOnly(pad.extract(html, 'buildBps'));
  const i = body.indexOf('dupeKeys[bpActionKey(b)]');
  check('buildBps branches on the duplicate key', i > 0, i > 0 ? '' : 'no duplicate branch found');
  const armEnd = body.indexOf('} else {', i);
  const arm = i > 0 && armEnd > i ? body.slice(i, armEnd) : '';
  check('the arm was located', arm.length > 0, arm.replace(/\s+/g, ' ').slice(0, 70));
  check("the flagged arm never sends 'bpremove'", !/send\(\s*'bpremove'/.test(arm));
  check('the flagged arm installs NO onclick at all', !/\.onclick\s*=/.test(arm));
  check('it marks BOTH controls disabled', (arm.match(/classList\.add\('disabled'\)/g) || []).length === 2,
        (arm.match(/classList\.add\('disabled'\)/g) || []).length + ' of 2');
  check('and gives both a reason', (arm.match(/\.title\s*=/g) || []).length === 2,
        (arm.match(/\.title\s*=/g) || []).length + ' of 2');
  // ISOLATION: the unflagged path must still wire both actions, or "no action when flagged" is satisfied
  // by a pane whose buttons never work.
  const rest = i > 0 ? body.slice(armEnd) : '';
  check('the ordinary row still wires remove', /send\(\s*'bpremove'/.test(rest));
  check('the ordinary row still wires the gear', /cfg\.onclick\s*=/.test(rest));
  // The editor refuses too, so the guard does not rest on the gear being the only way in.
  const edBody = codeOnly(pad.extract(html, 'buildBpEditor'));
  check('the properties editor refuses a locked row before sending', /if\s*\(\s*locked\s*\)\s*return\s*;/.test(edBody));
  check("...and 'bpprops' is sent after that refusal, not before",
        edBody.indexOf('locked) return') < edBody.indexOf("send('bpprops'"),
        'refusal at ' + edBody.indexOf('locked) return') + ', send at ' + edBody.indexOf("send('bpprops'"));

  // A ROW CAN BE BOTH, and the two explanations must not fight. They are DIFFERENT ambiguities: the path
  // one is about which FILE the name opens, the duplicate one about which BREAKPOINT the buttons act on.
  // They are written onto DIFFERENT elements — the filename link vs the x and the gear — so each control
  // carries the reason for its own refusal and neither overrides the other. Pinned, because merging them
  // onto one element later would silently drop one of the two explanations.
  const bothRow = { module: 'clbrws011.clw', line: 50, requested: 50, pathState: 'ambiguous', path: null };
  const bothDup = bpAmbiguousActionKeys([bothRow, Object.assign({}, bothRow)]);
  check('a row can be BOTH path-ambiguous and duplicate-keyed',
        bpPathDeclines(bpPathState(bothRow)) && !!bothDup[bpActionKey(bothRow)]);
  check('the path reason is written on the LINK', /lk\.title\s*=/.test(body));
  check('the action reason is written on the two CONTROLS, not the link',
        /cfg\.title\s*=\s*why/.test(body) && /rm\.title\s*=\s*why/.test(body));
  check('...so neither explanation is assigned to the element the other owns',
        !/lk\.title\s*=\s*why/.test(body));
}

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

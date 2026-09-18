// Regression check: the pad's CAUTION colour is readable in BOTH themes.
//
// The states this colour paints are the ones saying WHICH THREAD THE PANELS ARE SHOWING, and which call
// stack frames were recovered by raw stack scanning rather than walked. They are the last things that
// should be hard to read — and they were: the dark theme's amber sat at 1.8:1 on the light theme's panel,
// which the Owner reported as "it's in orange font and I can barely see it".
//
// Two failure modes, and this covers both, because the second one has nothing to do with the colour:
//   - a token that does not clear WCAG AA (4.5:1) against the surfaces it actually sits on;
//   - a marker crushed by an opacity on its ROW, which takes any colour below 3:1 no matter how good it is.
//
//   node tools/test-pad-contrast.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const html = pad.readPage(process.argv[2]);

// ---- WCAG relative luminance / contrast ----
function lum(hex) {
  const v = [0, 1, 2].map(i => parseInt(hex.slice(1 + i * 2, 3 + i * 2), 16) / 255)
    .map(c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4));
  return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
}
function ratio(a, b) { const x = lum(a), y = lum(b); const [hi, lo] = x > y ? [x, y] : [y, x]; return (hi + 0.05) / (lo + 0.05); }

// ---- read a custom property out of a theme block ----
// The two blocks are `:root { … }` (dark) and `body.light { … }`; a token defined in both is themed.
function themeBlock(selector) {
  const i = html.indexOf(selector);
  if (i < 0) throw new Error('no ' + selector + ' block');
  return html.slice(i, html.indexOf('}', i));
}
function token(block, name) {
  const m = new RegExp('--' + name + '\\s*:\\s*(#[0-9a-fA-F]{6})').exec(block);
  return m ? m[1] : null;
}
const DARK = themeBlock(':root {'), LIGHT = themeBlock('body.light {');

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}
const AA = 4.5;
function checkContrast(themeName, fg, surfaces) {
  Object.keys(surfaces).forEach(k => {
    const r = ratio(fg, surfaces[k]);
    check('   ' + themeName + ' on ' + k, r >= AA, r.toFixed(2) + ':1' + (r >= AA ? '' : ' — below AA ' + AA));
  });
}

console.log('the caution colour is defined per theme');
const warnDark = token(DARK, 'warn'), warnLight = token(LIGHT, 'warn');
check('--warn in the dark theme', !!warnDark, warnDark || 'absent');
check('--warn in the light theme', !!warnLight, warnLight || 'absent');
check('the two themes do not share one value', warnDark !== warnLight,
      'a single amber cannot clear AA on both a near-black and a white panel');
if (!warnDark || !warnLight) { console.log('\n' + (failures || 1) + ' FAILURE(S)'); process.exit(1); }

console.log('\nand it clears WCAG AA against the surfaces it actually sits on');
// bg / panel / titlebar as the theme blocks define them: the warning shows in the toolbar (titlebar),
// the Call Stack banner and picker (panel), and the console (bg).
const surf = b => ({ bg: token(b, 'bg'), panel: token(b, 'panel'), titlebar: token(b, 'titlebar') });
checkContrast('dark ', warnDark, surf(DARK));
checkContrast('light', warnLight, surf(LIGHT));

console.log('\nthe states that say which thread the panels are showing all use it');
// A literal amber anywhere else is the "fourth amber" problem: it cannot be themed, so it is readable in
// one theme by luck. The token is the only place a caution colour may be written down.
// Counted with the theme blocks removed: the definitions themselves are where the literal belongs, and
// --warn-bg / --warn-border share its prefix, so counting them would just measure the definition.
const outsideThemes = html.replace(DARK, '').replace(LIGHT, '');
const stray = (outsideThemes.match(/#e2b341/g) || []).length;
check('no literal amber outside the token definitions', stray === 0, stray + ' occurrence(s)');
['.thsel.other', '.thwarn', '#thBadgeTop', '.throw .thstop', '.frame .unc'].forEach(sel => {
  const i = html.indexOf(sel + ' {');
  const rule = i < 0 ? '' : html.slice(i, html.indexOf('}', i));
  check('   ' + sel + ' paints with the token', /var\(--warn/.test(rule), i < 0 ? 'rule not found' : rule.trim().slice(0, 60));
});

console.log('\nand no marker is dimmed into illegibility by its row');
// .frame.uncertain used to carry a row-wide opacity:.55, which took the ⚠ to 2.7:1 in BOTH themes — the
// one glyph saying "this frame may be stale" was the hardest thing in the panel to see. De-emphasise the
// frame's TEXT if you must; never the marker that explains why it is de-emphasised.
const rowDim = /\.frame\.uncertain\s*\{[^}]*opacity/.test(html);
check('the uncertain frame does not dim its whole row', !rowDim,
      rowDim ? 'a row-wide opacity also dims the ⚠' : 'only its text is dimmed');
// `.unc` must be followed by a separator: ".uncertain" contains ".unc", so a looser pattern matches the
// selector it is looking inside and reports a dimmed marker that is not there.
const uncDimmed = /\.frame\.uncertain[^{]*\.unc[\s,{][^{]*\{[^}]*opacity/.test(html);
check('…and never the ⚠ itself', !uncDimmed);

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

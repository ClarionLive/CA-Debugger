// Parse-only check of the pad's inline <script> bodies: catches a stray brace or a typo that would break
// the page silently inside the IDE's WebView. The other pad tests pull individual FUNCTIONS out of the
// page, so they cannot see a syntax error in the code between them.
//
// EVERY inline block is compiled, not just one. This used to seek with html.lastIndexOf('<script>'), so
// only the LAST block was ever checked and a syntax error anywhere above it went unreported — and, because
// the same seek demanded the exact spelling `<script>`, adding an attribute to the final tag would have
// silently dropped the page's only real block out of coverage.
//
//   node tools/test-pad-parse.js [path/to/debugger.html]
// Exit code 0 = every inline block parses.
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const page = pad.resolvePage(pagePath);
const html = pad.readPage(pagePath);

// A block with src= has no body here to compile, and a type= that is not JavaScript (a template, JSON-LD)
// is not meant to. Those are REPORTED as skipped rather than quietly counted as passes.
const JS_TYPES = ['', 'module', 'text/javascript', 'application/javascript', 'text/ecmascript'];
const re = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;

const blocks = [];
let m;
while ((m = re.exec(html))) {
  const bodyStart = m.index + m[0].indexOf('>') + 1;
  blocks.push({
    attrs: m[1],
    body: m[2],
    // 1-based line of the block's first body line, so a reported error can be found in the file
    line: html.slice(0, bodyStart).split('\n').length,
  });
}

if (!blocks.length) { console.log('no <script> block found in ' + page); process.exit(1); }

let compiled = 0, failures = 0;
for (const b of blocks) {
  const where = page + ' line ' + b.line;
  const src = /\bsrc\s*=/i.test(b.attrs) ? null : b.body;
  const type = (/\btype\s*=\s*["']?([^"'\s>]*)/i.exec(b.attrs) || [, ''])[1].toLowerCase();
  if (src === null) { console.log('  SKIP  external script   (' + where + ')'); continue; }
  if (!JS_TYPES.includes(type)) { console.log('  SKIP  type="' + type + '"   (' + where + ')'); continue; }
  if (!b.body.trim()) { console.log('  SKIP  empty block       (' + where + ')'); continue; }
  // new Function COMPILES without running: a syntax error throws here, page state never gets touched.
  // A `module` block may legally use import/export, which new Function rejects — it is reported as such
  // rather than as a syntax error, so the message never blames the wrong thing.
  try {
    new Function(b.body);
    compiled++;
    console.log('  PASS  parses OK         (' + where + ', ' + b.body.split('\n').length + ' lines)');
  } catch (e) {
    failures++;
    const modular = type === 'module' && /import|export/.test(e.message);
    console.log('  FAIL  ' + (modular ? 'ES module, not compilable standalone' : 'PARSE ERROR') +
                ': ' + e.message + '   (' + where + ')');
  }
}

// Every block being skipped is not a pass: it means this check is covering nothing at all.
if (!failures && !compiled) {
  console.log('\nFAILED: ' + blocks.length + ' <script> block(s) found, none of them inline JavaScript — nothing was checked.');
  process.exit(1);
}
console.log(failures
  ? '\n' + failures + ' of ' + blocks.length + ' block(s) FAILED to parse'
  : '\nall ' + compiled + ' inline script block(s) parse OK');
process.exit(failures ? 1 : 0);

// Parse-only check of the pad's inline <script> body: catches a stray brace or a typo that would break
// the page silently inside the IDE's WebView. The other pad tests pull individual FUNCTIONS out of the
// page, so they cannot see a syntax error in the code between them.
//
//   node tools/test-pad-parse.js [path/to/debugger.html]
// Exit code 0 = the page's script parses.
const fs = require('fs');
const pad = require('./pad-dom');
const p = process.argv[2] || pad.DEFAULT_PAGE;
const html = fs.readFileSync(p, 'utf8');
const i = html.lastIndexOf('<script>');
const j = html.indexOf('</script>', i);
if (i < 0 || j < 0) { console.log('no inline <script> found in ' + p); process.exit(1); }
const src = html.slice(i + '<script>'.length, j);
// new Function COMPILES without running: a syntax error throws here, page state never gets touched.
try { new Function(src); console.log('script parses OK  (' + src.split('\n').length + ' lines)'); }
catch (e) { console.log('PARSE ERROR: ' + e.message); process.exit(1); }

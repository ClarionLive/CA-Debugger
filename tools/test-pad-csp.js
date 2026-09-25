// Content-Security-Policy of the debugger pad (1797b13a).
//
// The pad is trusted for memory reads, so its <meta http-equiv="Content-Security-Policy"> is defence in depth
// behind the escaped sinks (test-pad-xss.js): default-src 'none', and the one inline <script> is allowed by
// the sha256 of its exact text. That hash goes stale on ANY edit to the script, and a stale hash does not
// fail loudly anywhere but inside the IDE, where WebView2 silently refuses to run the page's only script.
// So this suite recomputes it and fails until the meta carries it, printing the value to paste.
//
// What the browser hashes: the script element's text AFTER the HTML parser's input preprocessing, which
// turns CRLF and a lone CR into LF. The working tree here is CRLF (autocrlf) and the index LF, so the hash
// is computed over LF-normalised text and is the same whichever way the file was checked out.
//
// Also checked: no inline on*= event-handler attribute is left anywhere, in the markup or in HTML the script
// builds as a string (CSP without 'unsafe-inline' refuses to run those, so the button would just go dead),
// and the script never needs 'unsafe-eval'.
//
//   node tools/test-pad-csp.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
'use strict';
const crypto = require('crypto');
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const raw = pad.readPage(pagePath);
// The markup with every HTML comment OUTSIDE a script element blanked to spaces, so offsets still line up
// with `raw`. A comment that says "<script>" would otherwise open a block, and the hash would be of the wrong text.
const html = raw.replace(/<!--[\s\S]*?-->|<script\b[^>]*>[\s\S]*?<\/script\s*>/gi,
  m => m.startsWith('<!--') ? m.replace(/[^\n]/g, ' ') : m);

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

// ---- the policy --------------------------------------------------------------------------------------
console.log('\n1) the page carries one CSP meta, ahead of anything it governs');
const metas = [...html.matchAll(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*\/?>/gi)];
check('exactly one Content-Security-Policy meta', metas.length === 1, String(metas.length));
const policy = metas.length ? metas[0][1] : '';
const metaAt = metas.length ? metas[0].index : -1;
// A meta policy governs only what the parser meets after it.
const firstStyle = html.search(/<style\b/i), firstScript = html.search(/<script\b/i);
check('it comes before the first <style> and the first <script>',
      metaAt >= 0 && metaAt < firstStyle && metaAt < firstScript, metaAt + ' / ' + firstStyle + ' / ' + firstScript);
check('it comes right after <meta charset>',
      /<meta charset="utf-8" \/>\s*(<!--[\s\S]*?-->\s*)?<meta\s+http-equiv="Content-Security-Policy"/i.test(html));

const dirs = new Map();
policy.split(';').map(d => d.trim()).filter(Boolean).forEach(d => {
  const [name, ...vals] = d.split(/\s+/);
  dirs.set(name.toLowerCase(), vals);
});
const dir = n => dirs.get(n) || [];
console.log('   policy: ' + policy);
check("default-src 'none'", dir('default-src').join(' ') === "'none'", dir('default-src').join(' '));
check("style-src 'unsafe-inline' and nothing else", dir('style-src').join(' ') === "'unsafe-inline'", dir('style-src').join(' '));
const scriptSrc = dir('script-src');
check("script-src is hashes only: no 'unsafe-inline', 'unsafe-eval', nonce, host or scheme",
      scriptSrc.length > 0 && scriptSrc.every(v => /^'sha256-[A-Za-z0-9+/]+=*'$/.test(v)), scriptSrc.join(' '));

// ---- the hash ----------------------------------------------------------------------------------------
console.log('\n2) script-src names the sha256 of every inline script, and nothing else');
const blocks = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
check('no external script (default-src \'none\' would block it)', blocks.every(b => !/\bsrc\s*=/i.test(b[1])));
check('exactly one inline <script> (the PM decision: it stays one inline block)', blocks.length === 1, String(blocks.length));
const want = blocks.map(b => "'sha256-" + crypto.createHash('sha256')
  .update(b[2].replace(/\r\n?/g, '\n'), 'utf8').digest('base64') + "'");
want.forEach((h, i) => check('inline script ' + (i + 1) + ' is allowed by its hash', scriptSrc.includes(h),
  scriptSrc.includes(h) ? h : 'the script changed: put ' + h + ' in script-src (was ' + scriptSrc.join(' ') + ')'));
check('no stale hash left in script-src', scriptSrc.every(h => want.includes(h)), scriptSrc.join(' '));

// ---- inline handlers ---------------------------------------------------------------------------------
console.log('\n3) no inline event handler, in the markup or in HTML the script builds');
// An attribute is preceded by whitespace (or a quote, in a string the script concatenates). A property
// assignment such as row.onclick= is preceded by '.', which is not an attribute and CSP allows.
const attrHits = [...html.matchAll(/(^|[\s"'])(on[a-z]+)\s*=/gim)]
  .map(m => ({ name: m[2], line: html.slice(0, m.index).split('\n').length }));
check('no on*= attribute', attrHits.length === 0, attrHits.map(h => h.name + ' @ line ' + h.line).join(', '));
check('no setAttribute of an on* handler', !/setAttribute\(\s*['"]on/i.test(html));
// The two toolbar buttons that had inline handlers until 1797b13a are wired from the script instead
// (the Attach… one is also pinned in test-pad-attach.js). Structural: the handlers are anonymous.
check("Run to Cursor is wired from the script to send('runtocursor')",
      /\$\('btnRtc'\)\.onclick=function\(\)\{ send\('runtocursor'\); \};/.test(html));
check('Attach… is wired from the script to openAttach',
      /\$\('btnAttach'\)\.onclick=function\(\)\{ openAttach\(\); \};/.test(html));
check('no javascript: URL', !/javascript:\s*[^/\s]/i.test(html.replace(/\/\/[^\n]*|<!--[\s\S]*?-->/g, '')));

console.log("\n4) the script needs no 'unsafe-eval'");
const code = blocks.map(b => b[2].replace(/\/\/[^\n]*/g, '')).join('\n');
check('no eval( / new Function( / string setTimeout|setInterval',
      !/\beval\s*\(|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*['"`]/.test(code));

console.log('');
if (failures) { console.log(failures + ' FAILURE(S)'); process.exit(1); }
console.log('ALL CHECKS PASSED');

// Injection sinks in the debugger pad (e1dea0d9).
//
// The pad is a WebView2 page the Owner has ruled TRUSTED for memory reads, and every symbol name, type and
// value on it comes out of the debuggee's own debug info. A name that breaks out of an HTML attribute runs
// script in a page that can read the debugged process's memory, so these are sinks even though the
// "attacker" is the program being debugged.
//
// What this file checks, site by site, against the REAL functions pulled out of debugger.html:
//   1) esc() escapes quotes as well as & < >, since its output is interpolated into quoted attributes
//   2) buildSource: the identifier wrap tokenises the RAW line, so a quote in a symbol name cannot leave
//      data-name, and a symbol named lt/gt/amp/quot cannot split an entity
//   3) renderTA (type-ahead): rows are built with DOM APIs, and dataset.n is the name byte for byte
//   4) editAttrs: every attribute value is escaped, whatever the reply carries
//   5) cssEsc: a name containing a newline yields a selector string CSS can parse, which still finds the row
//
// pad-dom.js does not parse innerHTML, so the attribute checks run a small tag/attribute tokeniser over the
// stored markup (htmlTags below) that splits the way a browser does: a quoted value ends at its quote, and
// anything left in a tag that is not a well-formed attribute is a breakout.
//
//   node tools/test-pad-xss.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const pad = require('./pad-dom');
const pagePath = process.argv.slice(2).find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);

// ---- scope the page's functions run in -------------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);
const window = { innerWidth: 1200, innerHeight: 800 };
function attachTip() { }
function renderBpDots() { }
function setSrcLocation() { }
const ADDED = [];
function addWatch(n) { ADDED.push(n); }
let curFile = null, curLine = 0, allSyms = [];
const inp = $('watchInput'), ta = $('typeahead');

const FNS = ['esc', 'reEsc', 'buildSource', 'renderTA', 'editAttrs', 'cssEsc'];
const missing = [];
const src = FNS.map(n => {
  try { return pad.extract(html, n); }
  catch (e) { missing.push(n); return 'function ' + n + '(){}'; }
}).join('\n');
if (missing.length) {
  // A stubbed function returns undefined everywhere and every check below would pass vacuously. Refuse.
  console.log('  FAIL  ' + missing.length + ' of ' + FNS.length + ' page function(s) not found in '
              + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
eval(src);

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

// Copied from tools/test-pad-attach.js (HOSTILE_NAME): an attribute breakout with a live handler.
const HOSTILE_NAME = '<img src=x onerror="send(\'attach\',\'4\')">evil.exe';
// The same idea in a shape the source regex can match as an identifier: no `<`, a quote to leave the
// attribute with, and a handler after it.
const QUOTE_NAME = 'X"onmouseover="send(\'attach\',\'4\')';

// ---- a browser-shaped tokeniser for the stored markup ----------------------------------------------
// Returns every tag with its attributes, plus `junk`: whatever in the tag body was NOT a well-formed
// name="value" / name='value' / name=value / bare-name attribute. A breakout always leaves junk or an extra attribute.
function htmlTags(markup) {
  const out = [];
  const tagRe = /<(\/?)([A-Za-z][\w-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
  let m;
  while ((m = tagRe.exec(markup))) {
    const attrs = [];
    const body = m[3].replace(/\s*([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g, (_, n, dq, sq, uq) => {
      attrs.push({ name: n, value: dq !== undefined ? dq : sq !== undefined ? sq : uq !== undefined ? uq : '' }); return '';
    });
    out.push({ close: !!m[1], tag: m[2].toLowerCase(), attrs: attrs, junk: body.trim() });
  }
  return out;
}
function decode(s) {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}
// Decode each text run on its own, as a browser does: an entity split by a tag (`&<span>lt</span>;`) is
// NOT an entity and renders as the literal characters, so stripping the tags first would hide the split.
function textOf(markup) { return markup.split(/<(?:\/?)(?:[A-Za-z][\w-]*)(?:(?:[^>"']|"[^"]*"|'[^']*')*)>/).map(decode).join(''); }
// Every tag is an allowed one, carries only allowed attributes, has no junk, and no value holds a raw
// quote or `<` (a raw `<` inside a value is harmless to a browser but means nothing was escaped).
function markupProblems(markup, tags, attrs) {
  const bad = [];
  htmlTags(markup).forEach(t => {
    if (tags.indexOf(t.tag) < 0) bad.push('tag <' + t.tag + '>');
    if (t.junk) bad.push('junk in <' + t.tag + '>: ' + t.junk);
    t.attrs.forEach(a => {
      if (attrs.indexOf(a.name) < 0) bad.push('attribute ' + a.name + ' on <' + t.tag + '>');
      if (/["'<]/.test(a.value)) bad.push('raw quote or < in ' + a.name + '=' + a.value);
    });
  });
  return bad;
}

console.log('0) the tokeniser itself flags a breakout (a check that cannot fail proves nothing)');
{
  const broken = '<span class="srcid id" data-name="' + QUOTE_NAME + '">x</span>';
  const p = markupProblems(broken, ['span'], ['class', 'data-name']);
  check('an unescaped quote in data-name is reported', p.length > 0, p.join('; '));
  const imgs = markupProblems('<span>' + HOSTILE_NAME + '</span>', ['span'], []);
  check('an unescaped tag in text is reported', imgs.some(x => /tag <img>/.test(x)), imgs.join('; '));
  check('well-formed markup is not', markupProblems('<span class="a" data-name="b&quot;c">d</span>', ['span'], ['class', 'data-name']).length === 0);
}

console.log('\n1) esc() escapes both quote characters');
{
  const e = esc(HOSTILE_NAME + "'" + QUOTE_NAME);
  check('no raw " or \' or < or > survives', !/["'<>]/.test(e), e);
  check('...and it decodes back to the input', decode(e) === HOSTILE_NAME + "'" + QUOTE_NAME);
}

console.log('\n2) buildSource wraps identifiers without leaving the attribute or splitting an entity');
{
  allSyms = [{ name: QUOTE_NAME }, { name: 'lt' }, { name: 'gt' }, { name: 'amp' }, { name: 'quot' },
             { name: 'CNT' }];
  const LINES = [
    "  IF CNT < 3 AND CNT > 1 & 'x' THEN " + QUOTE_NAME + ' = 1.',
    '  lt = gt & amp   ! quot',
    "  s = '" + HOSTILE_NAME + "'",
  ];
  buildSource('a.clw', 'P', 10, LINES, 11);
  const rows = $('src').querySelectorAll('.sline');
  check('one row per line', rows.length === LINES.length, rows.length + '');
  rows.forEach((d, i) => {
    const probs = markupProblems(d.innerHTML, ['span'], ['class', 'data-name']);
    check('line ' + (i + 1) + ': markup is well-formed (no breakout, no stray tag)', probs.length === 0, probs.join('; '));
    // The gutter span holds the line number, so the rendered text is that number followed by the line.
    check('line ' + (i + 1) + ': renders exactly the source text (no split entity)',
          textOf(d.innerHTML) === String(10 + i) + LINES[i], JSON.stringify(textOf(d.innerHTML)));
  });
  const names = [];
  rows.forEach(d => htmlTags(d.innerHTML).forEach(t => t.attrs.forEach(a => { if (a.name === 'data-name') names.push(decode(a.value)); })));
  check('the quoted symbol is wrapped with its exact name in data-name', names.indexOf(QUOTE_NAME) >= 0, JSON.stringify(names));
  check('lt/gt/amp are wrapped where they are identifiers', ['lt', 'gt', 'amp'].every(n => names.indexOf(n) >= 0), JSON.stringify(names));
  check('...and never inside an entity: "quot" is wrapped once (the comment), not per escaped quote',
        names.filter(n => n === 'quot').length === 1, JSON.stringify(names));
}

console.log('\n3) renderTA builds the type-ahead with DOM APIs, carrying the name byte for byte');
{
  allSyms = [{ name: HOSTILE_NAME, type: '<b>"LONG"</b>' }, { name: QUOTE_NAME, type: 'STRING' }];
  renderTA('e');
  const items = ta.querySelectorAll('.ta-item');
  check('one row per match', items.length === 2, items.length + ' row(s); innerHTML=' + JSON.stringify(ta.innerHTML));
  check('nothing was interpolated into innerHTML', ta.innerHTML === '', JSON.stringify(ta.innerHTML));
  check('dataset.n is each name exactly', items.length === 2 && items[0].dataset.n === HOSTILE_NAME && items[1].dataset.n === QUOTE_NAME,
        items.map(i => i.dataset.n).join(' | '));
  check('the name and type are text', items.length === 2 && items[0].children[0].textContent === HOSTILE_NAME
        && items[0].children[1].textContent === '<b>"LONG"</b>');
  if (items.length) { ADDED.length = 0; items[1].onclick(); }
  check('clicking a row watches that exact name', ADDED.length === 1 && ADDED[0] === QUOTE_NAME, JSON.stringify(ADDED));
}

console.log('\n4) editAttrs escapes every value it writes');
{
  const a = editAttrs({ va: '0x1"><img src=x onerror=alert(1)>', typeCode: '"', size: '1" onclick="x', places: "'" });
  const probs = markupProblems('<span class="vval"' + a + '>v</span>', ['span'], ['class', 'data-va', 'data-tc', 'data-sz', 'data-pl']);
  check('hostile va/typeCode/size/places stay inside their attributes', probs.length === 0, probs.join('; '));
  check('a non-editable row writes nothing', editAttrs({}) === '');
  const ok = editAttrs({ va: '0x4A10F0', typeCode: 3, size: 4, places: 0 });
  check('an ordinary reply is unchanged by escaping', ok === ' data-va="0x4A10F0" data-tc="3" data-sz="4" data-pl="0"', ok);
}

console.log('\n5) cssEsc: a newline in a name still makes a parseable selector that finds the row');
{
  const NL = 'A\nB"C\\D\r';
  const e = cssEsc(NL);
  // A CSS string token is a bad-string (and querySelectorAll throws) on a raw newline, CR or form feed.
  check('no raw newline, CR or form feed in the escaped string', !/[\n\r\f]/.test(e), JSON.stringify(e));
  check('every quote is escaped', !/(^|[^\\])(\\\\)*"/.test(e), JSON.stringify(e));
  const row = document.createElement('div'); row.dataset.name = NL; document.body.appendChild(row);
  const other = document.createElement('div'); other.dataset.name = 'A'; document.body.appendChild(other);
  const hit = document.querySelectorAll('[data-name="' + e + '" i]');
  check('the selector matches that row and only that row', hit.length === 1 && hit[0] === row, hit.length + ' match(es)');
  check('an ordinary name is unchanged', cssEsc('LOC:Count') === 'LOC:Count');
}

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

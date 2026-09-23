// Regression check: the Memory panel (ticket 633d8b2f) - the hex + ASCII dump, its paging, its reply
// matching, and "View memory" on variable rows.
//
// Runs the REAL functions out of debugger.html against the shared mini-DOM (tools/pad-dom.js), with the
// host replaced by a recorder of what the page posts. What it holds the page to:
//   - an address is hex (0x optional, at most 8 digits) or nothing - a bad one is never sent;
//   - a request is `mem` "reqId|0xADDR|len", only while paused AND the panel is open, and never past 4 GB;
//   - only the NEWEST reply paints, and a reply is not tid-gated (memory is the process's);
//   - the dump escapes the ASCII gutter, and says so when the read came back short;
//   - "View memory" appears for any row with storage (`addr`, or an edit `va`), including the rows the
//     watch gate does not wire, and never for a row without one.
//
//   node tools/test-pad-memory.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
// (Not strict mode: the page's functions and constants are eval'd into THIS scope, as in the other pad suites.)
const pad = require('./pad-dom');
const argv = process.argv.slice(2);
const pagePath = argv.find(a => !a.startsWith('--'));
const html = pad.readPage(pagePath);
const El = pad.El;

// An element that remembers its listeners, so a test can fire one (pad-dom's El ignores them).
class LEl extends El {
  constructor(tag) { super(tag); this._ls = {}; }
  addEventListener(type, fn) { (this._ls[type] = this._ls[type] || []).push(fn); }
  fire(type, ev) { (this._ls[type] || []).forEach(f => f(ev)); }
}

// ---- scope the page's functions run in -------------------------------------------------------------
const doc = pad.makeDocument();
const document = doc;
const $ = id => doc.id(id);
const window = { innerWidth: 1200, innerHeight: 800 };
const SENT = [];
const wv = { postMessage: s => SENT.push(JSON.parse(s)) };
let isPaused = true;
const MEMSEC = new LEl('details'); MEMSEC.open = true; MEMSEC.dataset.sec = 'memory';
let shown = [];
function secEl(id) { return id === 'memory' ? MEMSEC : null; }
function showSection(id) { shown.push(id); MEMSEC.classList.remove('sec-hidden'); }

const FNS = ['esc', 'send', 'isHidden', 'memParseAddr', 'memHex', 'memClampStart', 'memRows', 'memIsOpen',
  'refreshMem', 'onMem', 'memReread', 'renderMem', 'memGo', 'openMemoryAt', 'memMenuFor', 'wireMemMenu'];
const missing = [];
const src = FNS.map(n => { try { return pad.extract(html, n); } catch (e) { missing.push(n); return ''; } }).join('\n');
if (missing.length) {
  console.log('  FAIL  page function(s) not found in ' + pad.resolvePage(pagePath) + ': ' + missing.join(', '));
  process.exit(1);
}
// The page's own constants, so the test cannot drift from them.
eval(pad.extractConst(html, 'MEM_MAX').replace(/^const /, 'var '));
eval(src);
// the page's `let` state, owned here
let _memReq = 0, memAddr = null, memLen = 256, lastMem = null, memInFlight = null, _memMenuAddr = null;

let failures = 0;
function check(label, cond, detail) {
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}
const memSends = () => SENT.filter(s => s.action === 'mem');
function reset() { SENT.length = 0; _memReq = 0; memAddr = null; memLen = 256; lastMem = null; memInFlight = null;
  isPaused = true; MEMSEC.open = true; MEMSEC.classList.remove('sec-hidden'); shown = []; }
const hexOf = bytes => bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');

// ---- 1. the constants ------------------------------------------------------------------------------
check('MEM_MAX matches the engine and host cap (4096)', MEM_MAX === 4096, String(MEM_MAX));
check('MEM_TOP is 4 GB', MEM_TOP === 0x100000000, String(MEM_TOP));

// ---- 2. address parsing ----------------------------------------------------------------------------
{
  const ok = [['0x4A2F10', 0x4A2F10], ['4a2f10', 0x4A2F10], [' 0XFF ', 0xFF], ['0xFFFFFFFF', 0xFFFFFFFF], ['0', 0]];
  ok.forEach(([s, v]) => check('memParseAddr accepts ' + JSON.stringify(s), memParseAddr(s) === v, String(memParseAddr(s))));
  const bad = ['', '0x', '0x123456789', 'zz', '-1', '0x1 2', '0x1|2', null, '1e3x'];
  bad.forEach(s => check('memParseAddr refuses ' + JSON.stringify(s), memParseAddr(s) === null, String(memParseAddr(s))));
  check('memHex pads to 8 upper-case digits', memHex(0x4a2f) === '0x00004A2F', memHex(0x4a2f));
}

// ---- 3. clamping: never below 0, never a span past 4 GB ---------------------------------------------
check('memClampStart keeps an ordinary address', memClampStart(0x401000, 256) === 0x401000);
check('memClampStart pulls a block that would pass 4 GB back to end AT it',
      memClampStart(0xFFFFFFF0, 256) === 0x100000000 - 256, memHex(memClampStart(0xFFFFFFF0, 256)));
check('memClampStart does not go below 0', memClampStart(-16, 256) === 0);

// ---- 4. rows --------------------------------------------------------------------------------------
{
  const bytes = [0x41, 0x00, 0x7F, 0x3C]; for (let i = 4; i < 20; i++) bytes.push(0x30 + (i % 10));
  const rows = memRows(0x1000, hexOf(bytes), 20);
  check('memRows makes one row per 16 bytes', rows.length === 2, String(rows.length));
  check('memRows addresses each row', rows[0].addr === '0x00001000' && rows[1].addr === '0x00001010', rows.map(r => r.addr).join(','));
  check('memRows ASCII shows printables and dots the rest', rows[0].ascii.slice(0, 4) === 'A..<', JSON.stringify(rows[0].ascii));
  check('memRows splits the hex 8 + 8', /^41 00 7F 3C \S\S \S\S \S\S \S\S  \S\S/.test(rows[0].hex), rows[0].hex);
  check('memRows pads a short last row so the ASCII column lines up', rows[1].hex.length === rows[0].hex.length, rows[1].hex.length + ' vs ' + rows[0].hex.length);
  check('memRows stops at `read`, not at the hex length', memRows(0, hexOf(bytes), 3).length === 1 && memRows(0, hexOf(bytes), 3)[0].ascii === 'A..');
  check('memRows stops at the hex length when `read` overstates it', memRows(0, '4142', 16)[0].ascii === 'AB');
}

// ---- 5. requests ------------------------------------------------------------------------------------
{
  reset(); memGo(0x401000);
  let s = memSends();
  check('memGo while paused and open sends one mem request', s.length === 1, JSON.stringify(s));
  check('the request is reqId|0xADDR|len', s.length === 1 && s[0].data === '1|0x00401000|256', s.length ? s[0].data : '');
  check('memGo shows the clamped address in the box', $('memAddr').value === '0x00401000', $('memAddr').value);
  refreshMem();
  check('the same read already in flight is not sent twice', memSends().length === 1, String(memSends().length));
  memReread();
  check('memReread (a new stop, or the refresh button) sends it again', memSends().length === 2 && memSends()[1].data === '2|0x00401000|256');

  reset(); isPaused = false; memGo(0x401000);
  check('nothing is sent while running', memSends().length === 0);
  check('...and the panel says to pause', /Pause to read memory/.test($('memBody').innerHTML), $('memBody').innerHTML);

  reset(); MEMSEC.open = false; memGo(0x401000);
  check('nothing is sent while the panel is collapsed', memSends().length === 0);

  reset(); memLen = 4096; memGo(0xFFFFFFFF);
  check('a block near 4 GB is requested so it ends at 4 GB, never past it',
        memSends().length === 1 && memSends()[0].data === '1|0xFFFFF000|4096', memSends().length ? memSends()[0].data : '');
}

// ---- 6. replies -------------------------------------------------------------------------------------
{
  reset(); memGo(0x401000); memGo(0x402000);   // two requests; only reqId 2 is current
  onMem({ type: 'mem', reqId: '1', addr: '0x401000', len: 256, read: 1, bytes: '41' });
  check('a reply to a superseded request does not paint', !/mrow/.test($('memBody').innerHTML), $('memBody').innerHTML.slice(0, 60));
  onMem({ type: 'mem', reqId: '2', addr: '0x402000', len: 256, read: 256, bytes: '3C'.repeat(256) });
  const body = $('memBody').innerHTML;
  check('the current reply paints 16 rows', (body.match(/class="mrow"/g) || []).length === 16, String((body.match(/class="mrow"/g) || []).length));
  check('the ASCII gutter is escaped', body.indexOf('&lt;&lt;') >= 0 && body.indexOf('<<') < 0);
  check('a full read carries no short-read note', !/memnote/.test(body));
  check('the reply clears the in-flight mark, so the next stop re-reads', memInFlight === null);

  // The SAME address asked twice (a stop, then the refresh button): the address match cannot tell the two
  // replies apart, so only the reqId stands between the older bytes and the screen.
  reset(); memGo(0x401000); memReread();
  onMem({ type: 'mem', reqId: '1', addr: '0x401000', len: 256, read: 1, bytes: '41' });
  check('an older reply for the SAME address does not paint either', !/mrow/.test($('memBody').innerHTML), $('memBody').innerHTML.slice(0, 60));
  check('...and the newer request is still in flight', memInFlight !== null);

  reset(); memGo(0x401000);
  onMem({ type: 'mem', reqId: '1', addr: '0x401000', len: 256, read: 32, bytes: '00'.repeat(32) });
  check('a short read says how much was readable', /32 of 256 bytes readable/.test($('memBody').innerHTML), $('memBody').innerHTML.slice(-90));

  reset(); memGo(0x10);
  onMem({ type: 'mem', reqId: '1', addr: '0x10', len: 256, read: 0, bytes: '', error: 'mem: read failed at 0x10' });
  check('a refusal shows its reason', /read failed at 0x10/.test($('memBody').innerHTML), $('memBody').innerHTML);
}

// ---- 7. "View memory" -------------------------------------------------------------------------------
{
  const row = new LEl('div');
  wireMemMenu(row, { name: 'G', addr: '0x400000' });
  check('a group row (addr, no va) is given its address', row.dataset.addr === '0x400000');
  check('...and its own context menu', (row._ls.contextmenu || []).length === 1);
  let prevented = false;
  row.fire('contextmenu', { preventDefault() { prevented = true; }, stopPropagation() { }, clientX: 10, clientY: 10 });
  check('that menu offers View memory and hides Add to Watch',
        prevented && $('tmMem').style.display === '' && $('tmWatch').style.display === 'none' && $('treeMenu').classList.contains('show'));
  check('...for that row\'s address', _memMenuAddr === '0x400000', String(_memMenuAddr));

  const vaOnly = new LEl('div'); wireMemMenu(vaOnly, { name: 'S', va: '0x400010' });
  check('a row with only an edit va still offers View memory at it', vaOnly.dataset.addr === '0x400010');

  const none = new LEl('div'); wireMemMenu(none, { name: 'X', value: '1' });
  check('a row with no storage gets no address and no menu', none.dataset.addr === undefined && !none._ls.contextmenu);

  const sel = new LEl('div'); sel.classList.add('selrow'); wireMemMenu(sel, { name: 'L', addr: '0x400020' });
  check('a watchable row gets its address but no second menu (wireSel shows it)', sel.dataset.addr === '0x400020' && !sel._ls.contextmenu);

  memMenuFor(undefined, true);
  check('memMenuFor with no address hides View memory and shows Add to Watch',
        $('tmMem').style.display === 'none' && $('tmWatch').style.display === '');

  reset(); MEMSEC.open = false; MEMSEC.classList.add('sec-hidden');
  openMemoryAt('0x400000');
  check('View memory un-hides and opens the panel', shown.indexOf('memory') >= 0 && MEMSEC.open === true);
  check('...and reads at the row\'s address', memSends().length === 1 && memSends()[0].data === '1|0x00400000|256', JSON.stringify(memSends()));
  reset(); openMemoryAt('not-an-address');
  check('View memory with a bad address sends nothing', memSends().length === 0);
}

// ---- 8. the shared hooks, by POSITION (a deleted or disabled call must fail here) ---------------------
{
  const onMsg = pad.extract(html, 'onMessage');
  const pausedArm = onMsg.slice(onMsg.indexOf("case 'paused':"), onMsg.indexOf("case 'resumed':"));
  check("the 'paused' arm re-reads memory, after setPaused(true)",
        /setPaused\(true\);[^;]*;?\s*memReread\(\);\s*break;/.test(pausedArm.replace(/refreshLibState\(\);\s*/, '')),
        pausedArm.replace(/\s+/g, ' ').slice(-80));
  check("the 'mem' reply goes straight to onMem, with no tid gate", /case 'mem':\s*onMem\(m\);\s*break;/.test(onMsg));
  const rvr = pad.extract(html, 'renderVarRow');
  const gateEnd = rvr.indexOf('wireSel(row);');
  const wm = rvr.indexOf('wireMemMenu(row, v);');
  check('renderVarRow calls wireMemMenu AFTER the watch gate (so nested and group rows get it)',
        gateEnd > 0 && wm > gateEnd && rvr.slice(gateEnd, wm).indexOf('}') >= 0, 'wireSel@' + gateEnd + ' wireMemMenu@' + wm);
  const ws = pad.extract(html, 'wireSel');
  check('wireSel sets the menu from the right-clicked row', /memMenuFor\(row\.dataset\.addr,\s*true\)/.test(ws));
  check('the tree menu carries a View memory item', /id="treeMenu"[^\n]*id="tmMem"/.test(html));
  check('the memory panel is in the layout lists, collapsed by default',
        /DEFAULT_LEFT=\[[^\]]*'memory'/.test(html) && /DEFAULT_COLLAPSED=\{[^}]*memory:true/.test(html) && /data-sec="memory"/.test(html));
}

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

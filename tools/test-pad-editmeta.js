// Regression check: a Variables/Watch row must never keep a STALE instance address or its edit pencil.
//
// Rows are reused across stops. A row that resolved to one thread's instance and then gets a reply with no
// va (THREADed data not yet used on that thread, or a read that failed) used to keep the old va, the
// 'editable' class and a live pencil, so committing an edit wrote ANOTHER thread's memory while the row
// displayed the template value.
//
// Runs the REAL clearEditMeta/setEditMeta/wireEdit/applyValue out of debugger.html against a minimal DOM.
// Point it at a pre-fix copy of the page and steps 2 and 3 fail - that is the before/after proof.
//
//   node tools/test-pad-editmeta.js [path/to/debugger.html]
// Exit code 0 = all checks passed.
const fs = require('fs');
const path = process.argv[2] || require('path').join(__dirname, '..', 'src', 'ClarionDebugger.Addin', 'Terminal', 'debugger.html');
const html = fs.readFileSync(path, 'utf8');

// ---- pull out a top-level `function NAME(` declaration by brace matching
function extract(name) {
  const sig = 'function ' + name + '(';
  const i = html.indexOf(sig);
  if (i < 0) throw new Error('not found: ' + name);
  let depth = 0, started = false;
  for (let j = i; j < html.length; j++) {
    const c = html[j];
    if (c === '{') { depth++; started = true; }
    else if (c === '}') { depth--; if (started && depth === 0) return html.slice(i, j + 1); }
  }
  throw new Error('unterminated: ' + name);
}

// ---- minimal DOM ----
class ClassList {
  constructor(){ this.s = new Set(); }
  add(...c){ c.forEach(x=>this.s.add(x)); }
  remove(...c){ c.forEach(x=>this.s.delete(x)); }
  contains(c){ return this.s.has(c); }
  toggle(c, on){ if(on===undefined) on = !this.s.has(c); on ? this.s.add(c) : this.s.delete(c); return on; }
  toString(){ return [...this.s].join(' '); }
}
class El {
  constructor(tag){ this.tag = tag; this.classList = new ClassList(); this.dataset = {}; this.children = [];
    this.parentElement = null; this.textContent = ''; this.attrs = {}; this.scrollWidth = 10; this.clientWidth = 100; }
  querySelector(sel){
    const want = sel.replace('.', '');
    for (const c of this.children) { if (c.classList.contains(want)) return c;
      const d = c.querySelector(sel); if (d) return d; }
    return null;
  }
  append(c){ c.parentElement = this; this.children.push(c); }
  get nextElementSibling(){
    if (!this.parentElement) return null;
    const i = this.parentElement.children.indexOf(this);
    return this.parentElement.children[i + 1] || null;
  }
  insertAdjacentElement(where, el){
    const p = this.parentElement; const i = p.children.indexOf(this);
    p.children.splice(where === 'afterend' ? i + 1 : i, 0, el); el.parentElement = p; return el;
  }
  remove(){ const p = this.parentElement; if (!p) return; p.children.splice(p.children.indexOf(this), 1); this.parentElement = null; }
  removeAttribute(a){ delete this.attrs[a]; if (a === 'title') this.title = undefined; }
  set className(v){ this.classList = new ClassList(); String(v).split(/\s+/).filter(Boolean).forEach(c=>this.classList.add(c)); }
  get className(){ return this.classList.toString(); }
  get title(){ return this.attrs.title; }
  set title(v){ if (v === undefined) delete this.attrs.title; else this.attrs.title = v; }
}

let ROW = null;
const document = {
  createElement: t => new El(t),
  querySelectorAll: sel => (sel.startsWith('[data-name=') && ROW) ? [ROW] : [],
  querySelector: () => null,
};
// deps applyValue touches that are not under test
const values = new Map();
const cssEsc = s => s.replace(/["\\]/g, '\\$&');
const beginEdit = () => {};
const STAR = '*';
// dtApply is REAL, not a stub: it inserts its own .vas tag next to the same cell and runs AFTER wireEdit,
// so on a DATE/TIME/integer row it sits between the cell and the pencil. Stubbing it out is precisely how a
// position-based pencil lookup passed this test while leaving a live pencil on every numeric row.
const dtModes = {};

// clearEditMeta exists only in the FIXED page; running this against the pre-fix one is the before/after proof
const src = ['dtParseInt','fieldPart','fmtClarionDate','fmtClarionTime','dtDefault','dtModeFor','dtApply','dtCycle',
             'clearEditMeta','setEditMeta','wireEdit','applyValue'].map(n => {
  try { return extract(n); }
  catch (e) { console.log('   (note: ' + n + ' absent — pre-fix page)'); return 'function ' + n + '(){}'; }
}).join('\n');
eval(src);

// ---- scenario ----
function makeRow(name){
  const tree = new El('div');                    // rows live in a container (the THREAD tag inserts beside the row)
  const row = new El('div'); row.dataset.name = name || 'AUT:AU_LNAME';
  const v = new El('span'); v.classList.add('vval','pending'); v.textContent = '…';
  row.append(v); tree.append(row); ROW = row; return row;
}
// sibling order after the cell, which is what a position-based lookup gets wrong
function siblings(row){ return row.children.map(c => c.classList.toString().split(' ')[0]).join(','); }
function state(row){
  const v = row.querySelector('.vval');
  const btn = row.querySelector('.vedit-btn');
  return { text: v.textContent, cls: v.classList.toString(), va: v.dataset.va, pencil: !!btn, title: v.title };
}
const THREAD_A = { va: '0x847A76', typeCode: '0x18', size: 41, places: 0 };

let failures = 0;
function check(label, cond, detail){
  console.log((cond ? '  PASS  ' : '  FAIL  ') + label + (detail ? '  ->  ' + detail : ''));
  if (!cond) failures++;
}

console.log('1) stop on thread A: value resolves to an instance');
const row = makeRow();
applyValue('AUT:AU_LNAME', true, "'Del Castillo'", 'STRING(41)', true, THREAD_A);
let s = state(row); console.log('   ' + JSON.stringify(s));
check('row is editable, bound to A, pencil shown', s.cls.includes('editable') && s.va === THREAD_A.va && s.pencil);

console.log('2) later stop: engine reports the value not yet allocated on this thread (no va)');
applyValue('AUT:AU_LNAME', true, "''", 'STRING(41)', true, { note: 'not yet used on this thread — initial value' });
s = state(row); console.log('   ' + JSON.stringify(s));
check("stale instance VA cleared", s.va === undefined, 'va=' + s.va);
check("'editable' cleared", !s.cls.includes('editable'));
check('edit pencil removed', !s.pencil);
check('note surfaced', s.cls.includes('noted') && !!s.title);

console.log('3) re-bind to an instance, then a failed read (found:false + error)');
applyValue('AUT:AU_LNAME', true, "'Del Castillo'", 'STRING(41)', true, THREAD_A);
applyValue('AUT:AU_LNAME', false, null, null, false, { error: 'THR$GetInstance is not emulatable on this runtime' });
s = state(row); console.log('   ' + JSON.stringify(s));
check("stale instance VA cleared", s.va === undefined, 'va=' + s.va);
check('edit pencil removed', !s.pencil);
check('row reads (unavailable), not "…"', s.text === '(unavailable)' && s.cls.includes('unavail'));
check('reason in tooltip', !!s.title);

console.log('4) a normal reply still re-arms editing');
applyValue('AUT:AU_LNAME', true, "'White'", 'STRING(41)', true, THREAD_A);
s = state(row); console.log('   ' + JSON.stringify(s));
check('editable + va + pencil restored', s.cls.includes('editable') && s.va === THREAD_A.va && s.pencil);

// ---- the same lifecycle on rows where dtApply inserts a .vas tag between the cell and the pencil ----
// A STRING row alone never exercises that ordering, which is how a position-based pencil lookup slipped through.
function numericScenario(label, name, resolved, typeName, meta, rawTooltip){
  console.log(label);
  const NOTE = 'not yet used on this thread — initial value';
  const ERR = 'THR$GetInstance returned no instance';
  const row = makeRow(name);
  applyValue(name, true, resolved, typeName, true, meta);
  let s = state(row);
  console.log('   after a resolved reply: ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('pencil armed, .vas tag present', s.pencil && siblings(row).includes('vas'));
  // dtApply owns the tooltip for an ORDINARY value and must keep doing so
  if (rawTooltip) check("dtApply's raw tooltip preserved", s.title === rawTooltip, 'title=' + JSON.stringify(s.title));

  applyValue(name, true, resolved, typeName, true, { note: NOTE });
  s = state(row);
  console.log('   after a no-va reply:    ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('stale instance VA cleared', s.va === undefined, 'va=' + s.va);
  check("'editable' cleared", !s.cls.includes('editable'));
  check('edit pencil removed', !s.pencil, 'siblings=[' + siblings(row) + ']');
  // the dotted 'noted' underline is meaningless without the explanation behind it
  check('note survives dtApply in the tooltip', s.title === NOTE, 'title=' + JSON.stringify(s.title));

  applyValue(name, false, null, null, false, { error: ERR });
  s = state(row);
  console.log('   after a failed read:    ' + JSON.stringify(s) + '  siblings=[' + siblings(row) + ']');
  check('edit pencil removed', !s.pencil, 'siblings=[' + siblings(row) + ']');
  check('engine reason in the tooltip', s.title === ERR, 'title=' + JSON.stringify(s.title));
}
numericScenario('5) LONG row (dtApply inserts .vas between the cell and the pencil)',
                'JOB:JOBID', '4711', 'LONG', { va: '0x847B20', typeCode: '0x11', size: 4, places: 0 }, '');
numericScenario('6) DATE row (same ordering, value rendered as a date, raw kept in the tooltip)',
                'TIT:PUBDATE', '80000', 'ULONG', { va: '0x847B40', typeCode: '0x12', size: 4, places: 0 }, 'raw: 80000');

console.log(failures ? `\n${failures} FAILURE(S)` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);

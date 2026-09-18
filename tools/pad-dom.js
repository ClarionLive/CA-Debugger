// Shared test scaffolding for the debugger pad (src/ClarionDebugger.Addin/Terminal/debugger.html).
//
// The pad is a single HTML file that only ever runs inside a WebView2 host in the Clarion IDE, which makes
// every change to it expensive to prove. These helpers pull the page's REAL functions out of the file by
// brace matching and run them against a minimal DOM, so a pad regression can be caught from `node` without
// building the add-in, starting the IDE, or having an engine to talk to.
//
// Deliberately minimal: no HTML parsing (innerHTML is stored, not parsed), no layout, no CSS. It supports
// exactly the DOM surface the page actually uses — enough that a test failure means the PAGE is wrong,
// not that the scaffolding ran out of road.
//
//   const { El, extract, extractConst, makeDocument } = require('./pad-dom');
'use strict';
const fs = require('fs');
const path = require('path');

const DEFAULT_PAGE = path.join(__dirname, '..', 'src', 'ClarionDebugger.Addin', 'Terminal', 'debugger.html');
function readPage(p) { return fs.readFileSync(p || DEFAULT_PAGE, 'utf8'); }

// ---- pull out a top-level `function NAME(` declaration by brace matching
function extract(html, name) {
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

// ---- pull out a single-statement `const NAME = ...;` (e.g. the resume-command table)
function extractConst(html, name) {
  const m = new RegExp('const\\s+' + name + '\\s*=\\s*([^;\\n]+);').exec(html);
  if (!m) throw new Error('not found: const ' + name);
  return 'const ' + name + ' = ' + m[1] + ';';
}

// ---- selectors: `.a.b`, `[data-x]`, `[data-x="v"]`, and combinations of those ----------------------
function dataKey(attr) { return attr.replace(/^data-/, '').replace(/-([a-z])/g, (_, c) => c.toUpperCase()); }
function parseSel(sel) {
  const out = { classes: [], attrs: [] };
  // `[attr="value" i]` — the CSS case-insensitive attribute flag. The page uses it to resolve a row keyed
  // in one spelling from a reply carrying another, so a mini-DOM that ignored the flag would match
  // case-sensitively and report a bug that is not there (or hide one that is).
  const re = /\.([A-Za-z0-9_-]+)|\[([A-Za-z0-9_-]+)(?:\s*=\s*"((?:[^"\\]|\\.)*)")?(\s+[iI])?\]/g;
  let m;
  while ((m = re.exec(sel))) {
    if (m[1]) out.classes.push(m[1]);
    else out.attrs.push({
      name: m[2],
      value: m[3] === undefined ? null : m[3].replace(/\\(.)/g, '$1'),
      ci: !!m[4],
    });
  }
  return out;
}

class ClassList {
  constructor() { this.s = new Set(); }
  add(...c) { c.forEach(x => this.s.add(x)); }
  remove(...c) { c.forEach(x => this.s.delete(x)); }
  contains(c) { return this.s.has(c); }
  toggle(c, on) { if (on === undefined) on = !this.s.has(c); on ? this.s.add(c) : this.s.delete(c); return on; }
  toString() { return [...this.s].join(' '); }
}

class El {
  constructor(tag) {
    this.tag = tag; this.classList = new ClassList(); this.dataset = {}; this.children = [];
    this.parentElement = null; this._text = ''; this.attrs = {}; this.scrollWidth = 10; this.clientWidth = 100;
    this.style = {}; this._html = '';
  }
  // Setting textContent REMOVES the children, as it does in a real DOM. The page relies on exactly that:
  // the in-place value editor does `cell.textContent=''; cell.appendChild(input)` to open and
  // `cell.textContent=old` to close, so a mini-DOM that kept the children left a dead <input> behind and
  // a second edit on the same cell drove the FIRST editor's handlers.
  set textContent(v) { this.children.forEach(c => { c.parentElement = null; }); this.children = []; this._text = String(v); }
  get textContent() { return this._text; }
  getBoundingClientRect() { return { left: 0, top: 0, right: 100, bottom: 20, width: 100, height: 20 }; }
  addEventListener() { }
  focus() { }      // the in-place value editor focuses and selects itself when it opens
  select() { }
  matches(sel) {
    const p = parseSel(sel);
    if (!p.classes.every(c => this.classList.contains(c))) return false;
    return p.attrs.every(a => {
      const v = this.dataset[dataKey(a.name)];
      if (a.value === null) return v !== undefined;
      if (v === undefined) return false;
      return a.ci ? String(v).toLowerCase() === a.value.toLowerCase() : v === a.value;
    });
  }
  walk(fn) { for (const c of this.children) { fn(c); c.walk(fn); } }
  querySelector(sel) {
    for (const c of this.children) { if (c.matches(sel)) return c; const d = c.querySelector(sel); if (d) return d; }
    return null;
  }
  querySelectorAll(sel) { const out = []; this.walk(c => { if (c.matches(sel)) out.push(c); }); return out; }
  // Real appendChild/append, plus the single-arg `append` the older scenarios use.
  appendChild(c) { if (c.parentElement) c.remove(); c.parentElement = this; this.children.push(c); return c; }
  append(...cs) { cs.forEach(c => this.appendChild(c)); }
  insertBefore(node, ref) {
    const i = ref ? this.children.indexOf(ref) : this.children.length;
    this.children.splice(i < 0 ? this.children.length : i, 0, node); node.parentElement = this; return node;
  }
  get nextElementSibling() {
    if (!this.parentElement) return null;
    const i = this.parentElement.children.indexOf(this);
    return this.parentElement.children[i + 1] || null;
  }
  insertAdjacentElement(where, el) {
    const p = this.parentElement; const i = p.children.indexOf(this);
    p.children.splice(where === 'afterend' ? i + 1 : i, 0, el); el.parentElement = p; return el;
  }
  remove() { const p = this.parentElement; if (!p) return; p.children.splice(p.children.indexOf(this), 1); this.parentElement = null; }
  removeAttribute(a) { delete this.attrs[a]; if (a === 'title') this.title = undefined; }
  // No HTML parsing: assigning innerHTML drops the children (which is what the page means by it) and keeps
  // the markup as text so a test can assert on what the page WOULD have rendered.
  set innerHTML(v) { this.children.forEach(c => { c.parentElement = null; }); this.children = []; this._html = String(v); }
  get innerHTML() { return this._html; }
  set className(v) { this.classList = new ClassList(); String(v).split(/\s+/).filter(Boolean).forEach(c => this.classList.add(c)); }
  get className() { return this.classList.toString(); }
  get title() { return this.attrs.title; }
  set title(v) { if (v === undefined) delete this.attrs.title; else this.attrs.title = v; }
}

// A document with a real body to search, plus getElementById backed by a registry the test fills with
// $('someId') — the page reaches most of its fixed furniture that way.
function makeDocument() {
  const body = new El('body');
  const byId = new Map();
  const doc = {
    body,
    createElement: t => new El(t),
    getElementById: id => byId.get(id) || null,
    querySelector: sel => body.querySelector(sel),
    querySelectorAll: sel => body.querySelectorAll(sel),
    // test helper: register (and create on demand) a fixed element the page looks up by id
    id(name) {
      let el = byId.get(name);
      if (!el) { el = new El('div'); el.dataset.id = name; byId.set(name, el); body.appendChild(el); }
      return el;
    },
  };
  return doc;
}

module.exports = { El, ClassList, extract, extractConst, parseSel, makeDocument, readPage, DEFAULT_PAGE };

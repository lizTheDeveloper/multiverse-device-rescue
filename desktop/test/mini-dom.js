// A very small DOM for the renderer tests: elements, attributes, hidden,
// parent/children, and the selectors the renderer uses (tag-less attribute
// and class selectors, comma lists, descendant and child combinators).
// innerHTML is stored as text and never parsed.

function parseSimple(sel) {
  const parts = [];
  const re = /\[([a-z0-9-]+)(?:="([^"]*)")?\]|\.([a-zA-Z0-9_-]+)/g;
  let m;
  while ((m = re.exec(sel))) parts.push(m[3] ? { cls: m[3] } : { attr: m[1], value: m[2] });
  return parts;
}

function matchesSimple(el, sel) {
  return parseSimple(sel).every((p) => (p.cls
    ? String(el.attrs.class || '').split(/\s+/).includes(p.cls)
    : p.attr in el.attrs && (p.value === undefined || el.attrs[p.attr] === p.value)));
}

// "a b", "a > b"
function matchesComplex(el, sel) {
  const tokens = sel.trim().split(/\s+/);
  let i = tokens.length - 1;
  if (!matchesSimple(el, tokens[i])) return false;
  let node = el;
  i -= 1;
  while (i >= 0) {
    if (tokens[i] === '>') {
      node = node.parentNode;
      if (!node || !node.attrs || !matchesSimple(node, tokens[i - 1])) return false;
      i -= 2;
    } else {
      node = node.parentNode;
      while (node && node.attrs && !matchesSimple(node, tokens[i])) node = node.parentNode;
      if (!node || !node.attrs) return false;
      i -= 1;
    }
  }
  return true;
}

function matches(el, selector) {
  return selector.split(',').some((s) => matchesComplex(el, s));
}

class El {
  constructor(doc, tag, attrs) {
    this.ownerDocument = doc;
    this.tagName = tag;
    this.attrs = { ...(attrs || {}) };
    this.children = [];
    this.parentNode = null;
    this.innerHTML = '';
    this.textContent = '';
    this.listeners = {};
  }

  get hidden() { return 'hidden' in this.attrs; }
  set hidden(v) { if (v) this.attrs.hidden = ''; else delete this.attrs.hidden; }
  getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; }
  setAttribute(n, v) { this.attrs[n] = String(v); }
  removeAttribute(n) { delete this.attrs[n]; }
  hasAttribute(n) { return n in this.attrs; }

  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.children.push(child);
    return child;
  }

  insertBefore(child, ref) {
    if (child.parentNode) child.parentNode.removeChild(child);
    const i = this.children.indexOf(ref);
    child.parentNode = this;
    if (i < 0) this.children.push(child); else this.children.splice(i, 0, child);
    return child;
  }

  removeChild(child) {
    const i = this.children.indexOf(child);
    if (i >= 0) this.children.splice(i, 1);
    child.parentNode = null;
    return child;
  }

  add(tag, attrs) {
    return this.appendChild(new El(this.ownerDocument, tag, attrs));
  }

  *walk() {
    for (const c of this.children) {
      yield c;
      yield* c.walk();
    }
  }

  querySelectorAll(sel) { return [...this.walk()].filter((e) => matches(e, sel)); }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }

  closest(sel) {
    let node = this;
    while (node && node.attrs) {
      if (matches(node, sel)) return node;
      node = node.parentNode;
    }
    return null;
  }

  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }

  // Click this element: runs the listeners on it and every ancestor; returns their promises.
  click() {
    const out = [];
    let node = this;
    while (node) {
      for (const fn of node.listeners.click || []) out.push(fn({ target: this }));
      node = node.parentNode;
    }
    return Promise.all(out);
  }
}

function createDocument() {
  const doc = { createElement: (tag) => new El(doc, tag) };
  doc.body = new El(doc, 'body');
  return doc;
}

module.exports = { createDocument, El, matches };

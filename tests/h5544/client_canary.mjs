// H5544 client canary: run the real makeMetricalAnalysis from templates/fulltext.html
// against a MiniDOM shim. Malicious server data must create no elements;
// clean server data must render byte-identical to the old (pre-hardening) behavior.
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const tpl = readFileSync(join(REPO_ROOT, 'templates', 'fulltext.html'), 'utf8');
const m = tpl.match(/async function makeMetricalAnalysis[\s\S]*?\n\}\n/);
if (!m) { console.error('CANARY FAIL: makeMetricalAnalysis not found'); process.exit(1); }
const src = m[0];

// MiniDOM
class El {
  constructor(tag) { this.tagName = tag; this.children = []; this._text = ''; this._html = null; this.style = {}; this.attrs = {}; this.className = ''; this.parses = 0; }
  get classList() { const self = this; return { add: (c) => { self.className = (self.className + ' ' + c).trim(); } }; }
  setAttribute(k, v) { this.attrs[k] = String(v); }
  get role() { return this.attrs.role; }
  set role(v) { this.attrs.role = String(v); }
  set textContent(v) { this._text = String(v); this.children = [{ text: String(v) }]; }
  get textContent() { return this._text; }
  set innerHTML(v) { this.parses++; this._html = String(v); this.children = [{ html: String(v) }]; }
  get innerHTML() { return this._html ?? ''; }
  appendChild(c) { this.children.push(c); return c; }
  // serialization for comparison
  serialize() {
    const attrs = Object.entries(this.attrs).map(([k, v]) => ` ${k}="${v}"`).join('');
    const cls = this.className ? ` class="${this.className}"` : '';
    let inner = '';
    for (const c of this.children) {
      if (c instanceof El) inner += c.serialize();
      else if (c.html !== undefined) inner += c.html;
      else inner += c.text;
    }
    return `<${this.tagName}${cls}${attrs}>${inner}</${this.tagName}>`;
  }
}
const doc = { createElement: (t) => new El(t) };

async function run(res) {
  const v = await eval(`(async () => {
    const document = { createElement: (t) => new El(t) };
    ${src.replace(/await jQueryPostResponse\('\/alignmentAPI', \{verse_text: verseLines, metre_name: metreName\}\)/, "await Promise.resolve({alignment:'', table: res.table || []})")}
    return makeMetricalAnalysis(res);
  })()`);
  return v;
}

// --- Malicious case ---
const malicious = {
  verse: '<img src=x onerror=alert(1)>',
  result: { metre_name: '<script>alert(2)</script>', is_perfect: false },
  table: ['<span class="sylG"><img src=y onerror=alert(3)></span> <br/>\n'],
};
const vm = await run(malicious);
let bad = [];
const metreDiv = vm.children[0];
if (metreDiv.tagName !== 'div' || metreDiv._html !== null) bad.push('metreName used HTML parse');
if (metreDiv.textContent !== 'possibly <script>alert(2)</script>') bad.push('metreName textContent wrong: ' + JSON.stringify(metreDiv.textContent));
if (metreDiv.attrs.role !== 'alert') bad.push('metreName role lost');
const lhs = vm.children[1];
if (lhs._html !== null) bad.push('lhs parsed HTML (innerHTML used)');
if (lhs.textContent !== malicious.verse) bad.push('lhs verse text wrong');
const rhs = vm.children[2];
if (rhs._html === null) bad.push('rhs never received table HTML');
if (rhs.parses !== 1) bad.push('rhs parsed more than once: ' + rhs.parses);

// --- Clean case: must match OLD behavior byte-for-byte ---
const clean = {
  verse: 'atitā yatavadhurvisaḥāir\nanuvēlakṛtair a parādhaśataiḥ',
  result: { metre_name: 'Vanshastha', is_perfect: true },
  table: ['<span class="sylG">a</span><span class="sylL">ti</span> <br/>\n', '<span class="sylL">ta</span><span class="sylG">yā</span> <br/>\n'],
};
const vc = await run(clean);
const metreC = vc.children[0];
const lhsC = vc.children[1];
const rhsC = vc.children[2];
const oldMetre = `<div class="metreName alert alert-success" role="alert">Vanshastha</div>`;
const newMetre = metreC.serialize();
if (newMetre !== oldMetre) bad.push('clean metre DOM differs:\n old=' + oldMetre + '\n new=' + newMetre);
const oldLhs = `<div class="lhsOrig">${clean.verse}</div>`;
if (lhsC.serialize() !== oldLhs) bad.push('clean lhs differs:\n old=' + oldLhs + '\n new=' + lhsC.serialize());
const oldRhs = `<div>${clean.table.join('')}</div>`;
if (rhsC.serialize() !== oldRhs) bad.push('clean rhs differs:\n old=' + oldRhs + '\n new=' + rhsC.serialize());

if (bad.length) { console.error('CLIENT CANARY FAIL'); bad.forEach(b => console.error(' -', b)); process.exit(1); }
console.log('CLIENT CANARY PASS: malicious verse/metre/table create no elements (textContent path, single innerHTML parse of server-authored table); clean-data DOM serialization byte-identical to pre-hardening behavior');
console.log('--- clean serialization:', newMetre, '|', oldLhs, '|', oldRhs.replace(/\n/g, ''));

// Structural checks for the actual wire diagram catalog and topology.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'wire.html'), 'utf8');
function declaration(start, end) {
  const a = html.indexOf(start), b = html.indexOf(end, a);
  assert(a >= 0 && b > a, `Cannot locate ${start}`);
  return html.slice(a, b);
}
const code = declaration('const LAYER_KEVS =', '\n/**') +
  declaration('const LAYER_CONFIG =', '\nconst ASSET_EXPOSURE_CHANCE') +
  '\n;({LAYER_KEVS, LAYER_CONFIG, ALLOWED_CONNECTIONS, EXTERNAL_ENTRY_GROUPS})';
const {LAYER_KEVS, LAYER_CONFIG, ALLOWED_CONNECTIONS, EXTERNAL_ENTRY_GROUPS} = vm.runInNewContext(code);
const groups = new Map();
for (const [layer, config] of LAYER_CONFIG.entries()) {
  for (const cluster of config.clusters) for (const target of cluster.targets) {
    assert(!groups.has(target.id), `Duplicate group ${target.id}`);
    groups.set(target.id, layer);
    assert(fs.existsSync(path.join(root, 'assets/diagram-icons/transparent', target.icon)), `Missing icon for ${target.id}`);
    if (target.kevByVariant) {
      assert.equal(target.kevByVariant.length, target.variants.length, `Variant mappings for ${target.id}`);
      for (const cve of target.kevByVariant.filter(Boolean))
        assert(LAYER_KEVS[layer].some(entry => entry.id === cve), `${target.id}: ${cve} missing from layer catalog`);
    }
  }
}
for (const [source, targets] of Object.entries(ALLOWED_CONNECTIONS)) {
  assert(groups.has(source), `Unknown source ${source}`);
  for (const target of targets) {
    assert(groups.has(target), `Unknown target ${target}`);
    assert.equal(groups.get(target), groups.get(source) + 1, `Non-adjacent connection ${source} -> ${target}`);
  }
}
for (const entry of EXTERNAL_ENTRY_GROUPS) {
  assert.equal(groups.get(entry), 0, `Invalid external entry ${entry}`);
}
console.log(`PASS: ${groups.size} asset groups, variant mappings, icons, connections, and external entries`);

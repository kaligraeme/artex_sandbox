// Optional source parity check: node scripts/verify-threat-vision.cjs <STIX bundle> <Threat Vision sim-engine.js>
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const catalogue = require('../js/gang-techniques.js');
const raw = fs.readFileSync(process.argv[2]);
assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), catalogue.sources.sha256);
const objects = JSON.parse(raw).objects;
const kinds = {'attack-pattern':'technique','intrusion-set':'group',malware:'software',tool:'software',campaign:'campaign'};
const active = object => !object.revoked && !object.x_mitre_deprecated;
const attackId = object => object.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
const byId = new Map(objects.filter(o => kinds[o.type]).map(o => [o.id, {
  id:o.id, attackId:attackId(o), kind:kinds[o.type], name:o.name, active:active(o), platforms:o.x_mitre_platforms || []
}]));
const relationships = objects.filter(r => r.type === 'relationship' && active(r) &&
  byId.get(r.source_ref)?.active && byId.get(r.target_ref)?.active).map(r => ({
    source:r.source_ref, target:r.target_ref, relType:r.relationship_type,
    sourceKind:byId.get(r.source_ref).kind, targetKind:byId.get(r.target_ref).kind
  }));
const model = {domain:'enterprise-attack',byId,
  from:(id,type,kind) => relationships.filter(r => r.source === id && r.relType === type && (!kind || r.targetKind === kind)),
  to:(id,type,kind) => relationships.filter(r => r.target === id && r.relType === type && (!kind || r.sourceKind === kind))
};
const context = {window:{}};
vm.runInNewContext(fs.readFileSync(process.argv[3],'utf8'), context);
for (const [gang,profile] of Object.entries(catalogue.gangs)) {
  const ids = profile.roots.map(id => [...byId.values()].find(o => o.attackId === id).id);
  const result = context.window.SimEngine.analyzeDomain(model,{software:new Set(ids)},
    {viaSoftware:true,viaCampaigns:true,platforms:new Set()});
  const actual = [...result.techniques.values()].map(t => t.tech.attackId).sort();
  assert.deepEqual(actual,Object.keys(profile.techniques).sort(),gang);
  console.log(`PASS Threat Vision parity: ${gang}, ${actual.length} techniques`);
}

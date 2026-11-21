// Structural and behavioral tests for the four-layer exposure engine and wire diagram.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const engine = require('../js/wire-engine.js');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'wire.html'), 'utf8');

// 1. Verify wire.html integration
assert(html.includes('<script src="js/wire-engine.js"></script>'), 'wire.html must load js/wire-engine.js');
assert(html.includes('id="map-profile"'), 'wire.html must include the attacker picker');
assert(!html.includes('id="estate-preset"'), 'Wire should have one estate generator');
assert.deepEqual([...html.matchAll(/data-mode="([^"]+)"/g)].map(match => match[1]),
  ['baseline', 'patch', 'soc', 'combined'], 'Wire must offer the four reference-design defense cards');
const demoAttackers = ['lockbit', 'conti', 'blackcat', 'hive', 'revil', 'solarwinds', 'darkside', 'log4shell', 'cl0p', 'artex'];
const pre2023PatternIds = ['lockbit', 'conti', 'blackcat', 'hive', 'revil', 'solarwinds', 'darkside', 'log4shell', 'cl0p'];
assert(!html.includes('<select id="map-profile"'), 'Attacker selection belongs in the title toggle');
assert.deepEqual([...html.matchAll(/data-attacker="([^"]+)"/g)].map(match => match[1]), ['artex', 'pre2023']);
const patternSelect = html.match(/<select id="pre2023-pattern"[^>]*>([\s\S]*?)<\/select>/)[1];
assert.deepEqual([...patternSelect.matchAll(/<option value="([^\"]+)"/g)].map(match => match[1]), ['rotation', ...pre2023PatternIds]);
assert.match(patternSelect, /<option value="rotation" selected>/, 'Pre-LLM Path dropdown must default to rotation');
for (const patternId of pre2023PatternIds) {
  assert(html.includes(`${patternId}:`), `wire.html pre2023Groups must include ${patternId}`);
  const pattern = engine.PRE2023_ATTACK_PATTERNS[patternId];
  assert(pattern, `PRE2023_ATTACK_PATTERNS must define ${patternId}`);
  assert.equal(pattern.behaviorPreset, 'operator_with_tools');
  assert.equal(pattern.provenanceType, 'historical_source');
  assert(pattern.sourceUrl && pattern.primaryVector && pattern.systemicImpact && pattern.techniques.length > 0);
  for (const cveId of pattern.cveIds) {
    assert(engine.CVE_ATTACK_DESCRIPTIONS[cveId], `Missing CVE description for ${cveId}`);
    assert(engine.KEV_MITIGATION_RULES[cveId]?.waf && engine.KEV_MITIGATION_RULES[cveId]?.ml,
      `Missing explicit KEV_MITIGATION_RULES coverage for ${cveId}`);
  }
}

{
  const catalog = require('../assets/wire-defense-catalog.json');
  assert.equal(catalog.schemaVersion, 1);
  assert.equal(catalog.examples.length, 100);
  assert.equal(new Set(catalog.examples.map(example => example.id)).size, 100);
  assert.equal(Object.keys(catalog.infrastructure).length, 4);
  assert(html.includes('assets/wire-defense-catalog.json'), 'Wire must load the reference catalog');
  for (const example of catalog.examples) {
    assert.match(example.id, /^CVE-\d{4}-\d{4,}$/);
    assert(Object.hasOwn(catalog.infrastructure, example.context));
    assert(example.vendor && example.product && example.techniques.length);
    for (const technique of example.techniques) assert.match(technique, /^T\d{4}(\.\d{3})?$/);
  }
  for (const [id, context] of Object.entries(catalog.infrastructure)) {
    assert.equal(catalog.examples.filter(example => example.context === id).length, 25);
    assert.equal(context.roles.length, 4);
    assert.equal(context.groups.length, 4);
    assert(context.roles[context.focus]);
    const rosters = new Set();
    for (let seed = 1; seed <= 25; seed++) {
      const estate = engine.generateEstate({ preset: 'mixed', seed, preferredIngress: context.groups[0] });
      const before = JSON.stringify(estate);
      const flow = engine.referenceServiceFlow(estate, context.groups);
      assert(flow, `Missing ${id} service flow for seed ${seed}`);
      assert.equal(flow.relationships.length, 3);
      assert.deepEqual(flow.assets.map(assetId => estate.assets.find(asset => asset.id === assetId).groupId), context.groups);
      assert.equal(JSON.stringify(estate), before);
      rosters.add(estate.assets.filter(asset => asset.referenceCve).map(asset => asset.groupId).sort().join());
    }
    assert(rosters.size > 1, `Expected appliance variety for ${id}`);
  }
}

{
  let baselineReads = 0;
  let patchReads = 0;
  let canaryModeReads = 0;
  let socCanaryReads = 0;
  let canaryAlerts = 0;
  let socContainedEvents = 0;
  let logsOpenings = 0;
  const pre2023ReadTimes = new Set();
  const artexReadTimes = new Set();
  for (let seed = 1; seed <= 60; seed++) {
    const estate = engine.generateEstate({ seed, seedExercise: true });
    assert.equal(estate.findings.filter(finding => finding.kind === 'exercise').length, 0, 'No exercise bypass findings');
    assert(estate.defensePosture && Array.isArray(estate.defensePosture.telemetryLayers), 'Estate must carry defensePosture');
    assert(estate.assets.some(asset => asset.isDecoy), 'Mixed estate should include a decoy asset');
    if (estate.findings.some(finding => finding.technique === 'T1552.001')) logsOpenings++;

    const readEvent = (mode, attacker) => engine.simulateWireRun(estate, mode, attacker).events.find(event => {
      const target = estate.assets.find(a => a.id === event.targetId);
      return event.outcome === 'succeeded' && event.grantedCapability === 'data_read' && target?.layerIdx === 3 && !target?.isDecoy;
    });

    const artexBaseline = readEvent('baseline', 'artex');
    if (artexBaseline) {
      baselineReads++;
      const artexMinutes = artexBaseline.timeSec / 60;
      const pre2023Minutes = readEvent('baseline', 'lockbit')?.timeSec / 60;
      assert(artexMinutes >= 45, 'Worker queue may add time beyond the nominal path duration');
      if (pre2023Minutes) {
        assert(pre2023Minutes >= 80);
        pre2023ReadTimes.add(pre2023Minutes);
      }
      artexReadTimes.add(artexMinutes);
    }
    if (readEvent('patch', 'artex')) patchReads++;
    const canariesRun = engine.simulateWireRun(estate, 'canaries', 'artex');
    if (readEvent('canaries', 'artex')) canaryModeReads++;
    if (canariesRun.controls.some(c => c.source === 'canary')) canaryAlerts++;
    assert.equal(canariesRun.controls.filter(c => c.control === 'enforced').length, 0, 'Standalone canaries must not enforce containment');
    assert.equal(canariesRun.summary.containedSessions, 0, 'Standalone canaries must not contain sessions');

    const socRun = engine.simulateWireRun(estate, 'soc', 'lockbit');
    if (socRun.events.some(e => e.outcome === 'suppressed')) socContainedEvents++;

    if (readEvent('soc-canary', 'artex')) socCanaryReads++;
  }
  assert(pre2023ReadTimes.size > 1, 'Pre-2023 timing should vary by estate seed');
  assert(artexReadTimes.size > 1, 'ARTEX timing should vary by estate seed');
  assert(baselineReads >= 35, 'Most seeded estates should demonstrate a baseline data read');
  assert(patchReads > 0 && patchReads < baselineReads, 'Patch coverage should vary across estates');
  assert(canaryAlerts > 0, 'Canaries mode should generate canary alerts when decoys are hit');
  assert.equal(canaryModeReads, baselineReads, 'Standalone canaries alert without blocking data reads');
  assert(socContainedEvents > 0, 'Containment must explain suppressed action effects');
  assert(socCanaryReads < baselineReads, 'SOC + Canary should reduce data reads');
  assert(logsOpenings > 0 && logsOpenings < 60, 'Credential exposure in logs should appear within the mixed estate pool');
}

{
  const estate = engine.generateEstate({ preset: 'demo', seed: 777 });
  const run = (mode, attacker) => engine.simulateWireRun(estate, mode, attacker);
  const read = result => result.events.find(event => event.grantedCapability === 'data_read');
  for (const attacker of demoAttackers) {
    const baseline = run('baseline', attacker);
    // This is an API/CVE demo path, not a guaranteed fit for every gang repertoire.
    if (attacker === 'artex') assert.equal(baseline.summary.dataReached, true);
    assert.equal(baseline.lanes, attacker === 'artex' ? 3 : 1);
    if (attacker !== 'artex') {
      assert.equal(baseline.attackerProfile.gangId, attacker);
      assert.equal(run('patch', attacker).summary.dataReached, false);
    }
    assert.deepEqual(run('baseline', attacker), baseline, 'Replay should keep all event timestamps');
  }
  const enforcement = result => result.controls.find(event => event.control === 'enforced');
  const slow = run('soc', 'lockbit');
  const fast = run('soc', 'artex');
  const early = run('soc-canary', 'artex');
  assert.equal(slow.controls.length, 0, 'Gang stops before a second monitored hop; no boundary signal is fabricated');
  assert(enforcement(fast), 'Actor identity must not disable telemetry');
  assert(enforcement(early));
  const firstSignal = early.controls.find(c => c.control === 'signal');
  const firstDecision = early.controls.find(c => c.control === 'decision');
  assert.equal(firstDecision.timeSec - firstSignal.timeSec, estate.defensePosture.decisionDelaySec);
  assert.equal(enforcement(early).timeSec - firstSignal.timeSec, estate.defensePosture.responseDelaySec);
  const blindEstate = {
    ...estate,
    defensePosture: { telemetryLayers: [], socCoverageSeed: 777, decoys: [] }
  };
  const blindRun = engine.simulateWireRun(blindEstate, 'soc-canary', 'revil');
  assert.equal(blindRun.controls.length, 0);
  assert.equal(blindRun.summary.dataReached, run('baseline', 'revil').summary.dataReached);

  // Defense posture must not depend on attacker gang identity
  const lockbitPostureRun = run('soc-canary', 'lockbit');
  const revilPostureRun = run('soc-canary', 'revil');
  assert.deepEqual(lockbitPostureRun.assumptions.telemetryLayers, revilPostureRun.assumptions.telemetryLayers);
  assert.equal(lockbitPostureRun.assumptions.responseDelaySec, revilPostureRun.assumptions.responseDelaySec);

  const missingPrerequisites = {
    ...estate,
    assets: estate.assets.map(asset => ({ ...asset, conditions: {} }))
  };
  assert.equal(engine.simulateWireRun(missingPrerequisites, 'soc-canary', 'artex').controls.length, 0);
}

for (const profile of ['pre2023', 'artex']) {
  const run = (fixture, defense) =>
    engine.evaluateComparisonRun(fixture, profile, defense, { combineVirtualPatch: true });
  assert.equal(run('speed-race', 'baseline').protectedReadReached, true);
  assert.equal(run('speed-race', 'patch').patchMissed, true);
  assert.equal(run('speed-race', 'soc').protectedReadReached, profile === 'artex');
  const layered = run('speed-race', 'combined');
  assert.equal(layered.protectedReadReached, false);
  assert.equal(layered.signalSource, 'canary');
  for (const stance of ['patch', 'combined']) {
    const covered = run('speed-covered-patch', stance);
    assert.equal(covered.protectedReadReached, false);
    assert.equal(covered.controlReason, 'RULE MATCH · BLOCKED AT EDGE');
    assert.equal(covered.effectiveControlTimeSec, 0);
  }
}

// 2. Structural checks on catalog, variant mappings, icons, connections, and external entries
const { LAYER_KEVS, LAYER_CONFIG, ALLOWED_CONNECTIONS, EXTERNAL_ENTRY_GROUPS } = engine;
const groups = new Map();
for (const [layer, config] of LAYER_CONFIG.entries()) {
  for (const cluster of config.clusters) {
    for (const target of cluster.targets) {
      assert(!groups.has(target.id), `Duplicate group ${target.id}`);
      groups.set(target.id, layer);
      assert(fs.existsSync(path.join(root, 'assets/diagram-icons/transparent', target.icon)), `Missing icon for ${target.id}`);
      if (target.kevByVariant) {
        assert.equal(target.kevByVariant.length, target.variants.length, `Variant mappings for ${target.id}`);
        for (const cve of target.kevByVariant.filter(Boolean)) {
          assert(LAYER_KEVS[layer].some(entry => entry.id === cve), `${target.id}: ${cve} missing from layer catalog`);
        }
      }
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

// Helper to build minimal valid v2 estates for unit tests
function makeEstate(overrides = {}) {
  return {
    schemaVersion: engine.SCHEMA_VERSION,
    seed: 12345,
    preset: 'mixed',
    intentionalPathNote: null,
    assets: [],
    findings: [],
    credentials: [],
    relationships: [],
    actionOrder: [],
    ...overrides
  };
}

function makeAsset(id, groupId, layerIdx, extra = {}) {
  return {
    id,
    groupId,
    label: id,
    product: id,
    assumedVersion: '1.0',
    layerIdx,
    trustZone: ['internet-dmz', 'identity-edge', 'internal-mesh', 'data-tier'][layerIdx],
    interfaces: ['https'],
    auth: 'token',
    isExternalEntry: layerIdx === 0,
    x: 0.1,
    y: 0.5,
    ...extra
  };
}

// 3. Schema validation & legacy snapshot migration
{
  const legacy = engine.migrateSnapshot({ soarSeed: 99, nodes: [], wires: [] });
  assert.equal(legacy.ok, false);
  assert.equal(legacy.legacy, true);

  const badEstate = makeEstate({ findings: [{ id: 'f1', assetId: 'missing', kind: 'cve' }] });
  const v = engine.validateEstate(badEstate);
  assert.equal(v.valid, false);
}

// 4. Negative prerequisite checks: wrong product/version, wrong protocol/direction, healthy asset
{
  const a0 = makeAsset('gw-1', 'ivanti-connect', 0, { product: 'Ivanti', assumedVersion: '22.0', interfaces: ['https'] });
  const a1 = makeAsset('app-1', 'app-engine', 1, { product: 'Spring', assumedVersion: '5.3', interfaces: ['api-https'] });
  const a2 = makeAsset('db-1', 'db-rds', 3, { interfaces: ['db-pg'] });

  const estate = makeEstate({
    assets: [a0, a1, a2],
    findings: [
      // Wrong product
      { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'OtherProduct', affectedVersions: ['22.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'gw-1', targetId: 'app-1', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.summary.succeededTransitions, 0);
  assert.equal(res.summary.ineligibleTransitions, 1);

  // Protocol mismatch + healthy asset
  estate.findings = [
    { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'Ivanti', affectedVersions: ['22.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' }
  ];
  const res2 = engine.simulateEstate(estate, 'baseline');
  assert.equal(res2.summary.succeededTransitions, 1); // gw-1 succeeded
  assert.equal(res2.events.find(e => e.targetId === 'app-1').outcome, 'ineligible');
  assert(res2.events.find(e => e.targetId === 'app-1').reason.includes('Protocol mismatch'));
}

// 5. Credentials: unacquired, wrong-scope, revoked vs valid credential on healthy/patched asset
{
  const a0 = makeAsset('gw-1', 'ivanti-connect', 0);
  const a1 = makeAsset('app-1', 'app-engine', 1, { interfaces: ['api-https'] });
  const a3 = makeAsset('db-1', 'db-rds', 3, { interfaces: ['db-pg'] });

  const base = makeEstate({
    assets: [a0, a1, a3],
    findings: [
      { id: 'f0', assetId: 'gw-1', kind: 'cve', cveId: 'CVE-2023-46805', requiredProduct: 'gw-1', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', yieldsCapability: 'app_exec' },
      { id: 'f1', assetId: 'app-1', kind: 'cve', cveId: 'CVE-2022-22965', requiredProduct: 'app-1', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'api-https', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r01', sourceId: 'gw-1', targetId: 'app-1', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r13', sourceId: 'app-1', targetId: 'db-1', protocol: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });

  // Valid credential acquired on app-1 grants read on healthy db-1 (no CVE on db-1)
  const validCredEstate = {
    ...base,
    credentials: [
      { id: 'c1', kind: 'db_credential', label: 'db-ro', scope: 'read', targetGroupIds: ['db-rds'], targetAssetIds: ['db-1'], revoked: false, mfaRequired: false, sourceAssetId: 'app-1', requiredSourceCapability: 'app_exec' }
    ]
  };
  const okRes = engine.simulateEstate(validCredEstate, 'baseline');
  assert.equal(okRes.summary.dataReached, true);
  assert.equal(okRes.events.find(e => e.targetId === 'db-1').outcome, 'succeeded');

  // Revoked credential stops db-1
  const revokedEstate = {
    ...base,
    credentials: [{ ...validCredEstate.credentials[0], revoked: true }]
  };
  const revRes = engine.simulateEstate(revokedEstate, 'baseline');
  assert.equal(revRes.summary.dataReached, false);

  // Wrong-scope credential (targets other group) stops db-1
  const wrongScopeEstate = {
    ...base,
    credentials: [{ ...validCredEstate.credentials[0], targetGroupIds: ['mssql-db'], targetAssetIds: ['other-db'] }]
  };
  const wsRes = engine.simulateEstate(wrongScopeEstate, 'baseline');
  assert.equal(wsRes.summary.dataReached, false);
}

// 6. Password spray: MFA / rate-limit blocks vs unprotected succeeds; anonymous read needs no CVE
{
  const s3 = makeAsset('public-s3-1', 'public-s3', 0, { interfaces: ['storage-s3'] });
  const idpMfa = makeAsset('iam-idp-1', 'iam-idp', 0, { interfaces: ['https'] });
  const idpOpen = makeAsset('iam-idp-2', 'iam-idp', 0, { interfaces: ['https'] });

  const estate = makeEstate({
    assets: [s3, idpMfa, idpOpen],
    findings: [
      { id: 'f-s3', assetId: 'public-s3-1', kind: 'anonymous_access', technique: 'T1530', yieldsCapability: 'data_read' },
      { id: 'f-mfa', assetId: 'iam-idp-1', kind: 'password_spray', syntheticAccountUsesSprayedPassword: true, mfaProtected: true, rateLimited: false, technique: 'T1110.003', yieldsCapability: 'account_session' },
      { id: 'f-open', assetId: 'iam-idp-2', kind: 'password_spray', syntheticAccountUsesSprayedPassword: true, mfaProtected: false, rateLimited: false, technique: 'T1110.003', yieldsCapability: 'account_session' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.events.find(e => e.targetId === 'public-s3-1').outcome, 'succeeded');
  assert.equal(res.events.find(e => e.targetId === 'iam-idp-1').outcome, 'ineligible');
  assert.equal(res.events.find(e => e.targetId === 'iam-idp-2').outcome, 'succeeded');
}

// 7. Display density does not truncate modeled access.
{
  const src = makeAsset('gw-1', 'ivanti-connect', 0);
  const t1 = makeAsset('t-1', 'cust-api', 1);
  const t2 = makeAsset('t-2', 'cust-api', 1);
  const t3 = makeAsset('t-3', 'cust-api', 1);
  const estate = makeEstate({
    assets: [src, t1, t2, t3],
    findings: [
      { id: 'f0', assetId: 'gw-1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f1', assetId: 't-1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f2', assetId: 't-2', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f3', assetId: 't-3', kind: 'anonymous_access', yieldsCapability: 'app_exec' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'gw-1', targetId: 't-1', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r2', sourceId: 'gw-1', targetId: 't-2', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r3', sourceId: 'gw-1', targetId: 't-3', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  assert.equal(res.summary.layerSuccessCounts[1], 3);
  assert.equal(res.summary.truncated, false);
}

// 8. Seeded determinism, mixed-estate (0-path allowed) vs demo-ready (verified 4-layer path), and 4 defense modes
{
  const e1 = engine.generateEstate({ seed: 42, preset: 'mixed' });
  const e2 = engine.generateEstate({ seed: 42, preset: 'mixed' });
  assert.deepEqual(e1, e2, 'Identical seeds must produce identical estates');
  assert.equal(engine.validateEstate(e1).valid, true);

  const demo = engine.generateEstate({ seed: 777, preset: 'demo' });
  assert.equal(engine.validateEstate(demo).valid, true);
  assert.ok(demo.intentionalPathNote);
  const baseSim = engine.simulateEstate(demo, 'baseline');
  assert.equal(baseSim.summary.completeFourLayerPath, true, 'Demo-ready preset must have a verified 4-layer path');

  for (const mode of ['baseline', 'patch', 'defender', 'combined']) {
    const rA = engine.simulateEstate(demo, mode);
    const rB = engine.simulateEstate(demo, mode);
    assert.deepEqual(rA.summary, rB.summary, `Replay invariance failed for mode ${mode}`);
  }
}

// Mixed estates open with an authenticated, staging-only credential exposure.
{
  const openingKinds = new Set();
  for (const seed of [0, 1, 2]) {
    const estate = engine.generateEstate({ seed, preset: 'mixed' });
    const diagnostics = estate.assets.find(asset => asset.groupId === 'support-diagnostics');
    const status = estate.assets.find(asset => asset.groupId === 'staging-status');
    assert.equal(status.isExternalEntry, false);
    assert(!estate.relationships.some(relationship => relationship.sourceId === status.id));

    const { events } = engine.simulateEstate(estate, 'baseline');
    const opening = events[0];
    openingKinds.add(opening.finding.openingType);
    assert.equal(opening.targetId, diagnostics.id);
    assert.equal(opening.finding.kind, 'diagnostic_access');
    assert.equal(opening.credentialUsed.startingAccess, true);
    assert.equal(opening.grantedCapability, 'diagnostic_read');
    assert.equal(opening.acquiredCredentials.length, 1);
    const [credential] = opening.acquiredCredentials;
    assert.equal(credential.scope, 'staging status only');
    assert.deepEqual(credential.targetAssetIds, [status.id]);
    assert.deepEqual(credential.permissions, ['authenticate']);
    assert.equal(events.find(event => event.targetId === status.id).credentialUsed?.id, credential.id);

    const unauthorizedEstate = { ...estate, credentials: estate.credentials.filter(cred => !cred.startingAccess) };
    const unauthorized = engine.simulateEstate(unauthorizedEstate, 'baseline').events[0];
    assert.equal(unauthorized.outcome, 'ineligible');
    assert.match(unauthorized.reason, /authorized diagnostics viewer/);

    const correctedDiagnostics = { ...diagnostics, conditions: {} };
    const correctedEstate = {
      ...estate,
      assets: estate.assets.map(asset => asset.id === diagnostics.id ? correctedDiagnostics : asset)
    };
    const corrected = engine.simulateEstate(correctedEstate, 'baseline').events;
    assert.equal(corrected[0].outcome, 'ineligible');
    assert.match(corrected[0].reason, /diagnostic exposure is absent/);
    assert(!corrected.some(event => event.targetId === status.id && event.outcome === 'succeeded'));
  }
  assert.deepEqual(openingKinds, new Set(['low_exposure', 'misconfiguration', 'low_vulnerability']));

  const counts = new Map();
  const entryCounts = new Set();
  const dataOutcomes = new Set();
  const applianceFamilies = new Set();
  const applianceCves = new Set();
  const applianceRosters = new Set();
  const misconfigurations = new Set();
  for (let seed = 0; seed < 300; seed++) {
    const estate = engine.generateEstate({ seed, preset: 'mixed' });
    const appliances = estate.assets.filter(asset => asset.referenceCve);
    assert(appliances.length >= 5 && appliances.length <= 7);
    applianceRosters.add(appliances.map(asset => asset.groupId).sort().join());
    for (const asset of appliances) {
      applianceFamilies.add(asset.groupId);
      const finding = estate.findings.find(item => item.assetId === asset.id);
      if (finding) {
        assert.equal(finding.cveId, asset.referenceCve);
        applianceCves.add(finding.cveId);
      } else {
        assert.equal(asset.assumedVersion, null);
      }
    }
    assert(appliances.some(asset => asset.assumedVersion), 'Mixed must model at least one appliance finding');
    const { openingType } = estate.findings.find(finding => finding.kind === 'diagnostic_access');
    counts.set(openingType, (counts.get(openingType) || 0) + 1);
    const { summary, events } = engine.simulateEstate(estate, 'baseline');
    // The original edge-opening budget excludes the new independent workforce branch.
    entryCounts.add(new Set(events.filter(event => event.outcome === 'succeeded' &&
      estate.assets.some(asset => asset.id === event.targetId && asset.layerIdx === 0 && !asset.id.startsWith('windows-')))
      .map(event => event.targetId)).size);
    dataOutcomes.add(summary.dataReached);
    const misconfig = estate.findings.find(item => item.category === 'external_misconfiguration');
    if (misconfig) {
      misconfigurations.add(misconfig.id);
      const asset = estate.assets.find(item => item.id === misconfig.assetId);
      assert(asset.isExternalEntry);
      assert(fs.existsSync(path.join(root, 'assets/diagram-icons/transparent', asset.icon)));
      assert(misconfig.sourceUrl && misconfig.historicalReference);
      const entry = events.find(event => event.targetId === asset.id);
      assert.equal(entry.outcome, 'succeeded');
      const outgoing = estate.relationships.filter(relationship => relationship.sourceId === asset.id);
      assert.equal(outgoing.length, 0);
      if (misconfig.id === 'finding-datadog-proxy') {
        assert.equal(misconfig.illustration, 'git-to-idp');
        assert.equal(entry.grantedCapability, 'file_read');
        assert.equal(entry.acquiredCredentials.length, 0);
      } else {
        assert(['edge_access', 'account_session'].includes(entry.grantedCapability));
      }
    }
  }
  assert.deepEqual([...counts.values()], [100, 100, 100]);
  assert.deepEqual(entryCounts, new Set([2, 3]));
  assert.deepEqual(dataOutcomes, new Set([true, false]));
  assert.equal(applianceFamilies.size, 10);
  assert.equal(applianceCves.size, 10);
  assert(applianceRosters.size > 50);
  assert.equal(misconfigurations.size, 11);
  assert(misconfigurations.has('finding-datadog-proxy'));

  const newMixed = engine.generateEstate({ seed: 42 });
  const legacyMixed = makeEstate({ seed: 42 });
  assert.deepEqual(engine.migrateSnapshot(legacyMixed).estate, newMixed);
  assert.equal(engine.migrateSnapshot(newMixed).estate, newMixed);
  const oldDiagnostics = {
    ...newMixed,
    findings: newMixed.findings.map(finding => {
      if (finding.kind !== 'diagnostic_access') return finding;
      const { openingType, ...previousFinding } = finding;
      return previousFinding;
    })
  };
  assert.deepEqual(engine.migrateSnapshot(oldDiagnostics).estate, newMixed);
  for (const preset of ['demo', 'logs']) {
    const estate = engine.generateEstate({ seed: 42, preset });
    assert(!estate.credentials.some(cred => cred.startingAccess));
    assert(!estate.assets.some(asset => asset.groupId === 'support-diagnostics'));
  }
}

// 9. A source must actually possess the capability required by its connection.
{
  const source = makeAsset('read-only', 'edge', 0);
  const target = makeAsset('target', 'service', 1);
  const relation = { id: 'r', sourceId: source.id, targetId: target.id, direction: 'outbound', protocol: 'https', requiredSourceCapability: 'app_exec' };
  const state = { reachedAssets: new Map([[source.id, { capabilities: new Set(['file_read']) }]]), acquiredCredentials: new Map(), revokedCredentials: new Set() };
  const estate = makeEstate({ assets: [source, target], relationships: [relation], findings: [{ id: 'public', assetId: target.id, kind: 'anonymous_access' }] });
  assert.equal(engine.evaluateAction(state, source, target, relation, estate).eligible, false);
  state.reachedAssets.get(source.id).capabilities.add('app_exec');
  assert.equal(engine.evaluateAction(state, source, target, relation, estate).eligible, true);
}

// 10. Credential authorization is shared by regular access and authenticated CVEs.
{
  const target = makeAsset('db-1', 'db-rds', 3);
  const sibling = makeAsset('db-2', 'db-rds', 3);
  const cred = { id: 'c', label: 'test', scope: 'read', targetAssetIds: ['db-1'], targetGroupIds: ['db-rds'] };
  const state = { reachedAssets: new Map(), acquiredCredentials: new Map([['c', cred]]), revokedCredentials: new Set() };
  const estate = makeEstate({ assets: [target, sibling] });
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false); // not external
  target.isExternalEntry = sibling.isExternalEntry = true;
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, true);
  assert.equal(engine.evaluateAction(state, null, sibling, null, estate).eligible, false);
  for (const attr of ['revoked', 'expired', 'mfaRequired']) {
    cred[attr] = true;
    assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false, attr);
    cred[attr] = false;
  }
  estate.findings = [{ id: 'f', assetId: target.id, kind: 'cve', cveId: 'CVE-TEST', requiredProduct: target.product, affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'https', requiresAuth: true, requiredPermission: 'execute' }];
  assert.notEqual(engine.evaluateAction(state, null, target, null, estate).actionKind, 'cve_authenticated');
  cred.permissions = ['execute']; cred.mfaRequired = true;
  assert.equal(engine.evaluateAction(state, null, target, null, estate).eligible, false);
}

// 11. The canary does not fire for an inaccessible target.
{
  const src = makeAsset('src', 'edge', 0);
  const decoy = makeAsset('decoy', 'db', 3);
  const estate = makeEstate({ assets: [src, decoy], findings: [{ id: 'entry', assetId: src.id, kind: 'anonymous_access', yieldsCapability: 'app_exec' }], relationships: [{ id: 'r', sourceId: src.id, targetId: decoy.id, direction: 'outbound', protocol: 'https', requiredSourceCapability: 'app_exec' }] });
  const event = engine.simulateEstate(estate, 'combined').events.find(e => e.targetId === decoy.id);
  if (event) assert.equal(event.outcome, 'ineligible');
}

// Demo preset must use sourced examples and produce a complete chain under many seeds.
for (let seed = 0; seed < 100; seed++) {
  const estate = engine.generateEstate({ seed, preset: 'demo' });
  assert(estate.findings.filter(f => f.kind === 'cve').every(f => f.sourceUrl && f.sourceReviewed && f.affectedVersions.length));
  assert(engine.simulateEstate(estate, 'baseline').summary.completeFourLayerPath, `demo seed ${seed}`);
}

// 12. Distinct actions against an already reached asset are not collapsed.
{
  const e1 = makeAsset('e1', 'ivanti-connect', 0);
  const e2 = makeAsset('e2', 'f5-gateway', 0);
  const e3 = makeAsset('e3', 'apache-edge', 0);
  const mid = makeAsset('mid', 'cust-api', 1, { interfaces: ['https', 'api-https'] });
  const db = makeAsset('db', 'db-rds', 3, { interfaces: ['db-pg'] });

  const estate = makeEstate({
    assets: [e1, e2, e3, mid, db],
    findings: [
      { id: 'f-e1', assetId: 'e1', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f-e2', assetId: 'e2', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      { id: 'f-e3', assetId: 'e3', kind: 'anonymous_access', yieldsCapability: 'app_exec' },
      // mid has a file_read finding over https AND an app_exec finding over api-https
      { id: 'f-mid-read', assetId: 'mid', kind: 'anonymous_access', yieldsCapability: 'file_read' },
      { id: 'f-mid-exec', assetId: 'mid', kind: 'cve', cveId: 'CVE-2022-29464', requiredProduct: 'mid', affectedVersions: ['1.0'], requiredConditions: {}, sourceUrl: 'https://example.test/advisory', requiredInterface: 'api-https', yieldsCapability: 'app_exec' },
      { id: 'f-db', assetId: 'db', kind: 'anonymous_access', yieldsCapability: 'data_read' }
    ],
    relationships: [
      { id: 'r1', sourceId: 'e1', targetId: 'mid', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r2', sourceId: 'e2', targetId: 'mid', protocol: 'api-https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r3', sourceId: 'e3', targetId: 'mid', protocol: 'https', direction: 'outbound', requiredSourceCapability: 'app_exec' },
      { id: 'r4', sourceId: 'mid', targetId: 'db', protocol: 'db-pg', direction: 'outbound', requiredSourceCapability: 'app_exec' }
    ]
  });
  const res = engine.simulateEstate(estate, 'baseline');
  const midEvents = res.events.filter(e => e.targetId === 'mid');
  assert(midEvents.some(e => e.outcome === 'succeeded' && e.grantedCapability === 'file_read'), 'First visit grants file_read');
  assert(midEvents.some(e => e.outcome === 'succeeded' && e.grantedCapability === 'app_exec'), 'Second distinct action grants app_exec instead of collapsing to revisit');
  assert(midEvents.some(e => e.outcome === 'revisit'), 'Third visit with duplicate capability records revisit');
  assert.equal(res.summary.layerSuccessCounts[1], 1, 'Distinct actions on one asset count once in layerSuccessCounts');
  assert.equal(res.summary.dataReached, true, 'Downstream db reached using newly acquired app_exec capability');
}

// 13. Dedicated credential-in-logs scenario (non-CVE 4-layer path + expired sibling rejection).
for (let seed = 0; seed < 20; seed++) {
  const logsEstate = engine.generateEstate({ seed, preset: 'logs' });
  assert.equal(engine.validateEstate(logsEstate).valid, true);
  assert.equal(logsEstate.preset, 'logs');
  assert.ok(logsEstate.intentionalPathNote.includes('CREDENTIAL-IN-LOGS'));
  assert.equal(logsEstate.findings.filter(f => f.kind === 'cve').length, 0, 'Credential-in-logs scenario requires no CVE');
  const sim = engine.simulateEstate(logsEstate, 'baseline');
  assert.equal(sim.summary.completeFourLayerPath, true, `logs seed ${seed} must complete 4-layer path`);
  assert.equal(sim.summary.dataReached, true);
  if (logsEstate.credentials.some(c => c.expired)) {
    assert(sim.events.some(e => e.outcome === 'ineligible' && /expired/i.test(e.reason)), 'Expired sibling token in logs must be rejected');
  }
}

// 14. Comparison mode: fixed estate, speed timing race, covered patch, capability 45s & denied, and edge cases
{
  const cmpEstate = engine.createComparisonEstate();
  assert.equal(engine.validateEstate(cmpEstate).valid, true, 'Comparison estate must be valid');
  assert.equal(new Set(cmpEstate.assets.map(a => a.layerIdx)).size, 4, 'Comparison estate must span 4 layers');
  assert.ok(cmpEstate.assets.some(a => a.isProtectedRecord), 'Comparison estate must designate protected record');
  assert.ok(cmpEstate.assets.some(a => a.isDecoyAsset), 'Comparison estate must have separate decoy asset');

  // Replay invariance & preserved estate/objective across matrix
  const m1 = engine.evaluateComparisonMatrix('speed-race');
  const m2 = engine.evaluateComparisonMatrix('speed-race');
  assert.deepEqual(m1, m2, 'Comparison matrix evaluation must be deterministic');
  assert.deepEqual(m1.estate, m2.estate);

  // Speed timing race: identical ordered activity across both paces
  const preIds = m1.fixture.traces.pre2023.map(e => e.id);
  const artIds = m1.fixture.traces.artex.map(e => e.id);
  assert.deepEqual(preIds, artIds, 'Speed comparison must use identical ordered attacker activity');

  // Baseline
  assert.equal(m1.cells.pre2023.baseline.protectedReadReached, true);
  assert.equal(m1.cells.pre2023.baseline.protectedReadTimeSec, 105 * 60);
  assert.equal(m1.cells.pre2023.baseline.trace.find(event => event.kind === 'lateral').timeSec, 90 * 60);
  assert.equal(m1.cells.artex.baseline.protectedReadReached, true);
  assert.equal(m1.cells.artex.baseline.trace.find(event => event.kind === 'lateral').timeSec, 15 * 60);
  assert.equal(m1.cells.artex.baseline.protectedReadTimeSec, 15 * 60 + 35);

  // Virtual patch miss (out of scope)
  assert.equal(m1.cells.pre2023.patch.controlReason, 'OUTSIDE RULE COVERAGE');
  assert.equal(m1.cells.pre2023.patch.protectedReadReached, true);
  assert.equal(m1.cells.artex.patch.controlReason, 'OUTSIDE RULE COVERAGE');
  assert.equal(m1.cells.artex.patch.protectedReadReached, true);

  // Agentic SOC: same 60s policy wins at pre2023 pace (+29 min) and loses at artex pace (-10 s)
  const preSoc = m1.cells.pre2023.soc;
  assert.equal(preSoc.telemetryTimeSec, 4500);
  assert.equal(preSoc.decisionTimeSec, 4515);
  assert.equal(preSoc.enforcementTimeSec, 4560);
  assert.equal(preSoc.protectedReadReached, false);
  assert.equal(preSoc.responseMarginSec, 1740); // +29 min
  assert.equal(preSoc.detectionLeadTimeSec, 1800); // +30 min

  const artSoc = m1.cells.artex.soc;
  assert.equal(artSoc.telemetryTimeSec, 885);
  assert.equal(artSoc.decisionTimeSec, 900);
  assert.equal(artSoc.enforcementTimeSec, 945);
  assert.equal(artSoc.protectedReadReached, true);
  assert.equal(artSoc.protectedReadTimeSec, 935);
  assert.equal(artSoc.controlReason, 'CONTAINMENT EFFECTIVE AFTER DATA ACCESS');
  assert.equal(artSoc.responseMarginSec, -10);
  assert.equal(artSoc.detectionLeadTimeSec, 50);
  assert(artSoc.trace.some(e => e.kind === 'containment' && e.timeSec === 945), 'Trace must retain late containment event after objective');

  // Canaries-only: alert only, protected read still occurs
  assert.equal(m1.cells.pre2023.canaries.controlReason, 'DECOY TRIGGERED · ALERT ONLY');
  assert.equal(m1.cells.pre2023.canaries.firstAlertTimeSec, 600);
  assert.equal(m1.cells.pre2023.canaries.detectionLeadTimeSec, 5700);
  assert.equal(m1.cells.pre2023.canaries.responseMarginSec, null);
  assert.equal(m1.cells.pre2023.canaries.protectedReadReached, true);

  assert.equal(m1.cells.artex.canaries.controlReason, 'DECOY TRIGGERED · ALERT ONLY');
  assert.equal(m1.cells.artex.canaries.firstAlertTimeSec, 120);
  assert.equal(m1.cells.artex.canaries.detectionLeadTimeSec, 815);
  assert.equal(m1.cells.artex.canaries.responseMarginSec, null);
  assert.equal(m1.cells.artex.canaries.protectedReadReached, true);

  // Combined: early canary signal + same 60s SOC prevents protected read at both paces
  assert.equal(m1.cells.pre2023.combined.enforcementTimeSec, 660); // 00:11:00
  assert.equal(m1.cells.pre2023.combined.protectedReadReached, false);
  assert.equal(m1.cells.artex.combined.enforcementTimeSec, 180); // 3 min
  assert.equal(m1.cells.artex.combined.protectedReadReached, false);
  assert.equal(m1.cells.artex.combined.signalSource, 'canary');
  assert.equal(m1.cells.artex.combined.responseMarginSec, 755);

  // Removing decoy signal in combined faster run restores late outcome
  const noDecoyCombined = engine.evaluateComparisonRun('speed-race', 'artex', 'combined', { useDecoySignal: false });
  assert.equal(noDecoyCombined.protectedReadReached, true);
  assert.equal(noDecoyCombined.enforcementTimeSec, 945);
  assert.equal(noDecoyCombined.responseMarginSec, -10);

  // Covered virtual patch blocks at both paces
  const covered = engine.evaluateComparisonMatrix('speed-covered-patch');
  for (const p of ['pre2023', 'artex']) {
    assert.equal(covered.cells[p].patch.protectedReadReached, false);
    assert.equal(covered.cells[p].patch.controlReason, 'RULE MATCH · BLOCKED AT EDGE');
    assert.equal(covered.cells[p].patch.effectiveControlTimeSec, 0);
    assert(covered.cells[p].patch.trace.some(ev => ev.isProtectedRead && ev.outcome === 'suppressed'));
    assert.equal(covered.cells[p].combined.firstAlertSource, 'canary');
    assert.equal(covered.cells[p].combined.effectiveControlTimeSec, m1.cells[p].combined.effectiveControlTimeSec);
    assert(!covered.cells[p].combined.trace.some(ev => ev.outcome === 'blocked'));
  }
  const coveredWithoutDecoy = engine.evaluateComparisonRun('speed-covered-patch', 'artex', 'combined', { useDecoySignal: false });
  assert.equal(coveredWithoutDecoy.enforcementTimeSec, covered.cells.artex.soc.enforcementTimeSec);
  assert.equal(coveredWithoutDecoy.protectedReadTimeSec, covered.cells.artex.soc.protectedReadTimeSec);

  // Capability 45s comparison
  const cap = engine.evaluateComparisonMatrix('capability-45s');
  assert.equal(cap.cells.pre2023.baseline.opportunitiesReviewed, 1);
  assert.equal(cap.cells.pre2023.baseline.concurrentReviews, 0);
  assert.equal(cap.cells.pre2023.baseline.manualHandoffs, 1);
  assert.equal(cap.cells.pre2023.baseline.protectedReadReached, false);

  assert.equal(cap.cells.artex.baseline.opportunitiesReviewed, 3);
  assert.equal(cap.cells.artex.baseline.concurrentReviews, 3);
  assert.equal(cap.cells.artex.baseline.manualHandoffs, 1);
  assert.equal(cap.cells.artex.baseline.protectedReadReached, true);
  assert.equal(cap.cells.artex.baseline.protectedReadTimeSec, 30);

  // Capability access-denied case: both end without protected read
  const capDenied = engine.evaluateComparisonMatrix('capability-denied');
  assert.equal(capDenied.cells.pre2023.baseline.protectedReadReached, false);
  assert.equal(capDenied.cells.artex.baseline.protectedReadReached, false);
  assert.equal(capDenied.cells.artex.baseline.opportunitiesReviewed, 3);
  assert.equal(capDenied.cells.artex.baseline.accessDeniedObserved, true);

  for (const defense of ['soc', 'combined']) {
    const denied = capDenied.cells.artex[defense];
    assert.equal(denied.accessDeniedObserved, true);
    assert.equal(denied.controlReason, 'CONTAINMENT PENDING AT CUTOFF');
    assert.equal(denied.scheduledEnforcementTimeSec, 75);
    assert.equal(denied.enforcementTimeSec, null);
    assert.equal(denied.effectiveControlTimeSec, null);
    assert(!denied.trace.some(ev => ev.outcome === 'enforced'));

    const readBeforeCutoff = cap.cells.artex[defense];
    assert.equal(readBeforeCutoff.protectedReadTimeSec, 30);
    assert.equal(readBeforeCutoff.scheduledEnforcementTimeSec, 75);
    assert.equal(readBeforeCutoff.effectiveControlTimeSec, null);
    assert.equal(readBeforeCutoff.responseMarginSec, null);
  }

  // Edge cases: no signal, tie-break at objective, late decoy, untouched decoy, scope mismatch
  const noSig = engine.evaluateComparisonRun('speed-no-signal', 'artex', 'soc');
  assert.equal(noSig.controlReason, 'NO MATCHING SIGNAL');
  assert.equal(noSig.responseMarginSec, null);
  assert.equal(noSig.protectedReadReached, true);

  const tieObj = engine.evaluateComparisonRun('speed-at-objective', 'artex', 'soc');
  assert.equal(tieObj.enforcementTimeSec, 80);
  assert.equal(tieObj.protectedReadReached, true, 'Same-timestamp tie must give objective precedence by default');
  const tieEnf = engine.evaluateComparisonRun('speed-at-objective', 'artex', 'soc', { enforcementPrecedesOnTie: true });
  assert.equal(tieEnf.protectedReadReached, false, 'Explicit enforcementPrecedesOnTie lets containment win');

  const lateDecoy = engine.evaluateComparisonRun('speed-late-decoy', 'artex', 'canaries');
  assert.equal(lateDecoy.detectionLeadTimeSec, -20);
  assert.equal(lateDecoy.protectedReadReached, true);

  const untouchedDecoy = engine.evaluateComparisonRun('speed-untouched-decoy', 'artex', 'canaries');
  assert.equal(untouchedDecoy.controlReason, 'DECOY UNTOUCHED · NO ALERT');
  assert.equal(untouchedDecoy.firstAlertTimeSec, null);
  assert.equal(untouchedDecoy.detectionLeadTimeSec, null);

  const scopeMismatch = engine.evaluateComparisonRun('speed-scope-mismatch', 'pre2023', 'soc');
  assert.equal(scopeMismatch.protectedReadReached, false);
  const unrelated = scopeMismatch.trace.find(e => e.id === 'ev-unrelated');
  assert.ok(unrelated && unrelated.outcome === 'succeeded', 'Scope mismatch must leave unrelated sess-secondary event in progress');
}

console.log(`PASS: ${groups.size} asset groups + prerequisite/credential/budget/replay/logs/comparison tests`);

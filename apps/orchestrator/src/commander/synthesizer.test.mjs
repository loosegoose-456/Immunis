import test from 'node:test';
import assert from 'node:assert/strict';
import { generalizeLiteral, candidatePatterns, fallbackPlan } from './fallback-plan.ts';
import { validateRule, BENIGN_CORPUS } from './mitigation.ts';
import { decide } from './policy.ts';

const briefFor = (payload, overrides = {}) => ({
  incidentId: 'inc_test',
  ip: '203.0.113.9',
  openedAt: 1,
  eventCount: 3,
  events: [{ ip: '203.0.113.9', url: 'https://shield.invalid/login', method: 'POST', payload, timestamp: 1 }],
  classification: { attackClass: 'sqli', severity: 89, confidence: 0.8, indicators: ['tautology'], fingerprint: 'abc', pathTemplate: '/login' },
  classesSeen: ['sqli'],
  threatScore: 120,
  stage: 'block',
  priorIncidents: 0,
  ...overrides,
});

test('generalizeLiteral turns a tautology into a spacing/number-tolerant rule', () => {
  const p = generalizeLiteral("' OR 2=2 --");
  const re = new RegExp(p, 'i');
  assert.ok(re.test("' OR 2=2 --"), 'matches the original');
  assert.ok(re.test("'OR 7 = 7--"), 'matches spacing + different number');
  assert.ok(re.test("' or 1=1 -- "), 'matches lowercased original');
});

test('a rule synthesized from one mutation catches sibling mutations', () => {
  // Blue only ever saw "OR 2=2"; it must still stop "OR 9=9".
  const [pattern] = candidatePatterns(briefFor("username=admin' OR 2=2 -- &password=wrong"));
  const re = new RegExp(pattern, 'i');
  assert.ok(re.test("admin' OR 2=2 -- "));
  assert.ok(re.test("admin' OR 9=9 -- "));
});

test('every synthesized candidate is clean against the benign corpus', () => {
  for (const payload of ["admin' OR 1=1 -- ", "admin' OR 'a'='a' -- ", "x' UNION SELECT 1,2,3 -- ", "admin'/**/OR/**/1=1-- "]) {
    for (const pattern of candidatePatterns(briefFor(payload))) {
      const v = validateRule(pattern, 'i', [payload]);
      assert.ok(v.ok, `pattern ${pattern} from ${payload} must pass: ${v.reasons.join('; ')}`);
      for (const benign of BENIGN_CORPUS) {
        assert.ok(!new RegExp(pattern, 'i').test(benign), `pattern ${pattern} wrongly matched benign: ${benign}`);
      }
    }
  }
});

test('fallbackPlan deploys a synthesized pattern rule and records its working', () => {
  const { plan, steps } = fallbackPlan(briefFor("admin' OR 2=2 -- &password=wrong"), ["admin' OR 2=2 -- "]);
  assert.equal(plan.kind, 'pattern_rule');
  assert.equal(plan.source, 'commander-synthesizer');
  assert.ok(new RegExp(plan.pattern, plan.flags).test("admin' OR 2=2 -- "));
  assert.ok(steps.some((s) => s.tool === 'synthesize'));
  assert.ok(steps.some((s) => s.tool === 'validate' && s.ok));
});

test('fallbackPlan degrades to an IP block when no safe pattern exists', () => {
  const brief = briefFor('', { events: [], classification: { attackClass: 'unknown', severity: 25, confidence: 0.2, indicators: [], fingerprint: 'x', pathTemplate: '/' } });
  const { plan } = fallbackPlan(brief, []);
  assert.equal(plan.kind, 'block_ip');
});

test('the class signature is the last resort, not the first choice', () => {
  // A recognisable tautology should produce a synthesized rule, not the standing signature.
  const { plan } = fallbackPlan(briefFor("admin' OR 8=8 -- &password=wrong"), ["admin' OR 8=8 -- "]);
  assert.equal(plan.source, 'commander-synthesizer');
});

const profile = { ip: '9.9.9.9', firstSeen: 0, lastSeen: 0, score: 0, scoredAt: 0, stage: 'observe', totalEvents: 0, totalIncidents: 0, classesSeen: [] };
const config = { burstThreshold: 3, burstWindowMs: 60000, scoreHalfLifeMs: 600000, incidentIdleTimeoutMs: 120000, analysisCooldownMs: 20000, campaignMinIps: 3, campaignWindowMs: 600000, thresholds: { monitor: 30, challenge: 60, block: 85 } };

test('a single botnet request triggers analysis via the campaign signal', () => {
  // One request, no burst — the only reason to act is that it is part of a campaign.
  const d = decide({
    profile,
    classification: { attackClass: 'sqli', severity: 89, confidence: 0.8, indicators: ['tautology'], fingerprint: 'abc', pathTemplate: '/login' },
    windowEventCount: 1,
    now: 1000,
    config,
    incidentOpen: false,
    campaignDistributed: true,
  });
  assert.equal(d.triggerAnalysis, true);
  assert.ok(d.reasons.some((r) => /distributed campaign/.test(r)));
});

test('without the campaign signal a lone request does not trigger analysis', () => {
  const d = decide({
    profile,
    classification: { attackClass: 'sqli', severity: 89, confidence: 0.8, indicators: ['tautology'], fingerprint: 'abc', pathTemplate: '/login' },
    windowEventCount: 1,
    now: 1000,
    config,
    incidentOpen: false,
    campaignDistributed: false,
  });
  assert.equal(d.triggerAnalysis, false);
});

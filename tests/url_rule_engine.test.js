import { describe, it } from 'node:test';
import assert from 'node:assert';
import { URLParser } from '../core/ml/url_parser.js';
import { URLFeatureExtractor } from '../core/ml/url_features.js';
import { URLRuleEngine } from '../core/rules/url_rule_engine.js';
import { RiskAggregator } from '../core/rules/risk_aggregator.js';

describe('URL Rule Engine & Deterministic Risk Aggregator', () => {
  it('loads valid versioned rule configuration', () => {
    const config = URLRuleEngine.CONFIG;
    assert.strictEqual(config.version, '1.0.0');
    assert.ok(Array.isArray(config.rules));
    assert.strictEqual(config.rules.length, 14);
    assert.ok(config.thresholds.safeMax < config.thresholds.phishingMin);
  });

  it('classifies legitimate apex domains as SAFE with 0 risk score', () => {
    const parsed = URLParser.parse('https://google.com/');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    assert.strictEqual(result.classification, 'SAFE');
    assert.equal(result.outcome, 'UNVERIFIED');
    assert.equal(result.scope, 'URL_STRUCTURE_ONLY');
    assert.equal(result.isPreliminary, true);
    assert.strictEqual(result.verdict, 'SAFE');
    assert.strictEqual(result.explanation.includes('No suspicious'), true);
    assert.ok(result.ruleScore <= 24, `Expected score <= 24, got ${result.ruleScore}`);
    assert.strictEqual(result.rulesTriggered.length, 0);
  });

  it('classifies Wikipedia and standard deep paths as SAFE', () => {
    const parsed = URLParser.parse('https://en.wikipedia.org/wiki/Computer_security');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    assert.strictEqual(result.classification, 'SAFE');
    assert.ok(result.ruleScore <= 24);
  });

  it('triggers URL-RULE-001 (IP_ADDRESS_AS_HOSTNAME) on IP literal', () => {
    const parsed = URLParser.parse('http://192.168.1.1/banking/login');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    const ipRule = result.rulesTriggered.find(r => r.ruleId === 'URL-RULE-001');
    assert.ok(ipRule, 'URL-RULE-001 should trigger on IP address');
    assert.strictEqual(ipRule.weight, 35);
    assert.ok(result.ruleScore >= 35);
    assert.strictEqual(result.verdict, result.classification);
  });

  it('triggers URL-RULE-002 on Punycode/IDN homoglyph domain', () => {
    const parsed = URLParser.parse('https://xn--gogle-pua.com/signin');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    const punyRule = result.rulesTriggered.find(r => r.ruleId === 'URL-RULE-002');
    assert.ok(punyRule, 'URL-RULE-002 should trigger on Punycode domain');
    assert.strictEqual(punyRule.weight, 30);
  });

  it('triggers multiple high-risk rules and classifies banking phish as PHISHING', () => {
    const parsed = URLParser.parse('http://hdfc-netbanking-verify.xyz/login.php?verify=1');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    assert.strictEqual(result.classification, 'PHISHING');
    assert.strictEqual(result.verdict, 'PHISHING');
    assert.ok(result.ruleScore >= 60, `Expected score >= 60, got ${result.ruleScore}`);

    const ruleIds = result.rulesTriggered.map(r => r.ruleId);
    assert.ok(ruleIds.includes('URL-RULE-005') || ruleIds.includes('URL-RULE-006') || ruleIds.includes('URL-RULE-011'),
      'Should trigger brand, keyword, or TLD rules');
  });

  it('returns UNDER_REVIEW when URL feature extraction is incomplete', () => {
    const result = URLRuleEngine.evaluate({}, {});
    assert.strictEqual(result.verdict, 'UNDER_REVIEW');
    assert.strictEqual(result.classification, 'UNDER_REVIEW');
    assert.match(result.explanation, /incomplete|missing/i);
  });

  it('returns UNDER_REVIEW for a warning-level rule result', () => {
    const result = URLRuleEngine.evaluate({}, { has_brand_token_mismatch: 1 });
    assert.strictEqual(result.ruleScore, 25);
    assert.strictEqual(result.verdict, 'UNDER_REVIEW');
  });

  it('triggers URL-RULE-007 on user-info @ symbol injection', () => {
    const parsed = URLParser.parse('http://google.com@attacker-site.com/login');
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);
    const result = URLRuleEngine.evaluate(parsed, ext.features);

    const atRule = result.rulesTriggered.find(r => r.ruleId === 'URL-RULE-007');
    assert.ok(atRule, 'URL-RULE-007 should trigger on @ symbol');
    assert.strictEqual(atRule.severity, 'CRITICAL');
  });

  it('applies anti-correlation category caps deterministically', () => {
    // Artificial mock rules with multiple high structural contributions
    const mockEvaluated = [
      { triggered: true, category: 'STRUCTURE', contribution: 20 },
      { triggered: true, category: 'STRUCTURE', contribution: 25 },
      { triggered: true, category: 'STRUCTURE', contribution: 15 }
    ];
    // Category cap for STRUCTURE is 30
    const config = {
      categoryCaps: { STRUCTURE: 30 },
      thresholds: { safeMax: 24, reviewMax: 59, phishingMin: 60 },
      version: '1.0.0'
    };
    const aggregated = RiskAggregator.aggregate(mockEvaluated, config);

    assert.strictEqual(aggregated.totalUncappedContribution, 60);
    assert.strictEqual(aggregated.score, 30); // Capped at 30
    assert.strictEqual(aggregated.classification, 'UNDER_REVIEW');
  });

  it('ensures score reproducibility (same inputs yield identical scores)', () => {
    const testUrl = 'http://paypal-security-update.top/account/verify';
    const parsed = URLParser.parse(testUrl);
    const ext = URLFeatureExtractor.extract(parsed.normalizedUrl);

    const run1 = URLRuleEngine.evaluate(parsed, ext.features);
    const run2 = URLRuleEngine.evaluate(parsed, ext.features);

    assert.strictEqual(run1.ruleScore, run2.ruleScore);
    assert.strictEqual(run1.classification, run2.classification);
    assert.strictEqual(run1.rulesTriggered.length, run2.rulesTriggered.length);
  });
});

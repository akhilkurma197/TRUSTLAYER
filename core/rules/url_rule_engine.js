/**
 * Trust Layer — Production URL Rule Engine v1.0
 * Evaluates extracted URL features against configured deterministic rules with per-rule accounting.
 * Zero hardcoded domain whitelists. Full transparency and reproducible scores.
 */

import { RiskAggregator } from './risk_aggregator.js';
import RULE_CONFIG from './url_rule_config.json' with { type: 'json' };

export class URLRuleEngine {
  static get CONFIG() {
    return RULE_CONFIG;
  }

  /**
   * Evaluates a URL, its parsed structure, and extracted 28-D features against the rule set.
   * @param {object} parsed Output from URLParser
   * @param {object} features Output from URLFeatureExtractor.extract()
   * @returns {{
   *   ruleScore: number,
   *   classification: 'SAFE' | 'UNDER_REVIEW' | 'PHISHING',
   *   rulesEvaluated: Array<object>,
   *   rulesTriggered: Array<object>,
   *   categoryBreakdown: object,
   *   explanation: string,
   *   configVersion: string,
   *   timestamp: number
   * }}
   */
  static evaluate(parsed = {}, features = {}) {
    if (!features || Object.keys(features).length === 0) {
      return {
        ruleScore: 0,
        classification: 'UNDER_REVIEW',
        verdict: 'UNDER_REVIEW',
        outcome: 'UNVERIFIED', scope: 'URL_STRUCTURE_ONLY', isPreliminary: true,
        provenance: 'URL_RULES', confidenceLevel: 'NONE',
        rulesEvaluated: [],
        rulesTriggered: [],
        categoryBreakdown: {},
        explanation: 'URL feature extraction was incomplete or missing; review required.',
        configVersion: RULE_CONFIG.version,
        timestamp: Date.now()
      };
    }

    const rulesEvaluated = [];

    for (const ruleDef of RULE_CONFIG.rules) {
      const evaluation = this.evaluateSingleRule(ruleDef, parsed, features);
      rulesEvaluated.push(evaluation);
    }

    // Deterministic Aggregation with Category Caps
    const aggregateResult = RiskAggregator.aggregate(rulesEvaluated, RULE_CONFIG);

    // Build plain-language explanation
    const triggered = aggregateResult.triggeredRules;
    let explanation = '';
    if (triggered.length === 0) {
      explanation = 'No suspicious structural, lexical, or obfuscation rules were triggered. URL falls within low-risk threshold.';
    } else {
      const highSeverity = triggered.filter(r => r.severity === 'HIGH' || r.severity === 'CRITICAL');
      if (highSeverity.length > 0) {
        explanation = `Flagged by ${triggered.length} rule(s) including high-severity signals: ${highSeverity.map(r => r.name).join(', ')}.`;
      } else {
        explanation = `Triggered ${triggered.length} minor/warning risk signal(s) totaling ${aggregateResult.score} risk points.`;
      }
    }

    return {
      ruleScore: aggregateResult.score,
      classification: aggregateResult.classification,
      verdict: aggregateResult.classification,
      outcome: aggregateResult.classification === 'PHISHING' || aggregateResult.classification === 'UNDER_REVIEW'
        ? 'SUSPICIOUS' : 'UNVERIFIED',
      scope: 'URL_STRUCTURE_ONLY', isPreliminary: true, provenance: 'URL_RULES', confidenceLevel: 'LOW',
      rulesEvaluated,
      rulesTriggered: triggered,
      categoryBreakdown: aggregateResult.categoryBreakdown,
      explanation,
      configVersion: aggregateResult.configVersion,
      timestamp: Date.now()
    };
  }

  /**
   * Evaluates a single configured rule against the extracted observations.
   */
  static evaluateSingleRule(ruleDef, parsed, features) {
    let triggered = false;
    let observedValue = null;

    switch (ruleDef.id) {
      case 'URL-RULE-001': // IP_ADDRESS_AS_HOSTNAME
        observedValue = features.has_ip_address ?? features.is_ip_address ?? (parsed.isIp ? 1 : 0);
        triggered = observedValue === 1;
        break;

      case 'URL-RULE-002': // PUNYCODE_IDN_HOMOGLYPH
        const puny = features.has_punycode ?? features.is_punycode ?? (parsed.isPunycode ? 1 : 0);
        const homo = features.has_homoglyphs ?? 0;
        observedValue = `punycode=${puny}, homoglyphs=${homo}`;
        triggered = (puny === 1) || (homo === 1);
        break;

      case 'URL-RULE-003': // EXCESSIVE_HOSTNAME_ENTROPY
        observedValue = features.hostname_entropy ?? 0;
        triggered = observedValue > 3.75;
        break;

      case 'URL-RULE-004': // DEEP_SUBDOMAIN_NESTING
        observedValue = features.num_subdomains ?? (parsed.subdomains ? parsed.subdomains.length : 0);
        triggered = observedValue >= 3;
        break;

      case 'URL-RULE-005': // BRAND_TOKEN_IN_UNOFFICIAL_DOMAIN
        observedValue = features.has_brand_token_mismatch ?? features.brand_token_count ?? 0;
        triggered = observedValue === 1 || observedValue > 0;
        break;

      case 'URL-RULE-006': // SENSITIVE_CREDENTIAL_KEYWORDS
        observedValue = features.sensitive_word_count ?? (features.has_sensitive_keyword ? 1 : 0);
        // Requires 2 or more sensitive keywords to avoid false positives on benign words like 'security'
        triggered = observedValue >= 2;
        break;

      case 'URL-RULE-007': // USER_INFO_AT_SYMBOL_INJECTION
        observedValue = features.num_at_symbols ?? 0;
        triggered = observedValue > 0;
        break;

      case 'URL-RULE-008': // EXCESSIVE_URL_LENGTH
        observedValue = features.url_length ?? 0;
        triggered = observedValue > 100;
        break;

      case 'URL-RULE-009': // ELEVATED_DIGIT_RATIO
        observedValue = features.digit_ratio ?? 0;
        triggered = observedValue > 0.22;
        break;

      case 'URL-RULE-010': // EXCESSIVE_HYPHENATION_SPECIAL_CHARS
        const hyphens = features.num_hyphens ?? 0;
        const specRatio = features.special_char_ratio ?? 0;
        const urlLen = features.url_length ?? 0;
        const hasBrandMismatch = (features.has_brand_token_mismatch ?? 0) === 1;
        observedValue = `hyphens=${hyphens}, special_ratio=${specRatio}`;
        // High hyphens (>=3 in host, or >=2 combined with brand token mismatch) or heavy punctuation
        triggered = (hyphens >= 3) || (hyphens >= 2 && hasBrandMismatch) || (specRatio > 0.25 && urlLen > 45);
        break;

      case 'URL-RULE-011': // SUSPICIOUS_REGISTRATION_TLD
        observedValue = features.has_suspicious_tld ?? features.is_suspicious_tld ?? 0;
        triggered = observedValue === 1;
        break;

      case 'URL-RULE-012': // KNOWN_URL_SHORTENER
        observedValue = features.is_url_shortener ?? features.is_shortened ?? 0;
        triggered = observedValue === 1;
        break;

      case 'URL-RULE-013': // NON_STANDARD_HTTP_PORT
        observedValue = parsed.port || 'default';
        triggered = Boolean((features.has_port === 1 || features.has_explicit_port === 1) && parsed.port && parsed.port !== '80' && parsed.port !== '443');
        break;

      case 'URL-RULE-014': // EXCESSIVE_HEX_PERCENT_ENCODING
        observedValue = features.num_percent_encoded ?? 0;
        triggered = (features.num_percent_encoded ?? 0) >= 3;
        break;

      default:
        triggered = false;
        observedValue = 'Not implemented';
    }

    return {
      ruleId: ruleDef.id,
      name: ruleDef.name,
      category: ruleDef.category,
      severity: ruleDef.severity,
      weight: ruleDef.weight,
      triggered,
      contribution: triggered ? ruleDef.weight : 0,
      observedValue,
      explanation: ruleDef.explanation,
      evidenceType: ruleDef.evidenceType
    };
  }

  /**
   * Helper to verify if brand token appears in an authentic brand apex without hardcoded lists.
   */
  static isOfficialBrandApex(hostname = '', detectedBrands = []) {
    if (!hostname || detectedBrands.length === 0) return true;
    const clean = hostname.toLowerCase();
    for (const b of detectedBrands) {
      // Check if domain is apex or sub of official apex, e.g. amazon.in, google.com
      if (clean === `${b}.com` || clean.endsWith(`.${b}.com`) || clean.endsWith(`.${b}.in`) || clean.endsWith(`.${b}.co.in`) || clean.endsWith(`.${b}.org`)) {
        return true;
      }
    }
    return false;
  }
}

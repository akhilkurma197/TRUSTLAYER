/**
 * Trust Layer — Structured Case Schema & Lifecycle State Machine v2.2
 * Single Source of Truth for all investigation telemetry.
 */

export const CASE_STATE = {
  CREATED:              'CREATED',
  NORMALIZING:          'NORMALIZING',
  URL_ANALYSIS:         'URL_ANALYSIS',
  HOST_ANALYSIS:        'HOST_ANALYSIS',
  HTTP_ANALYSIS:        'HTTP_ANALYSIS',
  BROWSER_ANALYSIS:     'BROWSER_ANALYSIS',
  PAGE_ANALYSIS:        'PAGE_ANALYSIS',
  NETWORK_ANALYSIS:     'NETWORK_ANALYSIS',
  ENTITY_ANALYSIS:      'ENTITY_ANALYSIS',
  TRUST_ANALYSIS:       'TRUST_ANALYSIS',
  EVIDENCE_FINALIZATION:'EVIDENCE_FINALIZATION',
  
  // Terminal Lifecycle States
  COMPLETED:            'COMPLETED',
  INCOMPLETE:           'INCOMPLETE',
  FAILED:               'FAILED',
  BLOCKED:              'BLOCKED'
};

export const STAGE = CASE_STATE; // Backward compatibility alias

export const STAGE_STATUS = {
  PENDING:     'PENDING',
  RUNNING:     'RUNNING',
  COMPLETED:   'COMPLETED',
  FAILED:      'FAILED',
  SKIPPED:     'SKIPPED',
  NOT_RUN:     'NOT_RUN'
};

export const MODEL_STATE = {
  MODEL_LEGITIMATE: 'MODEL_LEGITIMATE',
  MODEL_SUSPICIOUS: 'MODEL_SUSPICIOUS',
  MODEL_UNCERTAIN:  'MODEL_UNCERTAIN',
  MODEL_MALFORMED:  'MODEL_MALFORMED'
};

export const VERIFICATION_STATE = {
  EVIDENCE_SUFFICIENT:     'EVIDENCE_SUFFICIENT',
  HIGH_RISK_CONFIRMED:     'HIGH_RISK_CONFIRMED',
  HIGH_RISK_SUSPECTED:     'HIGH_RISK_SUSPECTED',
  LOW_CONFIDENCE_SUSPICION:'LOW_CONFIDENCE_SUSPICION',
  UNVERIFIED:              'UNVERIFIED',
  INVESTIGATION_INCOMPLETE:'INVESTIGATION_INCOMPLETE',
  MODEL_EVIDENCE_CONFLICT: 'MODEL_EVIDENCE_CONFLICT',
  KNOWN_SECURITY_TEST_FIXTURE: 'KNOWN_SECURITY_TEST_FIXTURE',
  PHISHING_LIKE_BEHAVIOUR_DETECTED: 'PHISHING_LIKE_BEHAVIOUR_DETECTED'
};

export const EVIDENCE_PROVENANCE = {
  OBSERVED:  'OBSERVED',  // Directly collected from live network/DOM
  MODEL:     'MODEL',     // Calibrated ML model prediction output
  EXTERNAL:  'EXTERNAL',  // External DNS/WHOIS/registrar lookup
  DERIVED:   'DERIVED',   // Deterministic calculation from observed data
  INFERRED:  'INFERRED',  // Logical deduction from multiple signals
  SIMULATED: 'SIMULATED', // Controlled test-vector sandbox simulation
  OBSERVED_SCREENSHOT_TEXT: 'OBSERVED_SCREENSHOT_TEXT',
  DERIVED_SCREENSHOT_INDICATOR: 'DERIVED_SCREENSHOT_INDICATOR',
  CONFIRMED_CROSS_LAYER: 'CONFIRMED_CROSS_LAYER',
  SCREENSHOT_IMAGE_EMBEDDED: 'SCREENSHOT_IMAGE_EMBEDDED',
  UNKNOWN:   'UNKNOWN'    // Source unavailable or unobservable
};

export const EVIDENCE_TYPE = EVIDENCE_PROVENANCE; // Backward compatibility alias

export function createEmptyCaseSchema(caseId, target, targetType = 'URL') {
  return {
    id: caseId,
    target: target,
    targetType: targetType, // 'URL' | 'QR' | 'UPI'
    
    // Lifecycle & Progress
    status: CASE_STATE.CREATED,
    lifecycleState: 'created',
    currentStage: CASE_STATE.NORMALIZING,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    completedAt: null,
    isDemo: false,
    
    // Stage Execution Coverage Map
    coverage: {
      url:      STAGE_STATUS.PENDING,
      host:     STAGE_STATUS.PENDING,
      http:     STAGE_STATUS.PENDING,
      website:  STAGE_STATUS.NOT_RUN,
      network:  STAGE_STATUS.NOT_RUN,
      identity: STAGE_STATUS.PENDING,
      evidence: STAGE_STATUS.PENDING
    },
    
    // Subsystem Telemetry
    urlAnalysis: {
      rawInput: target,
      normalizedUrl: null,
      protocol: null,
      hostname: null,
      port: null,
      pathname: null,
      query: null,
      fragment: null,
      features: null,
      featureVector: null,
      schemaVersion: 'url_features_v1.0'
    },

    ruleEngineResult: {
      ruleScore: null,
      classification: null, // 'SAFE' | 'UNDER_REVIEW' | 'PHISHING'
      verdict: null,
      rulesTriggered: [],
      rulesEvaluated: [],
      categoryBreakdown: {},
      explanation: null,
      configVersion: null,
      timestamp: null
    },
    captureDelayMs: 10000,
    screenshotCapture: { status: 'NOT_STARTED', captureDelayMs: 10000, countdownStartedAt: null, countdownEndsAt: null, capturedAt: null },
    modeCTimings: null,

    modelResult: {
      modelName: null,
      modelVersion: null,
      prediction: null,
      probabilityPhishing: null,
      probabilityLegitimate: null,
      confidenceLevel: null,
      abstain: false,
      abstainReason: null,
      topContributingFeatures: [],
      evaluatedAt: null
    },

    domainAnalysis: {
      hostname: null,
      registrableDomain: null,
      subdomains: [],
      isIp: false,
      isPunycode: false,
      ipAddresses: [],
      dnsRecords: [],
      reverseDns: null,
      nameservers: [],
      asn: null,
      tlsMetadata: null,
      source: null,
      timestamp: null
    },

    httpAnalysis: {
      status: STAGE_STATUS.PENDING,
      statusCode: null,
      statusText: null,
      initialUrl: null,
      finalUrl: null,
      redirectCount: 0,
      redirectChain: [],
      latencyMs: null,
      headers: {},
      contentType: null,
      responseSize: null,
      serverHeader: null,
      error: null,
      timestamp: null
    },

    pageAnalysis: {
      status: STAGE_STATUS.NOT_RUN,
      title: null,
      headings: [],
      metaDescription: null,
      buttons: [],
      domNodes: 0,
      htmlBytes: 0,
      intent: {
        primary: 'UNKNOWN',
        primaryPageRole: 'UNKNOWN',
        secondary: null,
        confidence: 0,
        claimedPurpose: 'UNKNOWN',
        observedPurpose: 'NOT_OBSERVED',
        purposeMismatch: false,
        mismatchReason: null,
        availableActions: [],
        requiredActions: [],
        requestedActions: [],
        requestedData: []
      },
      dataFlow: [],
      forms: [],
      scripts: [],
      iframes: [],
      links: [],
      externalDomains: [],
      domFingerprint: null,
      screenshotAvailable: false,
      renderStatus: null
    },

    networkAnalysis: {
      status: STAGE_STATUS.NOT_RUN,
      requests: [],
      thirdPartyDomains: [],
      xhrRequests: [],
      formSubmissions: [],
      cookiesObserved: 0,
      storageAttempts: 0
    },

    identityAnalysis: {
      claimedEntity: null,
      observedEntity: null,
      domainEntity: null,
      certificateEntity: null,
      paymentRecipient: null,
      identityContinuity: 'UNKNOWN', // 'MATCH' | 'MISMATCH' | 'UNVERIFIED' | 'UNKNOWN'
      discontinuityReason: null
    },

    trustBreakpoints: [],
    
    // Conflict Detection
    conflictDetected: false,
    conflictReason: null,

    // Multilayer Mode Assessments
    urlRiskAssessment: null,
    redirectAssessment: null, // Mode B
    pageContentAssessment: null, // Mode C
    screenshotIntelligence: null,
    screenshotArtifactUrl: null,
    initialScreenshotUrl: null,
    initialScreenshotEvidenceId: null,
    renderStatus: null, // 'RENDER_COMPLETE' | 'RENDER_PARTIAL' | 'RENDER_TIMEOUT' | 'RENDER_FAILED' | 'ACCESS_DENIED'
    accessStatus: 'NOT_CHECKED', // 'ACCESSIBLE' | 'BLOCKED_HTTP_403' | 'HTTP_ERROR' | 'NO_RESPONSE'
    inspectionStatus: 'NOT_RUN', // separates target access from rendered error-document inspection
    screenshotStatus: 'NOT_CAPTURED',
    overallAssessment: null,

    // Final Synthesized Findings with Evidence Traceability
    assessment: {
      modelState: MODEL_STATE.MODEL_UNCERTAIN,
      verificationState: VERIFICATION_STATE.UNVERIFIED,
      headline: 'Awaiting Investigation Execution',
      summary: '',
      riskLevel: 'UNKNOWN',
      evidenceSufficient: false,
      supporting_evidence_ids: [],
      missing_evidence: [],
      limitations: [],
      reasons: []
    },

    evidence: [],
    timeline: [],
    graph: { nodes: [], edges: [] },
    deceptionPath: null,
    attackStory: [],
    errors: []
  };
}

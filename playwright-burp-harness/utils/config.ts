/**
 * SleepIQ Security Test Configuration
 *
 * Contains all endpoints, test credentials, and known IDs for security testing.
 * IMPORTANT: Do not use real user credentials - use test accounts only.
 */

export const config = {
  // API Endpoints
  endpoints: {
    prod: {
      api: 'https://prod-api.sleepiq.sleepnumber.com',
      web: 'https://sleepiq.sleepnumber.com',
      ecim: 'https://ecim.sleepnumber.com',
      bam: 'https://svcsleepiq.sleepnumber.com',
    },
    stage: {
      api: 'https://stage-api.sleepiq.sleepnumber.com',
      ecim: 'https://ecim-stage.sleepnumber.com',
    },
    qa: {
      api: 'https://qa-api.sleepiq.sleepnumber.com',
      ecim: 'https://ecim-qa.sleepnumber.com',
    },
  },

  // REST API Paths (from api_paths_analysis.md)
  apiPaths: {
    auth: {
      login: '/rest/login',
      jwt: '/rest/user/jwt',
      registration: '/rest/registration',
    },
    bed: {
      list: '/rest/bed',
      status: '/rest/bed/{bedId}/status',
      familyStatus: '/rest/bed/familyStatus',
      pauseMode: '/rest/bed/{bedId}/pauseMode',
      pumpStatus: '/rest/bed/{bedId}/pump/status',
      sleepNumber: '/rest/bed/{bedId}/sleepNumber',
    },
    sleeper: {
      list: '/rest/sleeper',
      profile: '/rest/sleeper/{sleeperId}/profile',
      health: '/rest/sleeper/{sleeperId}/health',
      calibrate: '/rest/sleeper/{sleeperId}/calibrate',
    },
    sleepData: {
      data: '/rest/sleepData',
      sliceData: '/rest/sleepSliceData',
      editedHidden: '/rest/sleepData/editedHidden',
      rolling30Days: '/sn/v1/sleeper/{sleeperId}/sleepData/30DaysRolling',
    },
    foundation: {
      status: '/rest/bed/{bedId}/foundation/status',
      system: '/rest/bed/{bedId}/foundation/system',
      preset: '/rest/bed/{bedId}/foundation/preset',
      outlet: '/rest/bed/{bedId}/foundation/outlet',
      footwarming: '/rest/bed/{bedId}/foundation/footwarming',
    },
    bamkey: {
      command: '/sn/v1/accounts/{accountId}/beds/{bedId}/bamkey',
    },
    account: {
      sleepers: '/rest/accounts/{accountId}/sleepers/{sleeperId}',
      circadian: '/rest/accounts/{accountId}/sleepers/{sleeperId}/circadianRoutines',
    },
  },

  // Legacy BAM Endpoints
  bamPaths: {
    getTime: '/bam/device/getTime.jsp',
    getConfig: '/bam/device/getConfig.jsp',
    getSoftware: '/bam/device/getSoftware.jsp',
  },

  // ECIM Endpoints
  ecimPaths: {
    ping: '/ping',
    health: '/health',
    admin: '/admin',
    internal: '/internal',
    users: '/api/users',
    beds: '/api/beds',
    metrics: '/metrics',
    graphql: '/graphql',
  },

  // Test IDs for IDOR testing (use IDs that look valid but shouldn't belong to test account)
  testIds: {
    // Example ID patterns observed (near Long.MIN_VALUE)
    sleeperIds: [
      '-9223372019953519548',
      '-9223372019953519547',
      '-9223372019953519549',
      '1', '12345', '99999',
    ],
    accountIds: [
      '-9223372019953873048',
      '-9223372019953873047',
      '-9223372019953873049',
      '1', '12345', '99999',
    ],
    bedIds: [
      '-9223372019954024511',
      '-9223372019954024510',
      '-9223372019954024512',
      '1', '12345', '99999',
    ],
  },

  // BAMKey Operations for testing
  bamkeyOps: [
    { key: 'SYCG', name: 'GetSystemConfiguration' },
    { key: 'SPRS', name: 'SetSleepiqPrivacyState' },
    { key: 'SPRG', name: 'GetSleepiqPrivacyState' },
    { key: 'SNCG', name: 'GetSleepNumberControls' },
    { key: 'SNFG', name: 'GetFavoriteSleepNumber' },
    { key: 'ACTG', name: 'GetActuatorPosition' },
    { key: 'AGCP', name: 'GetCurrentPreset' },
  ],

  // Patterns that indicate sensitive data exposure
  sensitivePatterns: {
    // Personal data
    email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    phone: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,

    // Internal data
    stackTrace: /(at\s+[\w.$]+\([\w.]+:\d+\))|(\bat\s+[\w.$/<>]+)/g,
    internalPath: /\/(?:home|usr|var|opt|etc|app|src|internal)\/[\w\/.]+/g,
    sqlError: /(?:SQL|ORA-\d+|mysql|postgresql|sqlite)/gi,
    javaException: /(?:Exception|Error):\s*[\w.]+/g,

    // Credentials
    apiKey: /(?:api[_-]?key|apikey)['":\s]*['"]?[\w-]{20,}['"]?/gi,
    token: /(?:token|bearer|jwt)['":\s]*['"]?[\w-]{20,}['"]?/gi,
    password: /(?:password|passwd|pwd)['":\s]*['"]?[^'"}\s]{4,}['"]?/gi,

    // Debug info
    debugHeader: /x-debug|x-trace|x-internal/gi,
    versionInfo: /(?:version|build)['":\s]*['"]?[\d.]+['"]?/gi,
  },

  // Headers to check for information disclosure
  sensitiveHeaders: [
    'x-amzn-requestid',
    'x-amz-apigw-id',
    'x-amzn-trace-id',
    'x-amzn-errortype',
    'x-debug',
    'x-powered-by',
    'server',
    'x-aspnet-version',
  ],
};

export type Config = typeof config;

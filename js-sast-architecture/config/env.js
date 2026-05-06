/**
 * Environment Configuration Manager
 * Centralized configuration for all environment variables
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const config = {
  // Server Configuration
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV || 'development',

  // Google Gemini API Configuration
  GOOGLE_GEMINI_API_KEY: process.env.GOOGLE_GEMINI_API_KEY || '',

  // Storage Configuration
  STORAGE_DIR: process.env.STORAGE_DIR || './data',
  RULES_DIR: process.env.RULES_DIR || './data/rules',

  // Analysis Configuration
  ANALYSIS_TIMEOUT: parseInt(process.env.ANALYSIS_TIMEOUT || '30000'),
  MAX_CODE_SIZE: parseInt(process.env.MAX_CODE_SIZE || '1000000'),

  // Logging Configuration
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  VERBOSE_LOGGING: process.env.VERBOSE_LOGGING === 'true',

  // Feature Flags
  USE_GEMINI: process.env.USE_GEMINI !== 'false',
  USE_PERSISTENCE: process.env.USE_PERSISTENCE !== 'false',
  USE_ADVANCED_ANALYSIS: process.env.USE_ADVANCED_ANALYSIS !== 'false',
  USE_MONGODB: process.env.USE_MONGODB !== 'false',

  // MongoDB Configuration
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017',
  MONGODB_DB_NAME: process.env.MONGODB_DB_NAME || 'js-sast',
  MONGODB_RULES_COLLECTION: process.env.MONGODB_RULES_COLLECTION || 'security_rules',
  MONGODB_ANALYSIS_COLLECTION: process.env.MONGODB_ANALYSIS_COLLECTION || 'analyses',
};

/**
 * Validate critical configuration
 */
const validateConfig = () => {
  if (!config.GOOGLE_GEMINI_API_KEY) {
    console.warn('GOOGLE_GEMINI_API_KEY not configured in .env. Using fallback local analysis.');
    config.USE_GEMINI = false;
  } else {
    config.USE_GEMINI = true;
  }

  if (config.MAX_CODE_SIZE < 1000) {
    throw new Error('MAX_CODE_SIZE must be at least 1000 bytes');
  }

  if (config.PORT < 1 || config.PORT > 65535) {
    throw new Error('PORT must be between 1 and 65535');
  }
};

module.exports = {
  config,
  validateConfig,
  getConfig: () => config,
  hasGeminiKey: () => !!config.GOOGLE_GEMINI_API_KEY,
  isProduction: () => config.NODE_ENV === 'production',
  isDevelopment: () => config.NODE_ENV === 'development',
};

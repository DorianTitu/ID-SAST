#!/usr/bin/env node

/**
 * JS-SAST Diagnostic Tool
 * Verifies all components are working correctly
 */

const fs = require('fs');
const path = require('path');

console.log('\n JS-SAST DIAGNOSTIC TOOL');
console.log('ïê'.repeat(50));

const checks = {
  passed: [],
  failed: [],
  warnings: []
};

// 1. Check environment
console.log('\n1É£ ENVIRONMENT CHECK');
console.log(''.repeat(50));

try {
  require('dotenv').config();
  
  // Check .env file exists
  const envPath = path.join(__dirname, 'config', '.env');
  if (fs.existsSync(envPath)) {
    console.log(' config/.env exists');
    checks.passed.push('.env file');
  } else {
    console.log(' config/.env not found');
    checks.failed.push('.env file');
  }

  // Check required env variables
  const requiredVars = ['GOOGLE_GEMINI_API_KEY', 'MONGODB_URI'];
  requiredVars.forEach(varName => {
    if (process.env[varName]) {
      console.log(` ${varName} is configured`);
      checks.passed.push(`ENV: ${varName}`);
    } else {
      console.log(`  ${varName} not configured (optional - using defaults)`);
      checks.warnings.push(`${varName} not set`);
    }
  });

  const port = process.env.PORT || 3000;
  console.log(` PORT configured: ${port}`);
  checks.passed.push('PORT');
} catch (error) {
  console.log(' Environment error:', error.message);
  checks.failed.push('Environment setup');
}

// 2. Check dependencies
console.log('\n2É£ DEPENDENCIES CHECK');
console.log(''.repeat(50));

const requiredModules = [
  'express',
  'tree-sitter',
  'tree-sitter-javascript',
  '@google/generative-ai',
  'mongodb',
  'dotenv',
  'swagger-jsdoc',
  'swagger-ui-express'
];

requiredModules.forEach(mod => {
  try {
    require.resolve(mod);
    console.log(` ${mod}`);
    checks.passed.push(`Module: ${mod}`);
  } catch (e) {
    console.log(` ${mod} not installed`);
    checks.failed.push(`Module: ${mod}`);
  }
});

// 3. Check file structure
console.log('\n3É£ FILE STRUCTURE CHECK');
console.log(''.repeat(50));

const requiredFiles = {
  'src/presentation/api/server.js': 'API Server',
  'src/infrastructure/adapters/tree-sitter-adapter.js': 'Tree-Sitter Adapter',
  'src/infrastructure/adapters/graph-builder.js': 'Graph Builder',
  'src/infrastructure/adapters/mongodb-adapter.js': 'MongoDB Adapter',
  'src/infrastructure/adapters/persistence-adapter.js': 'Persistence Adapter',
  'src/domain/services/gemini-service.js': 'Gemini Service',
  'src/domain/models/entities.js': 'Entities',
  'src/application/use-cases/sql-injection-detector.js': 'SQL Detector',
  'src/application/use-cases/xss-detector.js': 'XSS Detector',
  'src/application/use-cases/advanced-analyzer.js': 'Advanced Analyzer',
  'src/application/use-cases/gemini-deep-analyzer.js': 'Gemini Deep Analyzer',
  'config/env.js': 'Config Manager',
  'index.js': 'Entry Point'
};

Object.entries(requiredFiles).forEach(([file, name]) => {
  const fullPath = path.join(__dirname, file);
  if (fs.existsSync(fullPath)) {
    console.log(` ${name}`);
    checks.passed.push(`File: ${name}`);
  } else {
    console.log(` ${name} - NOT FOUND at ${file}`);
    checks.failed.push(`File: ${name}`);
  }
});

// 4. Check API Server methods
console.log('\n4É£ API SERVER METHODS CHECK');
console.log(''.repeat(50));

try {
  const APIServer = require('./src/presentation/api/server');
  const server = new APIServer();
  
  const requiredMethods = ['start', 'createApp', 'initialize', 'analyzeCode'];
  requiredMethods.forEach(method => {
    if (typeof server[method] === 'function') {
      console.log(` ${method}()`);
      checks.passed.push(`Method: ${method}`);
    } else {
      console.log(` ${method}() not found`);
      checks.failed.push(`Method: ${method}`);
    }
  });
} catch (error) {
  console.log(` Error loading APIServer: ${error.message}`);
  checks.failed.push('APIServer initialization');
}

// 5. Check MongoDB Adapter methods
console.log('\n5É£ MONGODB ADAPTER CHECK');
console.log(''.repeat(50));

try {
  const MongoDBAdapter = require('./src/infrastructure/adapters/mongodb-adapter');
  const mongoAdapter = new MongoDBAdapter();
  
  const requiredMethods = [
    'connect',
    'saveRule',
    'getAllRules',
    'getRulesByPattern',
    'getStatistics',
    'exportRules',
    'getStatus'
  ];
  
  requiredMethods.forEach(method => {
    if (typeof mongoAdapter[method] === 'function') {
      console.log(` ${method}()`);
      checks.passed.push(`MongoDB: ${method}`);
    } else {
      console.log(`  ${method}() not found (might be optional)`);
      checks.warnings.push(`MongoDB: ${method}`);
    }
  });
} catch (error) {
  console.log(` Error loading MongoDB Adapter: ${error.message}`);
  checks.failed.push('MongoDB Adapter initialization');
}

// 6. Check Gemini Service methods
console.log('\n6É£ GEMINI SERVICE CHECK');
console.log(''.repeat(50));

try {
  const GeminiService = require('./src/domain/services/gemini-service');
  const gemini = new GeminiService();
  
  const requiredMethods = ['analyze', 'fallbackAnalysis'];
  requiredMethods.forEach(method => {
    if (typeof gemini[method] === 'function') {
      console.log(` ${method}()`);
      checks.passed.push(`Gemini: ${method}`);
    } else {
      console.log(`  ${method}() not found`);
      checks.warnings.push(`Gemini: ${method}`);
    }
  });

  console.log(`Ñπ  Gemini Status: ${gemini.isAvailable ? ' Ready' : '  Fallback mode'}`);
} catch (error) {
  console.log(` Error loading Gemini Service: ${error.message}`);
  checks.failed.push('Gemini Service initialization');
}

// 7. Check Tree-Sitter Adapter
console.log('\n7É£ TREE-SITTER ADAPTER CHECK');
console.log(''.repeat(50));

try {
  const TreeSitterAdapter = require('./src/infrastructure/adapters/tree-sitter-adapter');
  const parser = new TreeSitterAdapter();
  
  if (typeof parser.parse === 'function') {
    console.log(' parse()');
    checks.passed.push('Tree-Sitter: parse');
    
    // Try to parse simple code
    const result = parser.parse('const x = 10;', 'test.js');
    if (result.success) {
      console.log(' Parser works - successfully parsed test code');
      checks.passed.push('Tree-Sitter: functional');
    } else {
      console.log('  Parser returned error:', result.error?.message);
      checks.warnings.push('Tree-Sitter: parsing test failed');
    }
  } else {
    console.log(' parse() method not found');
    checks.failed.push('Tree-Sitter: parse method');
  }
} catch (error) {
  console.log(` Error with Tree-Sitter: ${error.message}`);
  checks.failed.push('Tree-Sitter Adapter');
}

// 8. Check Detectors
console.log('\n8É£ DETECTORS CHECK');
console.log(''.repeat(50));

try {
  const SQLDetector = require('./src/application/use-cases/sql-injection-detector');
  if (typeof SQLDetector === 'function') {
    console.log(' SQLInjectionDetector');
    checks.passed.push('Detector: SQL');
  } else {
    console.log(' SQLInjectionDetector not exported correctly');
    checks.failed.push('Detector: SQL');
  }
} catch (error) {
  console.log(` Error loading SQLInjectionDetector: ${error.message}`);
  checks.failed.push('Detector: SQL');
}

try {
  const XSSDetector = require('./src/application/use-cases/xss-detector');
  if (typeof XSSDetector === 'function') {
    console.log(' XSSDetector');
    checks.passed.push('Detector: XSS');
  } else {
    console.log(' XSSDetector not exported correctly');
    checks.failed.push('Detector: XSS');
  }
} catch (error) {
  console.log(` Error loading XSSDetector: ${error.message}`);
  checks.failed.push('Detector: XSS');
}

try {
  const AdvancedAnalyzer = require('./src/application/use-cases/advanced-analyzer');
  if (typeof AdvancedAnalyzer === 'function') {
    console.log(' AdvancedAnalyzer');
    checks.passed.push('Analyzer: Advanced');
  } else {
    console.log(' AdvancedAnalyzer not exported correctly');
    checks.failed.push('Analyzer: Advanced');
  }
} catch (error) {
  console.log(` Error loading AdvancedAnalyzer: ${error.message}`);
  checks.failed.push('Analyzer: Advanced');
}

// 9. Summary
console.log('\n' + 'ïê'.repeat(50));
console.log(' DIAGNOSTIC SUMMARY');
console.log('ïê'.repeat(50));

console.log(`\n PASSED: ${checks.passed.length}`);
console.log(` FAILED: ${checks.failed.length}`);
console.log(`  WARNINGS: ${checks.warnings.length}`);

if (checks.failed.length > 0) {
  console.log('\n FAILED ITEMS:');
  checks.failed.forEach(item => console.log(`  ¢ ${item}`));
}

if (checks.warnings.length > 0) {
  console.log('\n  WARNINGS:');
  checks.warnings.forEach(item => console.log(`  ¢ ${item}`));
}

const exitCode = checks.failed.length > 0 ? 1 : 0;

console.log('\n' + 'ïê'.repeat(50));

if (exitCode === 0) {
  console.log(' ALL CHECKS PASSED! System ready.');
  console.log('\nTo start the server, run: npm start');
} else {
  console.log(' SOME CHECKS FAILED. Please review errors above.');
}

console.log('ïê'.repeat(50) + '\n');

process.exit(exitCode);

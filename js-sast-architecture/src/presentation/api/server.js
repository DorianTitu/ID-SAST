/**
 * API Server - Presentation Layer
 * Express.js REST API for JS-SAST analysis
 * Routes: AST extraction, Graph generation, Vulnerability detection, Deep learning analysis
 */

const express = require('express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

// Import services from new architecture
const TreeSitterAdapter = require('../../infrastructure/adapters/tree-sitter-adapter');
const GraphBuilder = require('../../infrastructure/adapters/graph-builder');
const PersistenceAdapter = require('../../infrastructure/adapters/persistence-adapter');
const MongoDBAdapter = require('../../infrastructure/adapters/mongodb-adapter');
const GeminiService = require('../../domain/services/gemini-service');

// Import use-cases (vulnerability detection)
const SQLInjectionDetector = require('../../application/use-cases/sql-injection-detector');
const XSSDetector = require('../../application/use-cases/xss-detector');
const AdvancedSecurityAnalyzer = require('../../application/use-cases/advanced-analyzer');

// Import configuration
const { config, validateConfig } = require('../../../config/env');

class APIServer {
  constructor() {
    validateConfig();
    this.parser = new TreeSitterAdapter();
    this.geminiService = new GeminiService();
    this.persistenceAdapter = new PersistenceAdapter(config.RULES_DIR);
    this.mongoAdapter = new MongoDBAdapter();
  }

  /**
   * Initialize database connections
   */
  async initialize() {
    try {
      if (config.USE_MONGODB) {
        const connected = await this.mongoAdapter.connect();
        if (!connected) {
          console.warn('  MongoDB connection failed, falling back to local persistence');
        }
      }
    } catch (error) {
      console.error('Error during initialization:', error.message);
    }
  }

  /**
   * Orchestrate complete analysis pipeline
   */
  analyzeCode(code, filename = 'unknown.js') {
    try {
      const parseResult = this.parser.parse(code, filename);
      if (!parseResult.success) {
        throw new Error(`Parse error: ${parseResult.error.message}`);
      }

      const { ast, metrics } = parseResult.result;

      const graphBuilder = new GraphBuilder(ast);
      const dfg = graphBuilder.buildDFG();
      const cfg = graphBuilder.buildCFG();

      const sqlDetector = new SQLInjectionDetector(ast, code);
      const sqlVulnerabilities = sqlDetector.analyze();

      const xssDetector = new XSSDetector(ast, code);
      const xssVulnerabilities = xssDetector.analyze();

      const allVulnerabilities = [...sqlVulnerabilities, ...xssVulnerabilities];

      return {
        success: true,
        data: {
          filename,
          ast: serializeAST(ast),
          graphs: { dfg, cfg },
          vulnerabilities: allVulnerabilities.map(v => ({
            id: v.id,
            type: v.type,
            severity: v.severity,
            location: v.location,
            message: v.message,
            cweId: v.cweId,
            remediation: v.remediation
          })),
          metrics,
          timestamp: new Date().toISOString()
        },
        message: `Analysis complete. Found ${allVulnerabilities.length} potential vulnerabilities.`
      };
    } catch (error) {
      return {
        success: false,
        data: null,
        error: error.message
      };
    }
  }

  createApp() {
    const app = express();
    app.use(express.json({ limit: '50mb' }));

    // Swagger documentation
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'JS-SAST API',
          version: '2.0.0',
          description: 'JavaScript Static Application Security Testing with Clean Architecture'
        },
        servers: [{ url: `http://localhost:${config.PORT}` }],
        components: {
          schemas: {
            CodeInput: {
              type: 'object',
              properties: {
                code: { type: 'string', description: 'JavaScript code to analyze' },
                filename: { type: 'string', description: 'Optional filename' }
              },
              required: ['code']
            }
          }
        }
      },
      apis: []
    };

    const swaggerSpec = swaggerJsdoc(swaggerOptions);
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

    // ============ HOME ============
    app.get('/', (req, res) => {
      res.json({
        name: 'JS-SAST Analyzer',
        version: '2.0.0',
        description: 'JavaScript Static Application Security Testing',
        architecture: 'Clean Architecture (Presentation/Application/Domain/Infrastructure)',
        gemini_enabled: config.USE_GEMINI && GeminiService.prototype.isAvailable,
        endpoints: {
          'Full Analysis': 'POST /api/analyze',
          'AST Extraction': 'POST /api/ast',
          'Graph Generation': 'POST /api/graphs',
          'Vulnerability Detection': 'POST /api/vulnerabilities',
          'Advanced Analysis': 'POST /api/advanced-analysis',
          'Deep Learning Analysis': 'POST /api/deep-analysis',
          'Rules Statistics': 'GET /api/rules/stats',
          'Export Rules': 'GET /api/rules/export',
          'Pattern Query': 'GET /api/rules/patterns/:patternName',
          'Health Check': 'GET /health',
          'API Documentation': 'GET /api-docs'
        }
      });
    });

    app.get('/health', (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        gemini_available: this.geminiService.isAvailable,
        persistence_enabled: config.USE_PERSISTENCE
      });
    });

    // ============ MAIN ENDPOINTS ============

    // POST /api/analyze - Complete analysis
    app.post('/api/analyze', (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code parameter required' });
        }

        const result = this.analyzeCode(code, filename);
        res.json(result);
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // POST /api/ast - Extract AST only
    app.post('/api/ast', (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code required' });
        }

        const result = this.parser.parse(code, filename || 'analysis.js');
        res.json({
          success: result.success,
          ast: result.success ? serializeAST(result.result.ast) : null,
          metrics: result.success ? result.result.metrics : null,
          error: result.error
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // POST /api/graphs - Generate CFG and DFG
    app.post('/api/graphs', (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code required' });
        }

        const parseResult = this.parser.parse(code, filename || 'analysis.js');
        if (!parseResult.success) {
          return res.json({ success: false, error: parseResult.error, graphs: null });
        }

        const graphBuilder = new GraphBuilder(parseResult.result.ast);
        const dfg = graphBuilder.buildDFG();
        const cfg = graphBuilder.buildCFG();

        res.json({
          success: true,
          graphs: { dfg, cfg },
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // POST /api/vulnerabilities - SQL Injection + XSS detection
    app.post('/api/vulnerabilities', (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code required' });
        }

        const parseResult = this.parser.parse(code, filename || 'analysis.js');
        if (!parseResult.success) {
          return res.json({
            success: false,
            error: parseResult.error,
            vulnerabilities: []
          });
        }

        const sqlDetector = new SQLInjectionDetector(parseResult.result.ast, code);
        const sqlVulnerabilities = sqlDetector.analyze();

        const xssDetector = new XSSDetector(parseResult.result.ast, code);
        const xssVulnerabilities = xssDetector.analyze();

        const allVulnerabilities = [...sqlVulnerabilities, ...xssVulnerabilities];

        res.json({
          success: true,
          vulnerabilities: allVulnerabilities.map(v => ({
            id: v.id,
            type: v.type,
            severity: v.severity,
            location: {
              line: v.location.line,
              column: v.location.column
            },
            message: v.message,
            cweId: v.cweId,
            remediation: v.remediation
          })),
          count: allVulnerabilities.length,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // POST /api/advanced-analysis - DFG + Sanitization + Rules
    app.post('/api/advanced-analysis', (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code required' });
        }

        const parseResult = this.parser.parse(code, filename || 'analysis.js');
        if (!parseResult.success) {
          return res.json({
            success: false,
            error: parseResult.error,
            analysis: null
          });
        }

        const { ast } = parseResult.result;
        const graphBuilder = new GraphBuilder(ast);
        const dfg = graphBuilder.buildDFG();
        const cfg = graphBuilder.buildCFG();

        const advancedAnalyzer = new AdvancedSecurityAnalyzer(ast, cfg, code);
        const analysis = advancedAnalyzer.analyze();

        res.json({
          success: true,
          analysis: {
            vulnerabilities: analysis.vulnerabilities,
            data_flows: analysis.data_flows,
            generated_rules: analysis.generated_rules,
            summary: analysis.summary,
            timestamp: new Date().toISOString()
          }
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // POST /api/deep-analysis - Gemini + Meta-rules
    app.post('/api/deep-analysis', async (req, res) => {
      try {
        const { code, filename } = req.body;
        if (!code) {
          return res.status(400).json({ success: false, error: 'Code required' });
        }

        const parseResult = this.parser.parse(code, filename || 'analysis.js');
        if (!parseResult.success) {
          return res.json({
            success: false,
            error: parseResult.error,
            analysis: null
          });
        }

        const { ast } = parseResult.result;
        const graphBuilder = new GraphBuilder(ast);
        const dfg = graphBuilder.buildDFG();
        const cfg = graphBuilder.buildCFG();

        const advancedAnalyzer = new AdvancedSecurityAnalyzer(ast, cfg, code);
        const advancedAnalysis = advancedAnalyzer.analyze();

        const geminiAnalysis = await this.geminiService.analyze(advancedAnalysis, serializeAST(ast), code);

        // Persist generated rules to MongoDB
        if (this.mongoAdapter.isConnected && geminiAnalysis.analysis && advancedAnalysis.vulnerabilities && advancedAnalysis.vulnerabilities.length > 0) {
          const ruleId = await this.mongoAdapter.saveRule(
            geminiAnalysis.analysis.deep_learning_rule,
            advancedAnalysis.vulnerabilities[0],
            geminiAnalysis.source
          );
          geminiAnalysis.rule_id = ruleId;
          
          // Also save analysis to MongoDB
          await this.mongoAdapter.saveAnalysis({
            code_snippet: code.substring(0, 500),
            vulnerabilities_found: advancedAnalysis.vulnerabilities.length,
            gemini_analysis: geminiAnalysis,
            filename: filename || 'analysis.js'
          });
        } else if (config.USE_PERSISTENCE) {
          // Fallback to local persistence if MongoDB not available
          const ruleId = this.persistenceAdapter.saveRule(
            geminiAnalysis.analysis.deep_learning_rule,
            advancedAnalysis.vulnerabilities[0],
            geminiAnalysis.source
          );
          geminiAnalysis.rule_id = ruleId;
        }

        res.json({
          success: true,
          deep_analysis: {
            advanced_findings: advancedAnalysis,
            gemini_semantic_analysis: geminiAnalysis,
            combined_verdict: {
              vulnerability_confirmed: geminiAnalysis.analysis.vulnerability_detected,
              confidence_score: geminiAnalysis.analysis.confidence_score,
              is_false_positive: geminiAnalysis.analysis.is_false_positive,
              recommendation: geminiAnalysis.analysis.issue
            },
            gemini_source: geminiAnalysis.source,
            storage: this.mongoAdapter.isConnected ? 'mongodb' : 'local'
          }
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // ============ RULES MANAGEMENT (MongoDB) ============

    // GET /api/rules/stats - Knowledge base statistics (MongoDB)
    app.get('/api/rules/stats', async (req, res) => {
      try {
        if (this.mongoAdapter.isConnected) {
          const stats = await this.mongoAdapter.getStatistics();
          res.json({
            success: true,
            storage: 'mongodb',
            statistics: stats
          });
        } else {
          // Fallback to local persistence
          const stats = this.persistenceAdapter.getStatistics();
          res.json({
            success: true,
            storage: 'local',
            statistics: stats
          });
        }
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // GET /api/rules/export - Export rules as JSON (MongoDB)
    app.get('/api/rules/export', async (req, res) => {
      try {
        if (this.mongoAdapter.isConnected) {
          const rules = await this.mongoAdapter.exportRules();
          res.json({
            success: true,
            count: rules.length,
            storage: 'mongodb',
            data: rules
          });
        } else {
          // Fallback
          const filepath = this.persistenceAdapter.exportAsCSV();
          if (filepath) {
            res.download(filepath);
          } else {
            res.status(500).json({ success: false, error: 'Export failed' });
          }
        }
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // GET /api/rules/patterns/:patternName - Query rules by pattern (MongoDB)
    app.get('/api/rules/patterns/:patternName', async (req, res) => {
      try {
        const { patternName } = req.params;
        
        if (this.mongoAdapter.isConnected) {
          const rules = await this.mongoAdapter.getRulesByPattern(patternName);
          res.json({
            success: true,
            storage: 'mongodb',
            pattern: patternName,
            rules: rules,
            count: rules.length
          });
        } else {
          // Fallback
          const rules = this.persistenceAdapter.getRulesByPattern(patternName);
          res.json({
            success: true,
            storage: 'local',
            pattern: patternName,
            rules: rules,
            count: rules.length
          });
        }
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // GET /api/rules/by-type/:vulnerabilityType - Query rules by vulnerability type
    app.get('/api/rules/by-type/:vulnerabilityType', async (req, res) => {
      try {
        const { vulnerabilityType } = req.params;
        let rules = [];
        let storage = 'none';
        
        if (this.mongoAdapter.isConnected) {
          rules = await this.mongoAdapter.getRulesByVulnerabilityType(vulnerabilityType);
          storage = 'mongodb';
        } else {
          rules = this.persistenceAdapter.getRulesByType(vulnerabilityType);
          storage = rules.length > 0 ? 'local' : 'none';
        }
        
        res.json({
          success: true,
          storage: storage,
          vulnerability_type: vulnerabilityType,
          rules: rules,
          count: rules.length
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // GET /api/rules/by-source/:source - Query rules by source (gemini or local_fallback)
    app.get('/api/rules/by-source/:source', async (req, res) => {
      try {
        const { source } = req.params;
        let rules = [];
        let storage = 'none';
        
        if (this.mongoAdapter.isConnected) {
          rules = await this.mongoAdapter.getRulesBySource(source);
          storage = 'mongodb';
        } else {
          rules = this.persistenceAdapter.getRulesBySource(source);
          storage = rules.length > 0 ? 'local' : 'none';
        }
        
        res.json({
          success: true,
          storage: storage,
          source: source,
          rules: rules,
          count: rules.length
        });
      } catch (error) {
        res.status(500).json({ success: false, error: error.message });
      }
    });

    // GET /api/database/status - MongoDB connection status
    app.get('/api/database/status', (req, res) => {
      const mongoStatus = this.mongoAdapter.getStatus();
      
      res.json({
        success: true,
        mongodb: mongoStatus,
        gemini: {
          available: this.geminiService.isAvailable,
          configured: !!config.GOOGLE_GEMINI_API_KEY
        },
        persistence: {
          local_enabled: config.USE_PERSISTENCE,
          mongodb_enabled: config.USE_MONGODB
        },
        timestamp: new Date().toISOString()
      });
    });

    return app;
  }

  start(port = config.PORT) {
    const app = this.createApp();
    
    app.listen(port, async () => {
      console.log(`\nJS-SAST API Server v2.0 (Clean Architecture + MongoDB)`);
      console.log(`Running on http://localhost:${port}`);
      console.log(`Documentation: http://localhost:${port}/api-docs`);
      
      // Initialize MongoDB
      await this.initialize();
      
      console.log(`\nGemini Deep Learning: ${this.geminiService.isAvailable ? 'Enabled' : 'Disabled (using local fallback)'}`);
      console.log(`MongoDB: ${this.mongoAdapter.isConnected ? 'Connected' : 'Not connected (using local persistence)'}`);
      console.log(`Local Persistence: ${config.USE_PERSISTENCE ? 'Enabled (fallback)' : 'Disabled'}`);
      
      console.log(`\nAvailable Endpoints:`);
      console.log(`\nAnalysis:`);
      console.log(`  POST /api/analyze - Full analysis pipeline`);
      console.log(`  POST /api/vulnerabilities - SQL Injection + XSS detection`);
      console.log(`  POST /api/advanced-analysis - DFG + Sanitization detection`);
      console.log(`  POST /api/deep-analysis - Gemini semantic analysis + meta-rules`);
      
      console.log(`\nKnowledge Base (MongoDB):`);
      console.log(`  GET /api/rules/stats - View knowledge base statistics`);
      console.log(`  GET /api/rules/export - Export all rules as JSON`);
      console.log(`  GET /api/rules/patterns/:patternName - Query rules by pattern`);
      console.log(`  GET /api/rules/by-type/:vulnerabilityType - Query by vulnerability type`);
      console.log(`  GET /api/rules/by-source/:source - Query by source (gemini/local_fallback)`);
      
      console.log(`\nSystem:`);
      console.log(`  GET /api/database/status - Database and system status`);
      console.log(`  GET /health - Server health check`);
      console.log(`  GET /api-docs - API documentation`);
      console.log(`  GET / - API information`);
      
      console.log('\n');
    });
  }
}

/**
 * Serialize AST node tree to JSON-compatible format
 */
function serializeAST(node) {
  return {
    id: node.id,
    type: node.type,
    name: node.name,
    line: node.line,
    column: node.column,
    properties: node.properties,
    children: node.children.map(child => serializeAST(child))
  };
}

// Start server if run directly
if (require.main === module) {
  const server = new APIServer();
  server.start();
}

module.exports = APIServer;

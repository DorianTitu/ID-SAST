const express = require('express');
const acorn = require('acorn');
const estraverse = require('estraverse');

const app = express();
app.use(express.json());

/**
 * Analiza código JavaScript y devuelve el AST tal cual lo genera Acorn + estraverse
 */
class JavaScriptAnalyzer {
  analyze(code, filename) {
    try {
      // Parsea con Acorn
      const ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        locations: true,
        ranges: true
      });

      return {
        success: true,
        file: filename,
        language: 'javascript',
        ast: ast,
        error: null
      };
    } catch (err) {
      return {
        success: false,
        file: filename,
        language: 'javascript',
        ast: null,
        error: err.message
      };
    }
  }
}

const analyzer = new JavaScriptAnalyzer();

// Health check
app.get('/health', (req, res) => {
  res.json({
    service: 'javascript-analyzer',
    status: 'ok',
    engine: 'Acorn',
    version: '8.11.0'
  });
});

// Analyze endpoint
app.post('/analyze', (req, res) => {
  const { code, filename = 'unknown.js' } = req.body;

  if (!code) {
    return res.status(400).json({
      error: 'Code is required',
      file: filename,
      language: 'javascript'
    });
  }

  const result = analyzer.analyze(code, filename);
  res.json(result);
});

// Start server
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`JavaScript Analyzer listening on port ${PORT}`);
  console.log(`Parser: Acorn 8.11.0`);
  console.log(`Traverser: estraverse 5.3.0`);
});

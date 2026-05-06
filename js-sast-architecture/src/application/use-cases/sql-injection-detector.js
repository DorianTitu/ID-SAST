/**
 * SQL INJECTION DETECTOR - Tree-Sitter Based
 * Detecta patrones de SQL injection en el código JavaScript
 */

const { VulnerabilityFinding } = require('../../domain/models/entities');

class SQLInjectionDetector {
  constructor(ast, code) {
    this.ast = ast;
    this.code = code;
    this.findings = [];
    this.vulnCounter = 0;
    this.taintedVars = new Set();
  }

  analyze() {
    this.findTaintedVariables();
    this.findSQLInjectionVulnerabilities();
    return this.findings;
  }

  findTaintedVariables() {
    const walk = (node) => {
      if (!node) return;
      
      if (node.type === 'variable_declarator' && node.properties?.varName) {
        const varName = node.properties.varName;
        const nodeText = node.name || '';
        
        if (this.isUntrusted(nodeText)) {
          this.taintedVars.add(varName);
        }
      }
      
      for (let child of (node.children || [])) {
        walk(child);
      }
    };
    
    walk(this.ast);
  }

  isUntrusted(text) {
    const patterns = ['req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies', 'process.env'];
    return patterns.some(p => text && text.includes(p));
  }

  findSQLInjectionVulnerabilities() {
    const walk = (node) => {
      if (!node) return;
      
      const nodeType = node.type || '';

      if (nodeType === 'call_expression') {
        const funcName = node.properties?.function || node.name || '';
        const args = node.properties?.arguments || [];
        
        if (this.isSQLCall(funcName)) {
          for (let arg of args) {
            if (this.hasTaintedVariable(arg)) {
              this.addVuln(node, `SQL Injection: Tainted variable in ${funcName}() call`);
            }
          }
        }
      }
      
      for (let child of (node.children || [])) {
        walk(child);
      }
    };
    
    walk(this.ast);
  }

  isSQLCall(text) {
    const sqlMethods = ['query', 'execute', 'run', 'exec', 'raw', 'sql'];
    return sqlMethods.some(m => text && text.includes(m));
  }

  hasTaintedVariable(arg) {
    for (let varName of this.taintedVars) {
      if (arg && arg.includes(varName)) {
        return true;
      }
    }
    return false;
  }

  addVuln(node, message) {
    const vuln = new VulnerabilityFinding(
      `vuln_${++this.vulnCounter}`,
      'SQL_INJECTION',
      'CRITICAL',
      {
        line: node.line || 0,
        column: node.column || 0,
        astNodeId: node.id
      },
      message
    );
    vuln.cweId = 'CWE-89';
    vuln.remediation = 'Use parameterized queries or prepared statements instead of string concatenation';
    this.findings.push(vuln);
  }
}

module.exports = SQLInjectionDetector;

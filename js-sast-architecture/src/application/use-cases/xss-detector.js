/**
 * XSS DETECTOR - Tree-Sitter Based
 * Detecta patrones de Cross-Site Scripting (XSS)
 * 
 * Reglas:
 * 1. Buscar assignment_expression
 * 2. Verificar si la asignación es a propiedades peligrosas (.innerHTML, .outerHTML, .insertAdjacentHTML)
 * 3. Verificar si el valor proviene de una variable no saneada
 */

const { VulnerabilityFinding } = require('../../domain/models/entities');

class XSSDetector {
  constructor(ast, code) {
    this.ast = ast;
    this.code = code;
    this.findings = [];
    this.vulnerabilityCounter = 0;
    this.dangerousProperties = ['innerHTML', 'outerHTML', 'insertAdjacentHTML'];
    this.unsafeVariables = new Set();
  }

  analyze() {
    this.identifyUnsafeVariables();
    this.detectDOMAssignments();
    return this.findings;
  }

  identifyUnsafeVariables() {
    const traverse = (node) => {
      if (node.type === 'assignment_expression') {
        const left = node.properties?.left || '';
        const right = node.properties?.right || '';

        if (this.isUserControlledInput(right)) {
          const varName = this.extractVariableName(left);
          if (varName) this.unsafeVariables.add(varName);
        }
      }

      for (let child of node.children) {
        traverse(child);
      }
    };

    traverse(this.ast);
  }

  detectDOMAssignments() {
    const traverse = (node) => {
      if (node.type === 'assignment_expression') {
        this.checkDOMAssignment(node);
      }

      for (let child of node.children) {
        traverse(child);
      }
    };

    traverse(this.ast);
  }

  checkDOMAssignment(assignmentNode) {
    const left = assignmentNode.properties?.left || '';
    const right = assignmentNode.properties?.right || '';

    const isDangerousProperty = this.dangerousProperties.some(prop => left.includes(prop));

    if (isDangerousProperty) {
      if (this.isValueUnsafe(right)) {
        this.reportVulnerability(
          assignmentNode,
          'XSS_DOM_ASSIGNMENT',
          `XSS Vulnerability: Unsafe assignment to ${this.extractPropertyName(left)} with unsanitized input`,
          'CRITICAL'
        );
      }
    }
  }

  isValueUnsafe(value) {
    for (let unsafe of this.unsafeVariables) {
      if (value.includes(unsafe)) {
        return true;
      }
    }

    return this.isUserControlledInput(value);
  }

  isUserControlledInput(value) {
    const userInputPatterns = [
      'req.query',
      'req.body',
      'req.params',
      'req.headers',
      'req.cookies',
      'process.env',
      'userInput',
      'input',
      'data',
      'formData',
      'params'
    ];

    return userInputPatterns.some(pattern => value && value.includes(pattern));
  }

  extractVariableName(expression) {
    const match = expression.match(/^(\w+)/);
    return match ? match[1] : null;
  }

  extractPropertyName(expression) {
    const match = expression.match(/\.(\w+)$/);
    return match ? match[1] : 'property';
  }

  reportVulnerability(node, vulnerabilityId, message, severity) {
    const finding = new VulnerabilityFinding(
      `vuln_${++this.vulnerabilityCounter}`,
      'XSS',
      severity,
      {
        line: node.line || 0,
        column: node.column || 0,
        astNodeId: node.id
      },
      message
    );

    finding.vulnerabilityId = vulnerabilityId;
    finding.cweId = 'CWE-79';
    finding.remediation = 'Use textContent instead of innerHTML, or properly sanitize user input using libraries like DOMPurify.';

    this.findings.push(finding);
  }
}

module.exports = XSSDetector;

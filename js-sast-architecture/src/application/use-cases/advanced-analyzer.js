/**
 * ADVANCED SECURITY ANALYZER
 * Data Flow Reconstruction + Contextual Sanitization + Rule Generation
 * 
 * Responsabilidades:
 * 1. Reconstruir flujo de datos (DFG) desde Source a Sink
 * 2. Detectar sanitización en el camino
 * 3. Generar reglas automáticas
 * 4. Normalizar código (ignorar nombres de variables)
 */

class AdvancedSecurityAnalyzer {
  constructor(ast, cfg, code) {
    this.ast = ast;
    this.cfg = cfg;
    this.code = code;
    this.dataFlows = [];
    this.vulnerabilities = [];
    this.generatedRules = [];
    
    this.sourcePatterns = [
      'req.body', 'req.query', 'req.params', 'req.headers', 
      'req.cookies', 'process.env', 'process.argv', 'userInput', 'input'
    ];
    
    this.sinkPatterns = [
      'query', 'execute', 'run', 'exec', 'raw', 'sql', // SQL
      'innerHTML', 'outerHTML', 'insertAdjacentHTML', // XSS
      'eval', 'Function', 'setTimeout', 'setInterval' // Code Injection
    ];
    
    this.sanitizationFunctions = [
      'sanitize', 'escape', 'strip', 'filter', 'validate', 'clean',
      'trim', 'replace', 'encode', 'quote', 'quote_identifier'
    ];
  }

  analyze() {
    this.reconstructDataFlows();
    this.detectVulnerabilities();
    this.generateRules();
    
    return {
      vulnerabilities: this.vulnerabilities,
      data_flows: this.dataFlows,
      generated_rules: this.generatedRules,
      summary: this.generateSummary()
    };
  }

  /**
   * PASO 1: Data Flow Reconstruction (DFG)
   * Rastrea datos desde Source a Sink
   */
  reconstructDataFlows() {
    const variables = {};
    const flowPaths = [];

    const walkAST = (node, path = []) => {
      if (!node) return;

      // Identificar assignments
      if (node.type === 'variable_declarator' && node.properties?.varName) {
        const varName = node.properties.varName;
        const nodeText = node.name || '';
        
        // Detectar si la asignación incluye una función de sanitización
        const hasSanitizationWrapper = this.sanitizationFunctions.some(func =>
          nodeText.toLowerCase().includes(func.toLowerCase())
        );
        
        variables[varName] = {
          name: varName,
          nodeId: node.id,
          source: nodeText,
          isUntrusted: this.isSource(nodeText),
          sanitized: hasSanitizationWrapper,
          sanitizationFunctions: hasSanitizationWrapper ? 
            this.sanitizationFunctions.filter(func => nodeText.toLowerCase().includes(func.toLowerCase())) : [],
          line: node.line,
          column: node.column
        };
      }

      // Identificar calls
      if (node.type === 'call_expression') {
        const funcName = node.properties?.function || node.name || '';
        const args = node.properties?.arguments || [];

        // Buscar si es un Sink
        if (this.isSink(funcName)) {
          // Verificar argumentos por tainted variables
          for (let arg of args) {
            const taintedVars = this.extractVariablesFromArg(arg);
            
            for (let taintedVar of taintedVars) {
              if (variables[taintedVar]) {
                const flowPath = this.buildFlowPath(variables[taintedVar], node, funcName);
                flowPaths.push(flowPath);
              }
            }
          }
        }
      }

      // DFS recursivo
      for (let child of (node.children || [])) {
        walkAST(child, [...path, node.id]);
      }
    };

    walkAST(this.ast);
    this.dataFlows = flowPaths;
  }

  /**
   * PASO 2: Detectar Vulnerabilidades + Sanitización
   */
  detectVulnerabilities() {
    for (let flow of this.dataFlows) {
      const hasSanitization = this.checkSanitizationInPath(flow);
      const confidence = this.calculateConfidence(flow, hasSanitization);
      
      const vulnerability = {
        vulnerability_confirmed: !hasSanitization,
        status: hasSanitization ? 'MITIGATED' : 'VULNERABLE',
        data_path: flow.path,
        source: flow.source,
        sink: flow.sink,
        source_line: flow.sourceLine,
        sink_line: flow.sinkLine,
        confidence_score: confidence,
        sanitization_detected: hasSanitization,
        sanitization_functions: flow.sanitizationFunctions || [],
        vulnerability_type: flow.vulnerabilityType,
        cwe_id: this.getCWE(flow.vulnerabilityType),
        tainted_variable: flow.taintedVar,
        recommendation: this.getRecommendation(hasSanitization)
      };
      
      this.vulnerabilities.push(vulnerability);
    }
  }

  /**
   * PASO 3: Rule Autogeneration
   * Genera reglas en formato JSON para reinsertar en el motor
   */
  generateRules() {
    const ruleLookup = {};

    for (let vuln of this.vulnerabilities) {
      const patternKey = `${vuln.source}_to_${vuln.sink}`;
      
      if (!ruleLookup[patternKey]) {
        const rule = {
          rule_id: `RULE_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          name: `${vuln.vulnerability_type}_pattern`,
          description: `Detects ${vuln.vulnerability_type} when ${vuln.source} flows to ${vuln.sink}`,
          vulnerability_type: vuln.vulnerability_type,
          patterns: {
            source: this.normalizePattern(vuln.source),
            sink: this.normalizePattern(vuln.sink),
            data_flow: {
              type: 'VARIABLE_ASSIGNMENT',
              from: 'UNTRUSTED_SOURCE',
              to: 'SINK_FUNCTION'
            }
          },
          severity: this.calculateSeverity(vuln.confidence_score),
          conditions: [
            {
              type: 'data_source',
              patterns: this.sourcePatterns,
              logic: 'OR'
            },
            {
              type: 'variable_taint',
              property: 'isUntrusted',
              value: true
            },
            {
              type: 'no_sanitization',
              property: 'sanitizationFunctions',
              condition: 'NOT_EXISTS'
            }
          ],
          remediation: [
            'Use parameterized queries for SQL',
            'Use textContent instead of innerHTML',
            'Implement input validation and sanitization',
            'Use security libraries like DOMPurify'
          ],
          cwe_id: vuln.cwe_id,
          cvss_base_score: this.calculateCVSS(vuln.confidence_score),
          examples: {
            vulnerable: this.generateVulnerableExample(vuln),
            safe: this.generateSafeExample(vuln)
          }
        };
        
        ruleLookup[patternKey] = rule;
        this.generatedRules.push(rule);
      }
    }
  }

  /**
   * Helper Methods
   */

  isSource(text) {
    return this.sourcePatterns.some(p => text && text.includes(p));
  }

  isSink(text) {
    return this.sinkPatterns.some(s => text && text.includes(s));
  }

  extractVariablesFromArg(arg) {
    const matches = arg.match(/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/g) || [];
    return [...new Set(matches)];
  }

  buildFlowPath(sourceVar, sinkNode, sinkFunc) {
    const vulnType = this.classifyVulnerability(sinkFunc);
    
    return {
      source: sourceVar.source,
      sourceLine: sourceVar.line,
      sink: sinkFunc,
      sinkLine: sinkNode.line,
      taintedVar: sourceVar.name,
      vulnerabilityType: vulnType,
      path: [
        { type: 'SOURCE', value: sourceVar.source, nodeId: sourceVar.nodeId },
        { type: 'VARIABLE_ASSIGNMENT', value: sourceVar.name, nodeId: sourceVar.nodeId },
        { type: 'SINK', value: sinkFunc, nodeId: sinkNode.id }
      ],
      sanitizationFunctions: sourceVar.sanitizationFunctions || [],
      sanitized: sourceVar.sanitized || false
    };
  }

  checkSanitizationInPath(flow) {
    // Verificar si la variable fue sanitizada en su asignación
    if (flow.sanitized || flow.sanitizationFunctions.length > 0) {
      return true;
    }
    
    // Verificar en el path completo como fallback
    const pathText = JSON.stringify(flow.path);
    return this.sanitizationFunctions.some(func => 
      pathText.toLowerCase().includes(func.toLowerCase())
    );
  }

  calculateConfidence(flow, hasSanitization) {
    if (hasSanitization) return 25; // Menor confianza si hay sanitización
    return 95; // Alta confianza si no hay
  }

  calculateSeverity(confidence) {
    if (confidence >= 90) return 'CRITICAL';
    if (confidence >= 70) return 'HIGH';
    if (confidence >= 50) return 'MEDIUM';
    return 'LOW';
  }

  calculateCVSS(confidence) {
    // Simplified CVSS scoring
    if (confidence >= 90) return 9.8;
    if (confidence >= 70) return 7.5;
    if (confidence >= 50) return 5.3;
    return 3.7;
  }

  classifyVulnerability(sink) {
    if (sink.includes('query') || sink.includes('execute') || sink.includes('sql')) {
      return 'SQL_INJECTION';
    }
    if (sink.includes('innerHTML') || sink.includes('outerHTML')) {
      return 'XSS';
    }
    if (sink.includes('eval') || sink.includes('Function')) {
      return 'CODE_INJECTION';
    }
    return 'INJECTION';
  }

  getCWE(vulnType) {
    const cweMap = {
      'SQL_INJECTION': 'CWE-89',
      'XSS': 'CWE-79',
      'CODE_INJECTION': 'CWE-95'
    };
    return cweMap[vulnType] || 'CWE-94';
  }

  normalizePattern(pattern) {
    // Remove variable names, keep structure
    return pattern
      .replace(/[a-zA-Z_$][a-zA-Z0-9_$]*/g, 'VAR')
      .replace(/\d+/g, 'NUM')
      .replace(/["'`]/g, 'STR');
  }

  getRecommendation(sanitized) {
    if (sanitized) {
      return 'Vulnerability appears to be mitigated. Verify sanitization function is effective.';
    }
    return 'Critical: Implement input validation and sanitization immediately.';
  }

  generateVulnerableExample(vuln) {
    return `const data = ${vuln.source}; 
${vuln.sink}("SELECT * FROM users WHERE id=" + data);`;
  }

  generateSafeExample(vuln) {
    return `const data = sanitize(${vuln.source}); 
${vuln.sink}("SELECT * FROM users WHERE id=?", [data]);`;
  }

  generateSummary() {
    const total = this.vulnerabilities.length;
    const vulnerable = this.vulnerabilities.filter(v => !v.sanitization_detected).length;
    const mitigated = total - vulnerable;
    
    return {
      total_flows_analyzed: total,
      vulnerable_flows: vulnerable,
      mitigated_flows: mitigated,
      average_confidence: Math.round(
        this.vulnerabilities.reduce((sum, v) => sum + v.confidence_score, 0) / (total || 1)
      ),
      vulnerability_types: [...new Set(this.vulnerabilities.map(v => v.vulnerability_type))],
      rules_generated: this.generatedRules.length
    };
  }
}

module.exports = AdvancedSecurityAnalyzer;

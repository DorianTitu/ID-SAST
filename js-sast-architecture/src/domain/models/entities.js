/**
 * SHARED MODELS - Estructuras de datos unificadas
 * Define los tipos de datos que fluyen entre microservicios
 */

/**
 * Representación normalizada de un nodo AST
 */
class ASTNode {
  constructor(id, type, name, line, column, properties = {}) {
    this.id = id;
    this.type = type; // 'FunctionDeclaration', 'CallExpression', etc.
    this.name = name;
    this.line = line;
    this.column = column;
    this.children = [];
    this.parent = null;
    this.properties = properties; // metadata específica
  }

  addChild(node) {
    this.children.push(node);
    node.parent = this;
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      name: this.name,
      line: this.line,
      column: this.column,
      children: this.children.map(c => c.toJSON()),
      properties: this.properties
    };
  }
}

/**
 * Nodo en los grafos de flujo (CFG/DFG)
 */
class FlowGraphNode {
  constructor(id, type, value, astNodeId = null) {
    this.id = id;
    this.type = type; // 'variable', 'function_call', 'literal', 'operation'
    this.value = value;
    this.astNodeId = astNodeId; // referencia al nodo AST correspondiente
    this.edges = []; // conexiones con otros nodos
    this.metadata = {};
  }

  addEdge(targetNode, label = 'flow') {
    this.edges.push({
      target: targetNode.id,
      label: label,
      targetNode: targetNode
    });
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      value: this.value,
      astNodeId: this.astNodeId,
      edges: this.edges.map(e => ({
        target: e.target,
        label: e.label
      })),
      metadata: this.metadata
    };
  }
}

/**
 * Reporte de vulnerabilidad encontrada
 */
class VulnerabilityFinding {
  constructor(id, type, severity, location, message) {
    this.id = id;
    this.type = type; // 'SQL_INJECTION', 'XSS', etc.
    this.severity = severity; // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    this.location = location; // { line, column, file }
    this.message = message;
    this.evidencePath = []; // cadena de nodos que demuestran la vulnerabilidad
    this.remediation = null;
    this.cweId = null;
  }

  toJSON() {
    return {
      id: this.id,
      type: this.type,
      severity: this.severity,
      location: this.location,
      message: this.message,
      evidencePath: this.evidencePath,
      remediation: this.remediation,
      cweId: this.cweId
    };
  }
}

/**
 * Resultado completo del análisis
 */
class AnalysisResult {
  constructor(code, filename) {
    this.code = code;
    this.filename = filename;
    this.ast = null;
    this.cfg = null; // Control Flow Graph
    this.dfg = null; // Data Flow Graph
    this.vulnerabilities = [];
    this.timestamp = new Date().toISOString();
    this.metrics = {};
  }

  addVulnerability(vulnerability) {
    this.vulnerabilities.push(vulnerability);
  }

  toJSON() {
    return {
      filename: this.filename,
      ast: this.ast ? this.ast.toJSON() : null,
      graphs: {
        cfg: this.cfg ? this.cfg.map(n => n.toJSON()) : null,
        dfg: this.dfg ? this.dfg.map(n => n.toJSON()) : null
      },
      vulnerabilities: this.vulnerabilities.map(v => v.toJSON()),
      timestamp: this.timestamp,
      metrics: this.metrics
    };
  }
}

module.exports = {
  ASTNode,
  FlowGraphNode,
  VulnerabilityFinding,
  AnalysisResult
};

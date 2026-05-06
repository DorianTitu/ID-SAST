/**
 * GRAPH BUILDER COMPONENT
 * Construye grafos de flujo (CFG y DFG) a partir del AST
 */

const { FlowGraphNode } = require('../../domain/models/entities');

class GraphBuilder {
  constructor(ast) {
    this.ast = ast;
    this.nodeCounter = 0;
    this.variables = new Map();
    this.dfgNodes = [];
    this.cfgNodes = [];
  }

  buildDFG() {
    this.variables.clear();
    this.dfgNodes = [];

    this.traverseForDFG(this.ast);
    this.connectDFGNodes();

    return this.dfgNodes;
  }

  buildCFG() {
    this.cfgNodes = [];
    let nodeId = 0;

    const traverse_cfg = (node, parent = null) => {
      const cfgNode = new FlowGraphNode(
        this.generateId(),
        'statement',
        node.name || node.type,
        node.id
      );

      this.cfgNodes.push(cfgNode);

      if (parent) {
        parent.addEdge(cfgNode, 'sequence');
      }

      for (let child of node.children) {
        traverse_cfg(child, cfgNode);
      }
    };

    traverse_cfg(this.ast);
    return this.cfgNodes;
  }

  traverseForDFG(node) {
    if (!node) return;

    if (node.type === 'VariableDeclarator') {
      if (node.properties?.varName) {
        const dfgNode = new FlowGraphNode(
          this.generateId(),
          'variable',
          node.properties.varName,
          node.id
        );

        this.checkIfUntrusted(node, dfgNode);
        this.dfgNodes.push(dfgNode);
        this.variables.set(node.properties.varName, dfgNode);
      }
    }

    if (node.type === 'CallExpression' && node.properties) {
      const isSQLSink = this.isSQLSink(node.name || node.properties.callee || '');
      if (isSQLSink) {
        const sinkNode = new FlowGraphNode(
          this.generateId(),
          'sql_sink',
          node.name || 'db.query',
          node.id
        );
        sinkNode.metadata.isSink = true;
        this.dfgNodes.push(sinkNode);
      }
    }

    if (node.type === 'BinaryExpression' && node.properties?.operator === '+') {
      const concatNode = new FlowGraphNode(
        this.generateId(),
        'concatenation',
        '+',
        node.id
      );
      concatNode.metadata.isConcatenation = true;
      this.dfgNodes.push(concatNode);
    }

    for (let child of node.children) {
      this.traverseForDFG(child);
    }
  }

  checkIfUntrusted(node, dfgNode) {
    const untrustedPatterns = ['req.', 'process.', 'input', 'userInput', 'data'];
    
    let hasUntrustedSource = false;
    const checkNode = (n) => {
      if (n.properties?.object && untrustedPatterns.some(p => n.properties.object.includes(p))) {
        hasUntrustedSource = true;
      }
      if (n.properties?.identifierName && untrustedPatterns.some(p => n.properties.identifierName.includes(p))) {
        hasUntrustedSource = true;
      }
    };

    const traverse_check = (n) => {
      checkNode(n);
      for (let child of n.children) traverse_check(child);
    };

    traverse_check(node);

    if (hasUntrustedSource) {
      dfgNode.metadata.isTainted = true;
    }
  }

  isSQLSink(name) {
    const sinks = ['query', 'execute', 'run', 'exec', 'raw', 'sql'];
    return sinks.some(s => name && name.toLowerCase().includes(s));
  }

  connectDFGNodes() {
    for (let i = 0; i < this.dfgNodes.length; i++) {
      for (let j = i + 1; j < this.dfgNodes.length; j++) {
        const node1 = this.dfgNodes[i];
        const node2 = this.dfgNodes[j];

        if (node1.metadata.isTainted && node2.metadata.isConcatenation) {
          node1.addEdge(node2, 'data_flow');
        }

        if (node2.metadata.isSink) {
          node1.addEdge(node2, 'flows_to_sink');
        }
      }
    }
  }

  generateId() {
    return `graph_${++this.nodeCounter}`;
  }
}

module.exports = GraphBuilder;

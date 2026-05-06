/**
 * Tree-Sitter Adapter
 * Extracts normalized AST from JavaScript code using tree-sitter
 * Part of infrastructure/adapters layer
 */

const Parser = require('tree-sitter');
const JavaScript = require('tree-sitter-javascript');
const { ASTNode, AnalysisResult } = require('../../domain/models/entities');

class TreeSitterAdapter {
  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(JavaScript);
    this.nodeCounter = 0;
    this.nodeMap = new Map();
  }

  /**
   * Parse JavaScript code and return normalized AST
   * @param {string} code - Source code to parse
   * @param {string} filename - Filename for reference
   * @returns {Object} Parse result with AST, metrics, or error
   */
  parse(code, filename = 'unknown.js') {
    try {
      this.nodeCounter = 0;
      this.nodeMap = new Map();
      const result = new AnalysisResult(code, filename);
      
      const tree = this.parser.parse(code);
      result.ast = this.buildNormalizedAST(tree.rootNode, code);
      result.metrics = this.calculateMetrics(code, result.ast);

      return {
        success: true,
        result: result,
        error: null,
        raw: tree
      };
    } catch (error) {
      return {
        success: false,
        result: null,
        error: { message: error.message },
        raw: null
      };
    }
  }

  buildNormalizedAST(treeNode, code) {
    const root = new ASTNode(this.generateId(), 'Program', 'root', 1, 0);
    this.nodeMap.set(treeNode, root);
    this.traverseTreeSitter(treeNode, root, code);
    return root;
  }

  traverseTreeSitter(treeNode, parentNode, code) {
    const childNode = this.createNodeFromTreeSitter(treeNode, code);
    if (childNode.type !== 'ERROR') {
      parentNode.addChild(childNode);
      this.nodeMap.set(treeNode, childNode);
    }

    for (let child of treeNode.children) {
      this.traverseTreeSitter(child, childNode, code);
    }
  }

  createNodeFromTreeSitter(treeNode, code) {
    const id = this.generateId();
    const type = treeNode.type;
    const name = this.extractNameFromTreeSitter(treeNode, code);
    const line = treeNode.startPosition.row + 1;
    const column = treeNode.startPosition.column;
    const properties = this.extractProperties(treeNode, code);

    return new ASTNode(id, type, name, line, column, properties);
  }

  extractNameFromTreeSitter(treeNode, code) {
    const text = treeNode.text;

    if (treeNode.type === 'identifier') return text;
    if (treeNode.type === 'property_identifier') return text;
    if (treeNode.type === 'call_expression') {
      const func = treeNode.childForFieldName('function');
      if (func) return func.text;
    }
    if (treeNode.type === 'member_expression') {
      const prop = treeNode.childForFieldName('property');
      if (prop) return prop.text;
    }
    if (treeNode.type === 'assignment_expression') {
      const left = treeNode.childForFieldName('left');
      if (left) return left.text;
    }

    return text.length > 50 ? text.substring(0, 50) + '...' : text;
  }

  extractProperties(treeNode, code) {
    const properties = {};

    if (treeNode.type === 'call_expression') {
      const func = treeNode.childForFieldName('function');
      if (func) properties.function = func.text;
      const args = treeNode.childrenForFieldName('arguments');
      if (args.length > 0) properties.arguments = args.map(arg => arg.text);
    }

    if (treeNode.type === 'member_expression') {
      const object = treeNode.childForFieldName('object');
      const property = treeNode.childForFieldName('property');
      if (object) properties.object = object.text;
      if (property) properties.property = property.text;
    }

    if (treeNode.type === 'assignment_expression') {
      const left = treeNode.childForFieldName('left');
      const right = treeNode.childForFieldName('right');
      if (left) properties.left = left.text;
      if (right) properties.right = right.text;
    }

    if (treeNode.type === 'template_string') {
      properties.isTemplate = true;
      properties.content = treeNode.text;
    }

    if (treeNode.type === 'variable_declarator') {
      const name = treeNode.childForFieldName('name');
      if (name) properties.varName = name.text;
    }

    return properties;
  }

  generateId() {
    return `node_${++this.nodeCounter}`;
  }

  calculateMetrics(code, ast) {
    let functions = 0, variables = 0, calls = 0;
    
    const traverse_ast = (node) => {
      if (node.type === 'function_declaration' || node.type === 'arrow_function') functions++;
      if (node.type === 'variable_declarator') variables++;
      if (node.type === 'call_expression') calls++;
      
      for (let child of node.children) traverse_ast(child);
    };

    traverse_ast(ast);
    
    return {
      lines: code.split('\n').length,
      characters: code.length,
      functions,
      variables,
      calls
    };
  }
}

module.exports = TreeSitterAdapter;

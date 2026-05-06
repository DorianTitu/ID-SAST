/**
 * AST Normalizer para JavaScript
 * Convierte el AST de @babel/parser a formato normalizado
 */

class ASTNodeType {
  // Definiciones
  static FUNCTION = "FunctionDef";
  static CLASS = "ClassDef";
  static ASYNC_FUNCTION = "AsyncFunctionDef";
  static METHOD = "MethodDef";

  // Sentencias
  static ASSIGNMENT = "Assignment";
  static EXPRESSION_STATEMENT = "ExpressionStatement";
  static RETURN = "Return";
  static IF = "If";
  static FOR = "For";
  static WHILE = "While";
  static BREAK = "Break";
  static CONTINUE = "Continue";
  static PASS = "Pass";
  static TRY = "Try";
  static RAISE = "Raise";
  static WITH = "With";
  static IMPORT = "Import";
  static FROM_IMPORT = "FromImport";

  // Expresiones
  static CALL = "Call";
  static BINARY_OP = "BinaryOp";
  static UNARY_OP = "UnaryOp";
  static LAMBDA = "Lambda";
  static CONDITIONAL = "Conditional";
  static COMPARE = "Compare";
  static BOOLEAN_OP = "BooleanOp";
  static ATTRIBUTE = "Attribute";
  static SUBSCRIPT = "Subscript";
  static SLICE = "Slice";

  // Valores  
  static IDENTIFIER = "Identifier";
  static LITERAL = "Literal";
  static NAME = "Name";
  static CONSTANT = "Constant";

  // Contenedores
  static LIST = "List";
  static DICT = "Dict";
  static TUPLE = "Tuple";
  static SET = "Set";

  // Argumentos
  static PARAMETER = "Parameter";
  static ARGUMENT = "Argument";
  static KEYWORD_ARGUMENT = "KeywordArgument";

  static UNKNOWN = "Unknown";
}

class ASTNode {
  constructor({
    type,
    name = null,
    value = null,
    children = [],
    lineno = null,
    col_offset = null,
    end_lineno = null,
    end_col_offset = null,
    attributes = {}
  } = {}) {
    this.type = type;
    this.name = name;
    this.value = value;
    this.children = children;
    this.lineno = lineno;
    this.col_offset = col_offset;
    this.end_lineno = end_lineno;
    this.end_col_offset = end_col_offset;
    this.attributes = attributes;
  }

  toDict() {
    return {
      type: this.type,
      name: this.name,
      value: this.value !== null ? String(this.value) : null,
      children: this.children.map(child => child.toDict()),
      location: {
        line: this.lineno,
        column: this.col_offset,
        end_line: this.end_lineno,
        end_column: this.end_col_offset
      },
      attributes: this.attributes
    };
  }

  toJSON() {
    return JSON.stringify(this.toDict(), null, 2);
  }
}

class NormalizedAST {
  constructor({
    language = "javascript",
    filename,
    version = null,
    source_code = null,
    root = null,
    metadata = {},
    error = null,
    success = true
  } = {}) {
    this.language = language;
    this.filename = filename;
    this.version = version;
    this.source_code = source_code;
    this.root = root;
    this.metadata = metadata;
    this.error = error;
    this.success = success;
  }

  toDict() {
    return {
      language: this.language,
      filename: this.filename,
      version: this.version,
      success: this.success,
      error: this.error,
      ast: this.root ? this.root.toDict() : null,
      metadata: this.metadata
    };
  }

  toJSON() {
    return JSON.stringify(this.toDict(), null, 2);
  }
}

class JavaScriptASTExtractor {
  constructor(filename = "<stdin>") {
    this.filename = filename;
    const pkg = require("./package.json");
    this.babelVersion = pkg.dependencies["@babel/parser"];
  }

  extract(code) {
    const { parse } = require("@babel/parser");

    try {
      // Parsea con Babel
      const ast = parse(code, {
        sourceType: "module",
        plugins: [
          "jsx",
          "typescript",
          "classProperties",
          "classPrivateProperties",
          "classPrivateMethods",
          "exportExtensions",
          "asyncGenerators",
          ["pipelineOperator", { proposal: "minimal" }],
          "partialApplication",
          "logicalAssignment",
          "optionalChaining",
          "nullishCoalescingOperator",
          "partialApplication",
          "decorators-legacy",
          "doExpressions",
          "functionBind",
          "functionSent",
          "logicalAssignment",
          "partialApplication",
          "pipelineOperator",
          "privateMethods",
          "privateIn",
          "staticBlocks"
        ],
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true
      });

      // Convierte a nodo normalizado
      const root = this.convertNode(ast);

      return new NormalizedAST({
        language: "javascript",
        filename: this.filename,
        version: this.babelVersion,
        source_code: code,
        root,
        metadata: {
          parser: "@babel/parser",
          babel_version: this.babelVersion
        },
        success: true,
        error: null
      });
    } catch (error) {
      return new NormalizedAST({
        language: "javascript",
        filename: this.filename,
        version: this.babelVersion,
        source_code: code,
        success: false,
        error: `ParseError: ${error.message} at line ${error.pos}`
      });
    }
  }

  convertNode(node) {
    if (!node || typeof node !== "object") {
      return null;
    }

    const typeMap = {
      // Definiciones
      FunctionDeclaration: ASTNodeType.FUNCTION,
      FunctionExpression: ASTNodeType.FUNCTION,
      ArrowFunctionExpression: ASTNodeType.FUNCTION,
      ClassDeclaration: ASTNodeType.CLASS,
      ClassExpression: ASTNodeType.CLASS,
      ObjectMethod: ASTNodeType.METHOD,

      // Sentencias
      ReturnStatement: ASTNodeType.RETURN,
      VariableDeclaration: ASTNodeType.ASSIGNMENT,
      AssignmentExpression: ASTNodeType.ASSIGNMENT,
      IfStatement: ASTNodeType.IF,
      ForStatement: ASTNodeType.FOR,
      ForInStatement: ASTNodeType.FOR,
      ForOfStatement: ASTNodeType.FOR,
      WhileStatement: ASTNodeType.WHILE,
      DoWhileStatement: ASTNodeType.WHILE,
      BreakStatement: ASTNodeType.BREAK,
      ContinueStatement: ASTNodeType.CONTINUE,
      ThrowStatement: ASTNodeType.RAISE,
      TryStatement: ASTNodeType.TRY,
      ImportDeclaration: ASTNodeType.IMPORT,
      ExportNamedDeclaration: ASTNodeType.IMPORT,
      ExportDefaultDeclaration: ASTNodeType.IMPORT,
      ExpressionStatement: ASTNodeType.EXPRESSION_STATEMENT,

      // Expresiones
      CallExpression: ASTNodeType.CALL,
      BinaryExpression: ASTNodeType.BINARY_OP,
      UnaryExpression: ASTNodeType.UNARY_OP,
      LogicalExpression: ASTNodeType.BOOLEAN_OP,
      ConditionalExpression: ASTNodeType.CONDITIONAL,
      MemberExpression: ASTNodeType.ATTRIBUTE,
      ArrayExpression: ASTNodeType.LIST,
      ObjectExpression: ASTNodeType.DICT,
      SequenceExpression: ASTNodeType.UNKNOWN,
      UpdateExpression: ASTNodeType.ASSIGNMENT,
      SpreadElement: ASTNodeType.UNKNOWN,

      // Valores
      Identifier: ASTNodeType.IDENTIFIER,
      StringLiteral: ASTNodeType.LITERAL,
      NumericLiteral: ASTNodeType.LITERAL,
      BooleanLiteral: ASTNodeType.LITERAL,
      NullLiteral: ASTNodeType.CONSTANT,
      RegExpLiteral: ASTNodeType.LITERAL,
      TemplateLiteral: ASTNodeType.LITERAL,

      // Argumentos
      ObjectProperty: ASTNodeType.UNKNOWN,
      ArrayPattern: ASTNodeType.UNKNOWN,
      ObjectPattern: ASTNodeType.UNKNOWN,
      RestElement: ASTNodeType.PARAMETER,

      // Otros
      Program: ASTNodeType.UNKNOWN,
      BlockStatement: ASTNodeType.UNKNOWN,
      EmptyStatement: ASTNodeType.PASS,
      DebuggerStatement: ASTNodeType.UNKNOWN,
      WithStatement: ASTNodeType.WITH,
      LabeledStatement: ASTNodeType.UNKNOWN,
      SwitchStatement: ASTNodeType.IF,
      CatchClause: ASTNodeType.TRY,
      SwitchCase: ASTNodeType.UNKNOWN,
      File: ASTNodeType.UNKNOWN
    };

    const nodeType = node.type || "Unknown";
    const astNodeType = typeMap[nodeType] || ASTNodeType.UNKNOWN;

    // Extrae información específica
    const name = this.getNodeName(node);
    const value = this.getNodeValue(node);
    const attributes = this.getNodeAttributes(node);

    // Crea el nodo normalizado
    const normalizedNode = new ASTNode({
      type: astNodeType,
      name,
      value,
      lineno: node.loc?.start?.line || null,
      col_offset: node.loc?.start?.column || null,
      end_lineno: node.loc?.end?.line || null,
      end_col_offset: node.loc?.end?.column || null,
      attributes: {
        js_node_type: nodeType,
        ...attributes
      }
    });

    // Procesa los hijos
    if (node.program?.body) {
      node.program.body.forEach(child => {
        const childNode = this.convertNode(child);
        if (childNode) normalizedNode.children.push(childNode);
      });
    } else if (node.body) {
      if (Array.isArray(node.body)) {
        node.body.forEach(child => {
          const childNode = this.convertNode(child);
          if (childNode) normalizedNode.children.push(childNode);
        });
      } else {
        const childNode = this.convertNode(node.body);
        if (childNode) normalizedNode.children.push(childNode);
      }
    }

    if (node.params && Array.isArray(node.params)) {
      node.params.forEach(param => {
        const childNode = this.convertNode(param);
        if (childNode) normalizedNode.children.push(childNode);
      });
    }

    if (node.arguments && Array.isArray(node.arguments)) {
      node.arguments.forEach(arg => {
        const childNode = this.convertNode(arg);
        if (childNode) normalizedNode.children.push(childNode);
      });
    }

    if (node.expression) {
      const childNode = this.convertNode(node.expression);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.test) {
      const childNode = this.convertNode(node.test);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.consequent) {
      const childNode = this.convertNode(node.consequent);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.alternate) {
      const childNode = this.convertNode(node.alternate);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.object) {
      const childNode = this.convertNode(node.object);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.left) {
      const childNode = this.convertNode(node.left);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.right) {
      const childNode = this.convertNode(node.right);
      if (childNode) normalizedNode.children.push(childNode);
    }

    if (node.callee) {
      const childNode = this.convertNode(node.callee);
      if (childNode) normalizedNode.children.push(childNode);
    }

    return normalizedNode;
  }

  getNodeName(node) {
    if (node.id?.name) return node.id.name;
    if (node.name) return node.name;
    if (node.key?.name) return node.key.name;
    if (node.local?.name) return node.local.name;
    return null;
  }

  getNodeValue(node) {
    if (node.value !== undefined) return node.value;
    if (node.raw !== undefined) return node.raw;
    return null;
  }

  getNodeAttributes(node) {
    const attributes = {};

    if (
      node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression"
    ) {
      attributes.async = node.async || false;
      attributes.generator = node.generator || false;
      attributes.params_count = node.params?.length || 0;
      if (node.params) {
        attributes.params = node.params.map(p => p.name || p.type);
      }
    }

    if (node.type === "ClassDeclaration" || node.type === "ClassExpression") {
      attributes.superClass = node.superClass?.name || null;
    }

    if (node.type === "CallExpression") {
      if (node.callee?.name) {
        attributes.function = node.callee.name;
      } else if (node.callee?.property?.name) {
        attributes.function = node.callee.property.name;
      }
      attributes.args_count = node.arguments?.length || 0;
    }

    if (node.type === "ImportDeclaration") {
      attributes.source = node.source?.value || null;
      attributes.specifiers = node.specifiers?.map(s => s.local?.name || s.name) || [];
    }

    if (node.type === "BinaryExpression" || node.type === "LogicalExpression") {
      attributes.operator = node.operator;
    }

    if (node.type === "UnaryExpression") {
      attributes.operator = node.operator;
      attributes.prefix = node.prefix;
    }

    if (node.type === "VariableDeclaration") {
      attributes.kind = node.kind; // var, let, const
      attributes.declarations = node.declarations?.map(d => d.id?.name || "unknown") || [];
    }

    if (node.type === "AssignmentExpression") {
      attributes.operator = node.operator;
    }

    return attributes;
  }
}

module.exports = {
  ASTNodeType,
  ASTNode,
  NormalizedAST,
  JavaScriptASTExtractor
};

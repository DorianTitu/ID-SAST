"""
Parser de Python: Genera AST desde código Python
"""

import ast
import sys
from typing import Dict, Any, List


class PythonASTParser:
    """Parsea código Python y genera un AST"""
    
    def parse(self, code: str, filename: str = "<unknown>") -> Dict[str, Any]:
        """
        Parsea código Python
        
        Args:
            code: Código Python a parsear
            filename: Nombre del archivo (para ubicaciones)
            
        Returns:
            Diccionario con el AST
        """
        try:
            tree = ast.parse(code, filename=filename)
            return {
                "success": True,
                "ast": self._ast_to_dict(tree),
                "filename": filename,
                "error": None
            }
        except SyntaxError as e:
            return {
                "success": False,
                "ast": None,
                "filename": filename,
                "error": f"Syntax error: {e.msg} at line {e.lineno}"
            }
        except Exception as e:
            return {
                "success": False,
                "ast": None,
                "filename": filename,
                "error": f"Parse error: {str(e)}"
            }
    
    def _ast_to_dict(self, node, parent_info=None):
        """Convierte nodo AST a diccionario"""
        if isinstance(node, ast.AST):
            result = {
                "type": node.__class__.__name__,
                "lineno": getattr(node, "lineno", None),
                "col_offset": getattr(node, "col_offset", None),
                "end_lineno": getattr(node, "end_lineno", None),
                "end_col_offset": getattr(node, "end_col_offset", None),
            }
            
            # Agrega atributos específicos del nodo
            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    result[field] = [self._ast_to_dict(item) for item in value]
                elif isinstance(value, ast.AST):
                    result[field] = self._ast_to_dict(value)
                else:
                    result[field] = value
            
            return result
        elif isinstance(node, list):
            return [self._ast_to_dict(item) for item in node]
        else:
            return node


class PythonASTVisitor(ast.NodeVisitor):
    """Visitor para extraer información específica del AST"""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.functions = []
        self.classes = []
        self.imports = []
        self.calls = []
        self.variables = []
        self.current_class = None
        self.current_function = None
    
    def visit_FunctionDef(self, node):
        func_info = {
            "name": node.name,
            "lineno": node.lineno,
            "col_offset": node.col_offset,
            "args": [arg.arg for arg in node.args.args],
            "decorators": [self._get_name(d) for d in node.decorator_list],
            "calls": [],
            "variables": [],
        }
        
        # Guarda contexto anterior
        prev_function = self.current_function
        self.current_function = func_info
        
        # Visita el cuerpo
        for child in node.body:
            self.visit(child)
        
        # Restaura contexto
        self.current_function = prev_function
        
        if self.current_class:
            # Es un método
            if "methods" not in self.current_class:
                self.current_class["methods"] = []
            self.current_class["methods"].append(func_info)
        else:
            # Es una función global
            self.functions.append(func_info)
    
    def visit_ClassDef(self, node):
        class_info = {
            "name": node.name,
            "lineno": node.lineno,
            "col_offset": node.col_offset,
            "base_classes": [self._get_name(base) for base in node.bases],
            "methods": [],
            "attributes": [],
        }
        
        prev_class = self.current_class
        self.current_class = class_info
        
        for child in node.body:
            self.visit(child)
        
        self.current_class = prev_class
        self.classes.append(class_info)
    
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({
                "module": alias.name,
                "alias": alias.asname,
                "lineno": node.lineno,
                "items": [],
            })
    
    def visit_ImportFrom(self, node):
        items = [alias.name for alias in node.names]
        self.imports.append({
            "module": node.module or "",
            "items": items,
            "lineno": node.lineno,
            "level": node.level,  # Para relative imports
        })
    
    def visit_Call(self, node):
        call_info = {
            "name": self._get_name(node.func),
            "lineno": node.lineno,
            "col_offset": node.col_offset,
            "args": [self._get_name(arg) for arg in node.args],
        }
        self.calls.append(call_info)
        
        if self.current_function:
            self.current_function["calls"].append(call_info)
        
        self.generic_visit(node)
    
    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_info = {
                    "name": target.id,
                    "lineno": node.lineno,
                    "type": None,
                }
                self.variables.append(var_info)
                
                if self.current_function:
                    self.current_function["variables"].append(var_info)
        
        self.generic_visit(node)
    
    def _get_name(self, node):
        """Extrae el nombre de un nodo"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        elif isinstance(node, ast.Constant):
            return str(node.value)
        else:
            return "unknown"

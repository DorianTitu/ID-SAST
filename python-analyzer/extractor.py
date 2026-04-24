"""
Extractor: Convierte AST de Python al modelo universal
"""

import sys
sys.path.insert(0, '/Users/doriantituana/Desktop/Tesis/ID-SAST')

from shared.models import (
    Location, Call, Variable, FunctionDef, ClassDef, 
    Import, AnalysisResult, Finding, Severity
)
from parser import PythonASTParser, PythonASTVisitor
import ast
from typing import List


class PythonExtractor:
    """Extrae información del AST de Python al modelo universal"""
    
    def __init__(self):
        self.parser = PythonASTParser()
        self.security_rules = self._get_security_rules()
    
    def extract(self, code: str, filename: str) -> AnalysisResult:
        """
        Extrae información del código Python
        
        Args:
            code: Código Python
            filename: Nombre del archivo
            
        Returns:
            AnalysisResult normalizado
        """
        # Parsea el código
        parse_result = self.parser.parse(code, filename)
        if not parse_result["success"]:
            return AnalysisResult(
                file=filename,
                language="python",
                functions=[],
                classes=[],
                imports=[],
                variables=[],
                findings=[],
            )
        
        # Extrae información usando Visitor
        tree = ast.parse(code, filename)
        visitor = PythonASTVisitor(filename)
        visitor.visit(tree)
        
        # Convierte a modelo universal
        functions = self._extract_functions(visitor, code)
        classes = self._extract_classes(visitor, code)
        imports = self._extract_imports(visitor)
        variables = self._extract_variables(visitor, code)
        
        # Análisis de seguridad
        findings = self._analyze_security(code, filename, visitor)
        
        return AnalysisResult(
            file=filename,
            language="python",
            functions=functions,
            classes=classes,
            imports=imports,
            variables=variables,
            findings=findings,
            metadata={
                "total_functions": len(functions),
                "total_classes": len(classes),
                "total_imports": len(imports),
            }
        )
    
    def _extract_functions(self, visitor: PythonASTVisitor, code: str) -> List[FunctionDef]:
        """Extrae funciones globales"""
        functions = []
        code_lines = code.split('\n')
        
        for func_info in visitor.functions:
            loc = Location(
                file=visitor.filename,
                line=func_info["lineno"],
                column=func_info["col_offset"],
            )
            
            # Extrae calls del cuerpo
            calls = [
                Call(
                    name=call["name"],
                    args=call["args"],
                    location=Location(
                        file=visitor.filename,
                        line=call["lineno"],
                        column=call["col_offset"],
                    )
                )
                for call in func_info.get("calls", [])
            ]
            
            # Extrae variables locales
            variables = [
                Variable(
                    name=var["name"],
                    type=var.get("type"),
                    location=Location(
                        file=visitor.filename,
                        line=var["lineno"],
                        column=0,
                    )
                )
                for var in func_info.get("variables", [])
            ]
            
            functions.append(FunctionDef(
                name=func_info["name"],
                location=loc,
                parameters=func_info.get("args", []),
                body_calls=calls,
                variables=variables,
                decorators=func_info.get("decorators", []),
            ))
        
        return functions
    
    def _extract_classes(self, visitor: PythonASTVisitor, code: str) -> List[ClassDef]:
        """Extrae clases y sus métodos"""
        classes = []
        
        for class_info in visitor.classes:
            loc = Location(
                file=visitor.filename,
                line=class_info["lineno"],
                column=class_info["col_offset"],
            )
            
            # Extrae métodos
            methods = [
                FunctionDef(
                    name=method["name"],
                    location=Location(
                        file=visitor.filename,
                        line=method["lineno"],
                        column=method["col_offset"],
                    ),
                    parameters=method.get("args", []),
                    body_calls=[
                        Call(
                            name=call["name"],
                            args=call["args"],
                            location=Location(
                                file=visitor.filename,
                                line=call["lineno"],
                                column=call["col_offset"],
                            )
                        )
                        for call in method.get("calls", [])
                    ],
                    decorators=method.get("decorators", []),
                )
                for method in class_info.get("methods", [])
            ]
            
            classes.append(ClassDef(
                name=class_info["name"],
                location=loc,
                methods=methods,
                base_classes=class_info.get("base_classes", []),
            ))
        
        return classes
    
    def _extract_imports(self, visitor: PythonASTVisitor) -> List[Import]:
        """Extrae importaciones"""
        imports = []
        
        for imp_info in visitor.imports:
            loc = Location(
                file=visitor.filename,
                line=imp_info["lineno"],
                column=0,
            )
            
            imports.append(Import(
                module=imp_info["module"],
                items=imp_info.get("items", []),
                location=loc,
                alias=imp_info.get("alias"),
            ))
        
        return imports
    
    def _extract_variables(self, visitor: PythonASTVisitor, code: str) -> List[Variable]:
        """Extrae variables globales"""
        variables = []
        
        for var_info in visitor.variables:
            loc = Location(
                file=visitor.filename,
                line=var_info["lineno"],
                column=0,
            )
            
            variables.append(Variable(
                name=var_info["name"],
                type=var_info.get("type"),
                location=loc,
            ))
        
        return variables
    
    def _analyze_security(self, code: str, filename: str, visitor: PythonASTVisitor) -> List[Finding]:
        """Análisis básico de seguridad"""
        findings = []
        
        # Detecta llamadas peligrosas
        dangerous_calls = {"os.system", "eval", "exec", "subprocess.call"}
        
        for call in visitor.calls:
            if call["name"] in dangerous_calls:
                findings.append(Finding(
                    rule_id="PY-DANGEROUS-CALL",
                    title=f"Llamada potencialmente peligrosa: {call['name']}",
                    description=f"Se detectó una llamada a {call['name']} que puede ser un riesgo de seguridad",
                    severity=Severity.HIGH,
                    location=Location(
                        file=filename,
                        line=call["lineno"],
                        column=call["col_offset"],
                    ),
                    recommendation=f"Considera usar alternativas más seguras a {call['name']}"
                ))
        
        return findings
    
    def _get_security_rules(self):
        """Define reglas de seguridad"""
        return {
            "dangerous_calls": {
                "os.system", "eval", "exec", "subprocess.call",
                "pickle.loads", "yaml.load", "__import__"
            },
            "sensitive_patterns": ["password", "secret", "token", "api_key"],
        }

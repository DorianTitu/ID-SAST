"""
Modelo universal para análisis de código de diferentes lenguajes.
Normaliza ASTs de Python, JavaScript, Java y C# a una estructura común.
"""

from dataclasses import dataclass, asdict
from typing import List, Optional, Any, Dict
from enum import Enum
import json


class NodeType(Enum):
    """Tipos de nodos universales"""
    FUNCTION = "function"
    CLASS = "class"
    VARIABLE = "variable"
    CALL = "call"
    ASSIGNMENT = "assignment"
    IMPORT = "import"
    CONDITION = "condition"
    LOOP = "loop"
    RETURN = "return"
    OPERATION = "operation"
    LITERAL = "literal"
    ATTRIBUTE = "attribute"
    PARAMETER = "parameter"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Niveles de severidad para hallazgos"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Location:
    """Ubicación de un nodo en el código"""
    file: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class Call:
    """Llamada a función/método"""
    name: str
    args: List[str]
    location: Location
    is_builtin: bool = False
    receiver: Optional[str] = None  # Para método.receiver
    
    def to_dict(self):
        return {
            "name": self.name,
            "args": self.args,
            "location": self.location.to_dict(),
            "is_builtin": self.is_builtin,
            "receiver": self.receiver,
        }


@dataclass
class Variable:
    """Variable/atributo"""
    name: str
    type: Optional[str]
    location: Location
    value: Optional[Any] = None
    
    def to_dict(self):
        return {
            "name": self.name,
            "type": self.type,
            "location": self.location.to_dict(),
            "value": str(self.value) if self.value else None,
        }


@dataclass
class FunctionDef:
    """Definición de función"""
    name: str
    location: Location
    parameters: List[str]
    returns: Optional[str] = None
    body_calls: List[Call] = None
    variables: List[Variable] = None
    decorators: List[str] = None
    
    def __post_init__(self):
        if self.body_calls is None:
            self.body_calls = []
        if self.variables is None:
            self.variables = []
        if self.decorators is None:
            self.decorators = []
    
    def to_dict(self):
        return {
            "name": self.name,
            "location": self.location.to_dict(),
            "parameters": self.parameters,
            "returns": self.returns,
            "body_calls": [c.to_dict() for c in self.body_calls],
            "variables": [v.to_dict() for v in self.variables],
            "decorators": self.decorators,
        }


@dataclass
class ClassDef:
    """Definición de clase"""
    name: str
    location: Location
    methods: List[FunctionDef] = None
    attributes: List[Variable] = None
    base_classes: List[str] = None
    
    def __post_init__(self):
        if self.methods is None:
            self.methods = []
        if self.attributes is None:
            self.attributes = []
        if self.base_classes is None:
            self.base_classes = []
    
    def to_dict(self):
        return {
            "name": self.name,
            "location": self.location.to_dict(),
            "methods": [m.to_dict() for m in self.methods],
            "attributes": [a.to_dict() for a in self.attributes],
            "base_classes": self.base_classes,
        }


@dataclass
class Import:
    """Importación de módulo"""
    module: str
    items: List[str]  # Qué se importa (vacío si import *)
    location: Location
    alias: Optional[str] = None
    
    def to_dict(self):
        return {
            "module": self.module,
            "items": self.items,
            "location": self.location.to_dict(),
            "alias": self.alias,
        }


@dataclass
class Finding:
    """Hallazgo de seguridad"""
    rule_id: str
    title: str
    description: str
    severity: Severity
    location: Location
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    
    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "location": self.location.to_dict(),
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
        }


@dataclass
class AnalysisResult:
    """Resultado completo del análisis"""
    file: str
    language: str
    functions: List[FunctionDef]
    classes: List[ClassDef]
    imports: List[Import]
    variables: List[Variable]
    findings: List[Finding]
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self):
        return {
            "file": self.file,
            "language": self.language,
            "functions": [f.to_dict() for f in self.functions],
            "classes": [c.to_dict() for c in self.classes],
            "imports": [i.to_dict() for i in self.imports],
            "variables": [v.to_dict() for v in self.variables],
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        """Convierte a JSON"""
        return json.dumps(self.to_dict(), indent=2, default=str)

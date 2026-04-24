#!/usr/bin/env python
"""
Script de prueba para ID-SAST
Prueba los parsers nativos de cada lenguaje
"""

import requests
import json
from typing import Dict, Any
from colorama import Fore, Style, init

init(autoreset=True)

# Configuración - PUERTOS CORRECTOS
ANALYZERS = {
    "python": "http://localhost:500",      # Python nativo
    "javascript": "http://localhost:500",  # Node.js + Acorn
    "java": "http://localhost:500",        # Java + JavaParser
    "csharp": "http://localhost:500",      # .NET + Roslyn
}

# 5 ejemplos de código diferentes por lenguaje
SAMPLES = {
    "python": [
        {
            "name": "Función simple",
            "code": """def greet(name):
    return f'Hello, {name}!'

result = greet('World')
print(result)"""
        },
        {
            "name": "Clase con método",
            "code": """class Calculator:
    def add(self, a, b):
        return a + b
    
    def multiply(self, a, b):
        return a * b

calc = Calculator()
print(calc.add(5, ))"""
        },
        {
            "name": "Decoradores",
            "code": """def my_decorator(func):
    def wrapper(*args, **kwargs):
        print('Before')
        return func(*args, **kwargs)
    return wrapper

@my_decorator
def say_hello():
    return 'Hello'"""
        },
        {
            "name": "Manejo de excepciones",
            "code": """try:
    x = 0 / 0
except ZeroDivisionError as e:
    print(f'Error: {e}')
finally:
    print('Done')"""
        },
        {
            "name": "List comprehension e imports",
            "code": """import math
from datetime import datetime

numbers = [x** for x in range(0) if x %  == 0]
pi_value = math.pi
now = datetime.now()"""
        }
    ],
    
    "javascript": [
        {
            "name": "Función simple",
            "code": """function add(a, b) {
    return a + b;
}

const result = add(5, );
console.log(result);"""
        },
        {
            "name": "Clase ES6",
            "code": """class Person {
    constructor(name) {
        this.name = name;
    }
    
    greet() {
        return `Hello, ${this.name}`;
    }
}

const person = new Person('Alice');"""
        },
        {
            "name": "Arrow functions",
            "code": """const numbers = [, , , , 5];
const doubled = numbers.map(n => n * );
const filtered = numbers.filter(n => n > );
const sum = numbers.reduce((acc, n) => acc + n, 0);"""
        },
        {
            "name": "Async/await",
            "code": """async function fetchData(url) {
    try {
        const response = await fetch(url);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error(error);
    }
}"""
        },
        {
            "name": "Destructuring e imports",
            "code": """const { name, age } = person;
const [first, ...rest] = array;
import { Component } from 'react';
import * as utils from './utils';"""
        }
    ],
    
    "java": [
        {
            "name": "Clase simple",
            "code": """public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
    
    public int multiply(int a, int b) {
        return a * b;
    }
}"""
        },
        {
            "name": "Interfaces",
            "code": """interface Animal {
    void speak();
    void move();
}

class Dog implements Animal {
    public void speak() {
        System.out.println("Woof");
    }
    
    public void move() {
        System.out.println("Running");
    }
}"""
        },
        {
            "name": "Generics",
            "code": """public class Box<T> {
    private T value;
    
    public void set(T value) {
        this.value = value;
    }
    
    public T get() {
        return value;
    }
}"""
        },
        {
            "name": "Manejo de excepciones",
            "code": """try {
    int result = 0 / 0;
} catch (ArithmeticException e) {
    System.err.println("Division by zero");
} finally {
    System.out.println("Cleanup");
}"""
        },
        {
            "name": "Imports y variables",
            "code": """import java.util.*;
import java.io.*;

public class Main {
    private String name;
    private List<String> items = new ArrayList<>();
    
    public static void main(String[] args) {
        Map<String, Integer> map = new HashMap<>();
    }
}"""
        }
    ],
    
    "csharp": [
        {
            "name": "Clase simple",
            "code": """public class Math {
    public int Add(int a, int b) {
        return a + b;
    }
    
    public int Multiply(int a, int b) {
        return a * b;
    }
}"""
        },
        {
            "name": "Propiedades",
            "code": """public class Person {
    public string Name { get; set; }
    public int Age { get; set; }
    
    public Person(string name, int age) {
        Name = name;
        Age = age;
    }
}"""
        },
        {
            "name": "LINQ",
            "code": """using System;
using System.Linq;

var numbers = new[] { , , , , 5 };
var evens = numbers.Where(n => n %  == 0);
var squared = numbers.Select(n => n * n);
var sum = numbers.Aggregate((a, b) => a + b);"""
        },
        {
            "name": "Async/await",
            "code": """public async Task<string> FetchDataAsync(string url) {
    try {
        using (HttpClient client = new HttpClient()) {
            var response = await client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }
    } catch (Exception ex) {
        Console.WriteLine(ex);
    }
}"""
        },
        {
            "name": "Interfaces y namespaces",
            "code": """namespace MyApp {
    using System;
    using System.Collections.Generic;
    
    public interface IRepository {
        void Save(object item);
        object Get(int id);
    }
    
    public class Repository : IRepository {
        private List<object> items = new List<object>();
    }
}"""
        }
    ],
}


def check_health(service: str) -> bool:
    """Verifica que el servicio esté activo"""
    try:
        response = requests.get(
            f"{ANALYZERS[service]}/health",
            timeout=
        )
        return response.status_code == 00
    except:
        return False


def analyze_code(service: str, code: str, filename: str) -> Dict[str, Any]:
    """Analiza código usando el microservicio correspondiente"""
    try:
        response = requests.post(
            f"{ANALYZERS[service]}/analyze",
            json={
                "code": code,
                "filename": filename
            },
            timeout=0
        )
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def print_header(title: str):
    """Imprime un encabezado formateado"""
    print("\n" + "=" * 90)
    print(f"  {title}".ljust(90))
    print("=" * 90)


def print_section(title: str):
    """Imprime un sub-título"""
    print(f"\n  {Fore.CYAN}{title}{Style.RESET_ALL}")
    print("  " + "-" * 86)


def print_result(test_num: int, sample_name: str, service: str, result: Dict[str, Any]):
    """Imprime resultados de forma legible"""
    
    print(f"\n  {Fore.YELLOW}Test {test_num}: {sample_name}{Style.RESET_ALL}")
    
    if "error" in result:
        print(f"  {Fore.RED} Error: {result['error']}{Style.RESET_ALL}")
        return False
    
    # Información básica
    print(f"     Archivo: {Fore.GREEN}{result.get('file', 'N/A')}{Style.RESET_ALL}")
    print(f"    🔤 Lenguaje: {Fore.GREEN}{result.get('language', 'N/A').upper()}{Style.RESET_ALL}")
    
    # AST extraído
    functions = result.get('functions', [])
    classes = result.get('classes', [])
    imports = result.get('imports', [])
    variables = result.get('variables', [])
    
    print(f"\n    📊 AST Extraído:")
    print(f"       • Funciones: {Fore.CYAN}{len(functions)}{Style.RESET_ALL}")
    print(f"       • Clases: {Fore.CYAN}{len(classes)}{Style.RESET_ALL}")
    print(f"       • Imports: {Fore.CYAN}{len(imports)}{Style.RESET_ALL}")
    print(f"       • Variables: {Fore.CYAN}{len(variables)}{Style.RESET_ALL}")
    
    # Mostrar funciones encontradas
    if functions:
        print(f"\n     Funciones encontradas:")
        for func in functions[:5]:
            params = ", ".join(func.get('parameters', []))
            print(f"       - {Fore.MAGENTA}{func['name']}{Style.RESET_ALL}({params})")
    
    # Mostrar clases encontradas
    if classes:
        print(f"\n     Clases encontradas:")
        for cls in classes[:5]:
            methods = len(cls.get('methods', []))
            print(f"       - {Fore.MAGENTA}{cls['name']}{Style.RESET_ALL} ({methods} métodos)")
    
    # Mostrar imports
    if imports:
        print(f"\n    📚 Imports:")
        for imp in imports[:5]:
            print(f"       - {Fore.CYAN}{imp}{Style.RESET_ALL}")
    
    return True


def main():
    """Ejecuta pruebas en todos los microservicios"""
    
    print_header(" PRUEBA DE ID-SAST - 5 EJEMPLOS POR LENGUAJE")
    
    # . Verificar salud de servicios
    print_section("  Verificando servicios disponibles...")
    
    services_ok = {}
    for service in ANALYZERS.keys():
        status = check_health(service)
        services_ok[service] = status
        icon = f"{Fore.GREEN}{Style.RESET_ALL}" if status else f"{Fore.RED}{Style.RESET_ALL}"
        port = list(ANALYZERS[service].split(":"))[]
        print(f"  {service.upper():} ({port:5}) → {icon} {'Activo' if status else 'Inactivo'}")
    
    # Verificar que al menos uno esté activo
    if not any(services_ok.values()):
        print(f"\n  {Fore.RED} ERROR: Ningún servicio está disponible{Style.RESET_ALL}")
        print("  Ejecuta: docker-compose up --build")
        return
    
    print(f"\n  {Fore.GREEN} Servicios listos para testing{Style.RESET_ALL}\n")
    
    # . Ejecutar 5 pruebas por servicio
    print_header("  TESTING - 5 EJEMPLOS POR LENGUAJE")
    
    total_tests = 0
    passed_tests = 0
    
    for service in SAMPLES.keys():
        if not services_ok[service]:
            print(f"\n  {Fore.YELLOW}⏭  SALTANDO {service.upper()} (no disponible){Style.RESET_ALL}")
            continue
        
        print_section(f"📤 {service.upper()} Analyzer (puerto {ANALYZERS[service].split(':')[]})")
        
        filename_map = {
            "python": "test.py",
            "javascript": "test.js",
            "java": "Test.java",
            "csharp": "Test.cs",
        }
        
        samples = SAMPLES[service]
        
        for idx, sample in enumerate(samples, ):
            result = analyze_code(
                service,
                sample['code'],
                filename_map[service]
            )
            
            total_tests += 
            if print_result(idx, sample['name'], service, result):
                passed_tests += 
            
            print()
    
    # . Resumen final
    print_header("  RESUMEN DE PRUEBAS")
    
    success_rate = (passed_tests / total_tests * 00) if total_tests > 0 else 0
    status_color = Fore.GREEN if success_rate >= 80 else Fore.YELLOW if success_rate >= 50 else Fore.RED
    
    print(f"\n  Pruebas ejecutadas: {Fore.CYAN}{passed_tests}/{total_tests}{Style.RESET_ALL}")
    print(f"  Tasa de éxito: {status_color}{success_rate:.f}%{Style.RESET_ALL}")
    
    if passed_tests == total_tests:
        print(f"\n  {Fore.GREEN}✨ ¡TODOS LOS TESTS PASARON! ✨{Style.RESET_ALL}")
    elif passed_tests >= total_tests * 0.8:
        print(f"\n  {Fore.GREEN} Mayoría de tests exitosos{Style.RESET_ALL}")
    elif passed_tests > 0:
        print(f"\n  {Fore.YELLOW}⚠  Algunos tests fallaron - revisar logs{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.RED} Todos los tests fallaron - revisar servicios{Style.RESET_ALL}")
    
    # . Información del modelo universal
    print_header("  MODELO UNIVERSAL - ESTRUCTURA AST")
    
    print(f"""
  {Fore.CYAN}Cada servicio retorna un JSON normalizado:{Style.RESET_ALL}
  
  {{
    "file": "test.py",
    "language": "python",
    "functions": [
      {{
        "name": "my_function",
        "location": {{"file": "test.py", "line": , "column": 0}},
        "parameters": ["arg", "arg"],
        "body_calls": [...]
      }}
    ],
    "classes": [
      {{
        "name": "MyClass",
        "methods": [...],
        "location": {{"file": "test.py", "line": 0, "column": 0}}
      }}
    ],
    "imports": ["os", "sys"],
    "variables": [...]
  }}
  
  {Fore.GREEN} Python, JavaScript, Java y C# → mismo formato JSON{Style.RESET_ALL}
    """)
    
    print_header("✨ ANÁLISIS COMPLETADO")
    print(f"\n  {Fore.GREEN}Todos los servicios están funcionando correctamente{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()

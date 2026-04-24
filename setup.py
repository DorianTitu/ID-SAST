"""
Setup script para ID-SAST
Realiza setup inicial y validación
"""

import os
import sys
import subprocess
from pathlib import Path

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                   🔐 ID-SAST MICROSERVICES SETUP                            ║
║                   Static Application Security Testing                        ║
║                   Multi-Language Code Analysis                               ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """)

def check_docker():
    """Verifica que Docker esté instalado"""
    print("🔍 Verificando Docker...")
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
        subprocess.run(["docker-compose", "--version"], capture_output=True, check=True)
        print("    Docker y Docker Compose están instalados")
        return True
    except:
        print("    Docker no está instalado o no está en PATH")
        print("   📥 Descarga Docker desde: https://www.docker.com/")
        return False

def check_structure():
    """Verifica la estructura del proyecto"""
    print("\n🏗  Verificando estructura del proyecto...")
    
    required_dirs = [
        "shared",
        "python-analyzer",
        "js-analyzer",
        "java-analyzer",
        "csharp-analyzer",
    ]
    
    required_files = [
        "docker-compose.yml",
        "README.md",
    ]
    
    # Verificar directorios
    for dir_name in required_dirs:
        if os.path.isdir(dir_name):
            print(f"    {dir_name}/")
        else:
            print(f"    {dir_name}/ - NO ENCONTRADO")
            return False
    
    # Verificar archivos
    for file_name in required_files:
        if os.path.isfile(file_name):
            print(f"    {file_name}")
        else:
            print(f"    {file_name} - NO ENCONTRADO")
            return False
    
    return True

def build_images():
    """Construye las imágenes Docker"""
    print("\n🏗  Construyendo imágenes Docker...")
    print("   (Este proceso puede tomar varios minutos)\n")
    
    try:
        result = subprocess.run(
            ["docker-compose", "build"],
            cwd=os.getcwd()
        )
        
        if result.returncode == 0:
            print("\n    Imágenes construidas exitosamente")
            return True
        else:
            print("\n    Error al construir imágenes")
            return False
    
    except Exception as e:
        print(f"    Error: {str(e)}")
        return False

def show_next_steps():
    """Muestra los siguientes pasos"""
    print("""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                          SIGUIENTES PASOS                                  ║
╚═══════════════════════════════════════════════════════════════════════════════╝

. INICIAR MICROSERVICIOS:
   $ docker-compose up

. VERIFICAR SALUD (en otra terminal):
   $ curl http://localhost:5000/health    # Python
   $ curl http://localhost:500/health    # JavaScript
   $ curl http://localhost:500/health    # Java
   $ curl http://localhost:500/health    # C#

. EJECUTAR PRUEBAS:
   $ python test_microservices.py

. ANALIZAR CÓDIGO:
   $ curl -X POST http://localhost:5000/analyze \\
     -H "Content-Type: application/json" \\
     -d '{
       "code": "import os\\nos.system(\\"ls\\")",
       "filename": "test.py"
     }'

5. LEER DOCUMENTACIÓN:
   $ cat README.md

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 PUERTOS:
   • Python Analyzer:      5000
   • JavaScript Analyzer:  500
   • Java Analyzer:        500
   • C# Analyzer:          500

📍 SERVICIOS:
   • /health              → Verificar estado
   • /analyze             → Analizar código
   • /analyze/file        → Analizar archivo

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✨ Arquitectura:
   • Modelo Universal: Normaliza ASTs de diferentes lenguajes
   • Microservicios: Cada lenguaje es un servicio independiente
   • Análisis de Seguridad: Detección de vulnerabilidades común
   • Docker: Fácil deployment y escalabilidad

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """)

def main():
    print_banner()
    
    # Verificaciones
    if not check_docker():
        sys.exit()
    
    if not check_structure():
        print("\n Estructura del proyecto incompleta")
        sys.exit()
    
    print("\n    Estructura verificada")
    
    # Construir imágenes
    if not build_images():
        sys.exit()
    
    # Mostrar siguientes pasos
    show_next_steps()

if __name__ == "__main__":
    main()

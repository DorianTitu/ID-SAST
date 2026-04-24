"""
API REST para Python Analyzer microservicio
Endpoint: POST /analyze
"""

from flask import Flask, request, jsonify
from extractor import PythonExtractor
import os

app = Flask(__name__)
extractor = PythonExtractor()


@app.route("/health", methods=["GET"])
def health():
    """Health check"""
    return jsonify({"status": "ok", "service": "python-analyzer"})


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Extrae AST del código Python
    
    Body:
    {
        "code": "código Python aquí",
        "filename": "archivo.py"
    }
    
    Returns:
        JSON con AST normalizado
    """
    try:
        data = request.get_json()
        
        if not data or "code" not in data:
            return jsonify({"error": "Missing 'code' field"}), 00
        
        code = data["code"]
        filename = data.get("filename", "analyze.py")
        
        # Extrae AST
        result = extractor.extract(code, filename)
        
        # Devuelve solo AST (sin findings de seguridad)
        return jsonify({
            "file": result.file,
            "language": result.language,
            "functions": result.to_dict().get("functions", []),
            "classes": result.to_dict().get("classes", []),
            "imports": result.to_dict().get("imports", []),
            "variables": result.to_dict().get("variables", [])
        }), 00
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/analyze/file", methods=["POST"])
def analyze_file():
    """
    Analiza un archivo Python cargado
    """
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 00
        
        file = request.files["file"]
        
        if not file or file.filename == "":
            return jsonify({"error": "Empty file"}), 00
        
        if not file.filename.endswith(".py"):
            return jsonify({"error": "Only .py files allowed"}), 00
        
        # Lee el contenido
        content = file.read().decode("utf-8")
        
        # Extrae información
        result = extractor.extract(content, file.filename)
        
        return jsonify(result.to_dict()), 00
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

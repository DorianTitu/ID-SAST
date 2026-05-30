"""
main.py

PY-SAST Main Orchestrator.

Responsabilidades:
- Coordinar TODO el pipeline SAST
- Ejecutar AST/CFG/DFG
- Ejecutar Taint Analysis
- Ejecutar Matching
- Ejecutar IA
- Generar reglas
- Guardar en MongoDB
- Generar reportes

Flujo:

Source Code
    ↓
AST Parser
    ↓
Normalizer
    ↓
CFG Builder  (si ENABLE_CFG)
    ↓
DFG Builder  (si ENABLE_DFG)
    ↓
Taint Analysis (si ENABLE_TAINT_ANALYSIS)
    ↓
Pattern Matching
    ↓
Semantic Analysis (si ENABLE_SEMANTIC_ANALYSIS)
    ↓
Vulnerability Classification
    ↓
Rule Generation (si ENABLE_RULE_GENERATION)
    ↓
MongoDB Persistence (si USE_PERSISTENCE)
    ↓
Reports
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

# =============================================================
# PARSERS
# =============================================================

from core.parsers.ast_parser   import ASTParser
from core.parsers.normalizer   import ASTNormalizer
from core.parsers.cfg_builder  import CFGBuilder
from core.parsers.dfg_builder  import DFGBuilder

# =============================================================
# ANALYZERS
# =============================================================

from core.analyzers.taint_analyzer           import TaintAnalyzer
from core.analyzers.pattern_matcher          import PatternMatcher
from core.analyzers.semantic_analyzer        import SemanticAnalyzer
from core.analyzers.vulnerability_classifier import VulnerabilityClassifier

# =============================================================
# AI
# =============================================================

from core.ai.rule_generator import RuleGenerator

# =============================================================
# REPORTS
# =============================================================

from reports.json_report    import JSONReport
from reports.console_report import ConsoleReport
from reports.html_report    import HTMLReport

# =============================================================
# CONFIG
# =============================================================

from config.settings import Settings


class PySAST:
    """
    Main SAST Engine.
    """

    # =========================================================
    # INIT
    # Corrección #3: acepta los flags que scanner.py pasa.
    # Corrección #2: repositorios NO se instancian aquí;
    # se crean en scan_project() después de conectar MongoDB.
    # Corrección #4: TaintAnalyzer se instancia por archivo,
    # no globalmente, porque requiere dfg_data en __init__.
    # =========================================================

    def __init__(
        self,
        use_ai:    bool = True,
        verbose:   bool = False,
        json_only: bool = False,
        html_only: bool = False,
    ):

        # Corrección #3: guardamos los flags para usarlos
        # en scan_project() y respetar las decisiones del CLI.
        self.use_ai    = use_ai and Settings.USE_GEMINI
        self.verbose   = verbose
        self.json_only = json_only
        self.html_only = html_only

        # -------------------------------------------------
        # Parsers (stateless, reutilizables entre archivos)
        # -------------------------------------------------

        self.ast_parser  = ASTParser()
        self.normalizer  = ASTNormalizer()
        self.cfg_builder = CFGBuilder()
        self.dfg_builder = DFGBuilder()

        # -------------------------------------------------
        # Analyzers stateless
        # -------------------------------------------------

        self.semantic_analyzer        = SemanticAnalyzer()
        self.vulnerability_classifier = VulnerabilityClassifier()
        self.rule_generator           = RuleGenerator()

        # -------------------------------------------------
        # Reports
        # -------------------------------------------------

        self.json_report    = JSONReport()
        self.console_report = ConsoleReport()
        self.html_report    = HTMLReport()

        # -------------------------------------------------
        # Corrección #1: importamos MongoDB con el nombre
        # correcto. La conexión se abre en scan_project().
        # -------------------------------------------------

        from database.mongodb import MongoDB
        self._MongoDB = MongoDB

    # =========================================================
    # MAIN SCAN
    # =========================================================

    def scan_project(self, project_path: str) -> Dict:
        """
        Ejecuta el pipeline SAST completo sobre un proyecto.
        """

        print("\n[PY-SAST] Starting scan...\n")

        findings:             List[Dict] = []
        generated_rules:      List[Dict] = []
        ai_analysis_results:  List[Dict] = []

        # Corrección #10: respetamos BLOCKED_DIRECTORIES.
        scanned_files = self._find_python_files(project_path)

        print(f"[+] Found {len(scanned_files)} Python files")

        # =====================================================
        # CONNECT MONGO
        # Corrección #2: conectamos ANTES de instanciar
        # repositorios para que get_collection() no falle.
        # =====================================================

        mongo              = None
        rule_repository    = None
        analysis_repository = None

        if Settings.USE_PERSISTENCE:

            mongo = self._MongoDB()

            if mongo.connect():

                from database.rule_repository     import RuleRepository
                from database.analysis_repository import AnalysisRepository

                rule_repository     = RuleRepository(mongo)
                analysis_repository = AnalysisRepository(mongo)

            else:
                print(
                    "[WARNING] MongoDB unavailable. "
                    "Running without persistence."
                )
                mongo = None

        # =====================================================
        # SCAN FILES
        # =====================================================

        for file_path in scanned_files:

            if self.verbose:
                print(f"\n[SCAN] {file_path}")

            try:

                # Corrección #12: verificamos tamaño antes
                # de leer el archivo completo en memoria.
                file_size = os.path.getsize(file_path)

                if file_size > Settings.MAX_FILE_SIZE:
                    print(
                        f"[SKIP] {file_path} "
                        f"({file_size} bytes > "
                        f"MAX_FILE_SIZE {Settings.MAX_FILE_SIZE})"
                    )
                    continue

                with open(file_path, "r", encoding="utf-8") as f:
                    code = f.read()

                if not code.strip():
                    continue

                # =============================================
                # AST
                # =============================================

                ast_data = self.ast_parser.parse(code, file_path)

                # =============================================
                # NORMALIZATION
                # =============================================

                normalized_ast = self.normalizer.normalize(ast_data)

                # =============================================
                # CFG
                # Corrección #11: respetamos ENABLE_CFG.
                # =============================================

                cfg_data = {}

                if Settings.ENABLE_CFG:
                    cfg_data = self.cfg_builder.build(normalized_ast)

                # =============================================
                # DFG
                # Corrección #11: respetamos ENABLE_DFG.
                # =============================================

                dfg_data = {"nodes": [], "edges": [], "tainted_variables": []}

                if Settings.ENABLE_DFG:
                    dfg_data = self.dfg_builder.build_from_code(code)

                # =============================================
                # TAINT ANALYSIS
                # Corrección #4: TaintAnalyzer recibe dfg_data
                # en su constructor, se instancia por archivo.
                # Corrección #11: respetamos ENABLE_TAINT_ANALYSIS.
                # =============================================

                taint_findings: List[Dict] = []

                if Settings.ENABLE_TAINT_ANALYSIS and dfg_data["nodes"]:

                    taint_analyzer = TaintAnalyzer(dfg_data)
                    taint_findings = taint_analyzer.analyze()

                # =============================================
                # PATTERN MATCHING
                # Corrección #5: PatternMatcher recibe findings
                # y rules en su constructor; match() sin args.
                # =============================================

                matched_rules: Dict = {"matches": [], "unknown_patterns": []}

                if taint_findings:

                    from core.rules.built_in_rules import get_all_rules

                    rules_for_matcher = [
                        r.to_dict() for r in get_all_rules()
                    ]

                    pattern_matcher = PatternMatcher(
                        taint_findings,
                        rules_for_matcher,
                    )

                    matched_rules = pattern_matcher.match()

                # =============================================
                # SEMANTIC ANALYSIS
                # Corrección #6: usamos analyze_many() con la
                # firma correcta (finding, ast, cfg, dfg).
                # Corrección #11: respetamos flag semántico.
                # =============================================

                semantic_results: List[Dict] = []

                if Settings.ENABLE_SEMANTIC_ANALYSIS and taint_findings:

                    raw_semantic = self.semantic_analyzer.analyze_many(
                        findings=taint_findings,
                        ast_data=normalized_ast,
                        cfg_data=cfg_data,
                        dfg_data=dfg_data,
                    )

                    semantic_results = self.semantic_analyzer.export_results(
                        raw_semantic
                    )

                    ai_analysis_results.extend(semantic_results)

                # =============================================
                # VULNERABILITY CLASSIFICATION
                # Corrección #7: classify() recibe el finding
                # del TaintAnalyzer, no el semántico.
                # =============================================

                classified_findings: List[Dict] = []

                for taint_finding in taint_findings:

                    classified = self.vulnerability_classifier.classify(
                        taint_finding
                    ).to_dict()

                    classified["file"] = file_path

                    classified_findings.append(classified)

                findings.extend(classified_findings)

                # =============================================
                # RULE GENERATION
                # Corrección #8: save_rule() recibe parámetros
                # nombrados, no un dict completo.
                # Corrección #11: respetamos ENABLE_RULE_GENERATION.
                # =============================================

                if Settings.ENABLE_RULE_GENERATION and taint_findings:

                    for taint_finding in taint_findings:

                        rule = self.rule_generator.generate_rule(
                            taint_finding
                        )

                        if not self.rule_generator.validate_rule(rule):
                            continue

                        generated_rules.append(rule)

                        if rule_repository:

                            # Corrección #8: parámetros nombrados.
                            try:
                                rule_repository.save_rule(
                                    vulnerability=rule.get(
                                        "vulnerability_type", "UNKNOWN"
                                    ),
                                    pattern={
                                        "source_type": rule.get(
                                            "source_pattern"
                                        ),
                                        "sink_type": rule.get(
                                            "sink_pattern"
                                        ),
                                        "transformations": [],
                                    },
                                    graph_signature=rule.get(
                                        "subgraph", {}
                                    ),
                                    confidence=rule.get("confidence", 0.0),
                                    created_by="gemini",
                                )
                            except Exception as e:
                                print(f"[WARNING] Could not save rule: {e}")

                # =============================================
                # SAVE ANALYSIS PER FILE
                # Corrección #9: save_analysis() recibe
                # parámetros nombrados correctos.
                # =============================================

                if analysis_repository and classified_findings:

                    try:
                        analysis_repository.save_analysis(
                            project_name=Path(project_path).name,
                            scanned_files=1,
                            vulnerabilities=classified_findings,
                            metadata={
                                "file":           file_path,
                                "matched_rules":  matched_rules,
                                "semantic_count": len(semantic_results),
                            },
                        )
                    except Exception as e:
                        print(f"[WARNING] Could not save analysis: {e}")

            except Exception as e:

                print(f"[ERROR] {file_path}: {e}")

                if self.verbose or Settings.DEBUG:
                    import traceback
                    traceback.print_exc()

        # =====================================================
        # GENERATE REPORTS
        # =====================================================

        report = self.json_report.generate(
            project_name=Path(project_path).name,
            scanned_files=scanned_files,
            findings=findings,
            ai_analysis=ai_analysis_results,
            generated_rules=generated_rules,
        )

        json_path: Optional[str] = None
        html_path: Optional[str] = None

        # Corrección #3: respetamos json_only / html_only.
        if not self.html_only:
            try:
                json_path = self.json_report.save(report)
            except Exception as e:
                print(f"[WARNING] Could not save JSON report: {e}")

        if not self.json_only:
            try:
                html_path = self.html_report.generate(report)
            except Exception as e:
                print(f"[WARNING] Could not save HTML report: {e}")

        if not self.json_only and not self.html_only:
            self.console_report.generate(
                project_name=Path(project_path).name,
                scanned_files=scanned_files,
                findings=findings,
            )

        # =====================================================
        # CLOSE MONGO
        # Corrección #13: método correcto es disconnect().
        # =====================================================

        if mongo:
            mongo.disconnect()

        # =====================================================
        # SUMMARY
        # =====================================================

        print("\n[REPORTS]")

        if json_path:
            print(f"  JSON : {json_path}")

        if html_path:
            print(f"  HTML : {html_path}")

        print(
            f"\n[PY-SAST] Scan completed. "
            f"Files: {len(scanned_files)} | "
            f"Findings: {len(findings)} | "
            f"Rules generated: {len(generated_rules)}\n"
        )

        return report

    # =========================================================
    # FIND PYTHON FILES
    # Corrección #10: filtra BLOCKED_DIRECTORIES de Settings
    # para evitar analizar venv, __pycache__, .git, etc.
    # =========================================================

    def _find_python_files(self, project_path: str) -> List[str]:
        """
        Busca archivos .py respetando BLOCKED_DIRECTORIES
        y ALLOWED_EXTENSIONS de Settings.
        """

        python_files = []

        for root, dirs, files in os.walk(project_path):

            # Corrección #10: filtramos in-place para que
            # os.walk no descienda a directorios bloqueados.
            dirs[:] = [
                d for d in dirs
                if d not in Settings.BLOCKED_DIRECTORIES
            ]

            for file in files:

                if not any(
                    file.endswith(ext)
                    for ext in Settings.ALLOWED_EXTENSIONS
                ):
                    continue

                full_path = os.path.join(root, file)
                python_files.append(full_path)

        return python_files


# =============================================================
# ENTRYPOINT
# Corrección #14: initialize_directories() se llama antes
# de instanciar PySAST para que los directorios de reports
# y storage existan cuando los reporters intenten escribir.
# =============================================================

if __name__ == "__main__":

    import argparse

    Settings.initialize_directories()

    parser = argparse.ArgumentParser(
        description="PY-SAST Scanner"
    )

    parser.add_argument(
        "path",
        help="Path to Python project",
    )

    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable Gemini AI analysis",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    scanner = PySAST(
        use_ai  = not args.no_ai,
        verbose = args.verbose,
    )

    scanner.scan_project(args.path)
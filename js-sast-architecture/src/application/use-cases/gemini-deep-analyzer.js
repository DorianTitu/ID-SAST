/**
 * GEMINI DEEP ANALYZER
 * Integración con Google Gemini para análisis semántico profundo
 * Taint Analysis + Meta-Rule Generation
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');

class GeminiDeepAnalyzer {
  constructor(apiKey = null) {
    this.apiKey = apiKey || process.env.GOOGLE_GEMINI_API_KEY;
    this.client = this.apiKey ? new GoogleGenerativeAI(this.apiKey) : null;
    this.model = this.client ? this.client.getGenerativeModel({ model: 'gemini-1.5-pro' }) : null;
    this.isAvailable = !!this.client;
    
    this.systemPrompt = `Contexto: Eres un modelo de Deep Learning experto en ciberseguridad y análisis de flujo de datos en grafos de código.

Tu Misión: Analizar el JSON adjunto que contiene el AST, el CFG y el DFG de un fragmento de código JavaScript. Debes realizar un Taint Analysis semántico para identificar vulnerabilidades que las reglas estáticas simples podrían pasar por alto.

Tareas específicas:

1. Data Lineage: Rastrea el origen de cada variable marcada como "Source" en el DFG. Si una variable proviene de req.body, req.query, req.params o process.env, considérala "contaminada" (tainted).

2. Transformation Logic: Analiza las funciones intermedias por las que pasa el dato:
   - Si el dato pasa por parseInt(), Number(), una librería de saneamiento conocida (DOMPurify, validator, sanitizer, escape), marca el flujo como SAFE (MITIGATED).
   - Si el dato solo se concatena o se interpola en un string, marca el flujo como VULNERABLE.
   - Si la transformación es ambigua o desconocida, marca como MEDIUM_RISK.

3. Sink Detection: Identifica si el dato contaminado llega a un "Sink" (ej. db.query, db.raw, db.execute, eval, child_process.exec, .innerHTML, .outerHTML, .insertAdjacentHTML, setTimeout, setInterval).

4. Meta-Rule Generation: Basado en este patrón, genera una regla lógica predictiva que podamos usar para entrenar modelos más pequeños o mejorar nuestro parser de Tree-sitter.

Retorna ESTRICTAMENTE este JSON (sin markdown, sin explicaciones extra):`;
  }

  async analyze(dfgAnalysis, astData, code) {
    if (!this.isAvailable) {
      console.warn('[GEMINI] API Key no disponible. Ejecutando análisis local fallback.');
      return this.fallbackAnalysis(dfgAnalysis, astData, code);
    }

    try {
      const userMessage = `Analiza este grafo de flujo de datos y genera la regla de seguridad:

AST: ${JSON.stringify(astData, null, 2)}

DFG Analysis: ${JSON.stringify(dfgAnalysis, null, 2)}

Código: ${code}

Retorna SOLO el JSON sin explicaciones adicionales.`;

      const result = await this.model.generateContent({
        contents: [
          {
            role: 'user',
            parts: [{ text: userMessage }]
          }
        ],
        systemInstruction: this.systemPrompt
      });

      const responseText = result.response.text();
      
      // Extraer JSON de la respuesta
      const jsonMatch = responseText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.warn('[GEMINI] No valid JSON found in response. Using fallback.');
        return this.fallbackAnalysis(dfgAnalysis, astData, code);
      }

      const analysis = JSON.parse(jsonMatch[0]);
      
      return {
        success: true,
        source: 'gemini',
        analysis: analysis,
        raw_response: responseText,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('[GEMINI] Error during analysis:', error.message);
      return this.fallbackAnalysis(dfgAnalysis, astData, code);
    }
  }

  fallbackAnalysis(dfgAnalysis, astData, code) {
    /**
     * Fallback: Análisis local sin Gemini
     * Implementa la misma lógica que Gemini pero en JavaScript puro
     */
    
    const vulnerabilities = dfgAnalysis.vulnerabilities || [];
    const analysis = vulnerabilities.length > 0 ? vulnerabilities[0] : null;
    
    if (!analysis) {
      return {
        success: true,
        source: 'local_fallback',
        analysis: {
          vulnerability_detected: false,
          confidence_score: 0,
          taint_track: 'No vulnerabilities detected',
          issue: null,
          is_false_positive: true,
          deep_learning_rule: {
            pattern_name: 'SAFE_CODE',
            logic_threshold: 'No untrusted data flows to sinks'
          }
        },
        timestamp: new Date().toISOString()
      };
    }

    // Verificar si es un falso positivo (high confidence + sanitización)
    const isFalsePositive = analysis.sanitization_detected && analysis.confidence_score <= 25;

    const deepLearningRule = this.generateDeepLearningRule(analysis, code);

    return {
      success: true,
      source: 'local_fallback',
      analysis: {
        vulnerability_detected: !isFalsePositive,
        confidence_score: analysis.confidence_score / 100,
        taint_track: this.buildTaintTrack(analysis),
        issue: {
          cwe: analysis.cwe_id,
          severity: this.mapSeverity(analysis.confidence_score, analysis.sanitization_detected),
          description: analysis.recommendation
        },
        is_false_positive: isFalsePositive,
        deep_learning_rule: deepLearningRule
      },
      timestamp: new Date().toISOString()
    };
  }

  buildTaintTrack(analysis) {
    const path = analysis.data_path || [];
    const steps = path.map(node => `${node.type}(${node.value})`).join(' → ');
    return `Data flows from ${analysis.source} to ${analysis.sink}: ${steps}`;
  }

  generateDeepLearningRule(analysis, code) {
    const vulnType = analysis.vulnerability_type;
    const hasUntrustedSource = /req\.(body|query|params|headers|cookies)|process\.(env|argv)|userInput|input/.test(analysis.source);
    const hasSanitization = analysis.sanitization_detected;
    const hasDirectSink = /query|execute|run|exec|innerHTML|eval|child_process/.test(analysis.sink);

    let patternName = `${vulnType}_pattern`;
    let logicThreshold = '';

    if (vulnType === 'SQL_INJECTION') {
      logicThreshold = hasUntrustedSource && hasDirectSink && !hasSanitization
        ? 'UNTRUSTED_SOURCE && SQL_SINK && NO_SANITIZATION → CRITICAL'
        : 'UNTRUSTED_SOURCE && SQL_SINK && SANITIZATION → LOW';
    } else if (vulnType === 'XSS') {
      logicThreshold = hasUntrustedSource && /innerHTML|outerHTML/.test(analysis.sink) && !hasSanitization
        ? 'UNTRUSTED_SOURCE && DOM_SINK && NO_SANITIZATION → CRITICAL'
        : 'UNTRUSTED_SOURCE && DOM_SINK && SANITIZATION → LOW';
    } else if (vulnType === 'CODE_INJECTION') {
      logicThreshold = hasUntrustedSource && /eval|Function|setTimeout/.test(analysis.sink) && !hasSanitization
        ? 'UNTRUSTED_SOURCE && EVAL_SINK && NO_SANITIZATION → CRITICAL'
        : 'UNTRUSTED_SOURCE && EVAL_SINK && SANITIZATION → LOW';
    }

    return {
      pattern_name: patternName,
      logic_threshold: logicThreshold,
      confidence_factors: {
        has_untrusted_source: hasUntrustedSource,
        has_direct_sink: hasDirectSink,
        has_sanitization: hasSanitization,
        severity_score: analysis.confidence_score
      },
      training_data: {
        source_pattern: analysis.source.substring(0, 50),
        sink_pattern: analysis.sink.substring(0, 50),
        vulnerability_type: vulnType,
        was_mitigated: hasSanitization
      }
    };
  }

  mapSeverity(confidenceScore, hasSanitization) {
    if (hasSanitization) return 'LOW';
    if (confidenceScore >= 90) return 'CRITICAL';
    if (confidenceScore >= 70) return 'HIGH';
    if (confidenceScore >= 50) return 'MEDIUM';
    return 'LOW';
  }
}

module.exports = GeminiDeepAnalyzer;

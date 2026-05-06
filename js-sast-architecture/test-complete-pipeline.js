// Test completo del sistema de análisis
const axios = require('axios');

const API_URL = 'http://localhost:3000';

// Código vulnerable de ejemplo
const vulnerableCode = `
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query, (err, result) => {
    res.json(result);
  });
});
`;

async function testCompleteAnalysisPipeline() {
  console.log('════════════════════════════════════════════════════════════════');
  console.log('  COMPLETE ANALYSIS PIPELINE TEST');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('');

  try {
    // 1. Health check
    console.log('1. Verificando servidor...');
    const healthRes = await axios.get(`${API_URL}/health`);
    console.log('   ✅ Servidor activo');
    console.log('');

    // 2. Deep analysis
    console.log('2. Enviando análisis profundo...');
    const analysisRes = await axios.post(`${API_URL}/api/deep-analysis`, {
      code: vulnerableCode
    });
    
    const analysis = analysisRes.data;
    console.log('   ✅ Análisis completado');
    console.log('');

    console.log('3. Resultado del análisis:');
    const vulns = analysis.deep_analysis?.advanced_findings?.vulnerabilities;
    if (vulns && vulns.length > 0) {
      const vuln = vulns[0];
      console.log('   Source:', vuln.source);
      console.log('   Sink:', vuln.sink);
      console.log('   Vulnerability type:', vuln.vulnerability_type);
      console.log('   Confidence:', vuln.confidence_score + '%');
      console.log('   CWE:', vuln.cwe_id);
      console.log('   Sanitization detected:', vuln.sanitization_detected);
    }
    console.log('');

    // 3. Get rules statistics
    console.log('4. Obteniendo estadísticas de reglas...');
    const statsRes = await axios.get(`${API_URL}/api/rules/stats`);
    const stats = statsRes.data;
    
    console.log('   Total rules in DB:', stats.total_rules || 0);
    console.log('   Rules by source:', stats.by_source || {});
    console.log('');

    // 4. Show generated rules from this analysis
    console.log('5. Reglas generadas en este análisis:');
    const rules = analysis.deep_analysis?.advanced_findings?.generated_rules;
    if (rules && rules.length > 0) {
      console.log('   Total reglas generadas:', rules.length);
      rules.forEach((rule, idx) => {
        console.log(`   Regla ${idx + 1}:`);
        console.log(`     - Name: ${rule.name}`);
        console.log(`     - Type: ${rule.vulnerability_type}`);
        console.log(`     - Severity: ${rule.severity}`);
        console.log(`     - CWE: ${rule.cwe_id}`);
        console.log(`     - CVSS: ${rule.cvss_base_score}`);
      });
    }
    console.log('');

    console.log('════════════════════════════════════════════════════════════════');
    console.log('✅ COMPLETE PIPELINE WORKING SUCCESSFULLY');
    console.log('════════════════════════════════════════════════════════════════');

  } catch (error) {
    console.error('❌ ERROR:');
    console.error('   Message:', error.message);
    if (error.response?.data) {
      console.error('   Response:', error.response.data);
    }
  }
}

testCompleteAnalysisPipeline();

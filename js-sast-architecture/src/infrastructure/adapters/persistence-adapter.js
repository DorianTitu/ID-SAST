/**
 * Persistence Adapter
 * Manages storage and retrieval of generated security rules
 * Uses JSONL for scalable rule persistence and CSV export for ML datasets
 */

const fs = require('fs');
const path = require('path');

class PersistenceAdapter {
  constructor(storageDir = './data/rules') {
    this.storageDir = storageDir;
    this.rulesFile = path.join(storageDir, 'generated_rules.jsonl');
    this.rulesIndexFile = path.join(storageDir, 'rules_index.json');
    this.ensureStorageDir();
  }

  ensureStorageDir() {
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  /**
   * Save a generated deep learning rule
   * @param {Object} deepLearningRule - Rule object from Gemini/Local analysis
   * @param {Object} vulnerabilityAnalysis - Vulnerability context
   * @param {string} source - Source of rule ('gemini' or 'local_fallback')
   * @returns {string} Rule ID
   */
  saveRule(deepLearningRule, vulnerabilityAnalysis, source = 'unknown') {
    try {
      const ruleRecord = {
        id: `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        source: source,
        rule: deepLearningRule,
        vulnerability: {
          type: vulnerabilityAnalysis.vulnerability_type,
          severity: vulnerabilityAnalysis.cwe_id,
          confidence: vulnerabilityAnalysis.confidence_score
        }
      };

      fs.appendFileSync(this.rulesFile, JSON.stringify(ruleRecord) + '\n');
      this.updateIndex(ruleRecord);
      return ruleRecord.id;
    } catch (error) {
      console.error('[PERSISTENCE] Error saving rule:', error.message);
      return null;
    }
  }

  updateIndex(ruleRecord) {
    try {
      let index = {};
      if (fs.existsSync(this.rulesIndexFile)) {
        index = JSON.parse(fs.readFileSync(this.rulesIndexFile, 'utf8'));
      }

      const key = ruleRecord.rule.pattern_name;
      if (!index[key]) index[key] = [];

      index[key].push({
        id: ruleRecord.id,
        timestamp: ruleRecord.timestamp,
        source: ruleRecord.source,
        confidence: ruleRecord.vulnerability.confidence
      });

      fs.writeFileSync(this.rulesIndexFile, JSON.stringify(index, null, 2));
    } catch (error) {
      console.error('[PERSISTENCE] Error updating index:', error.message);
    }
  }

  getAllRules() {
    try {
      if (!fs.existsSync(this.rulesFile)) return [];
      const lines = fs.readFileSync(this.rulesFile, 'utf8').trim().split('\n');
      return lines.filter(line => line.trim()).map(line => JSON.parse(line));
    } catch (error) {
      console.error('[PERSISTENCE] Error reading rules:', error.message);
      return [];
    }
  }

  getRulesByPattern(patternName) {
    try {
      const rules = this.getAllRules();
      return rules.filter(r => r.rule.pattern_name === patternName);
    } catch (error) {
      console.error('[PERSISTENCE] Error filtering rules:', error.message);
      return [];
    }
  }

  getRulesByType(vulnerabilityType) {
    try {
      const rules = this.getAllRules();
      return rules.filter(r => r.vulnerability.type === vulnerabilityType || r.vulnerability.severity === vulnerabilityType);
    } catch (error) {
      console.error('[PERSISTENCE] Error filtering by type:', error.message);
      return [];
    }
  }

  getRulesBySource(source) {
    try {
      const rules = this.getAllRules();
      return rules.filter(r => r.source === source);
    } catch (error) {
      console.error('[PERSISTENCE] Error filtering by source:', error.message);
      return [];
    }
  }

  getTrainingDataset() {
    try {
      const rules = this.getAllRules();
      return rules.map(r => ({
        pattern: r.rule.pattern_name,
        logic: r.rule.logic_threshold,
        confidence: r.rule.confidence_factors.severity_score,
        training_data: r.rule.training_data
      }));
    } catch (error) {
      console.error('[PERSISTENCE] Error generating dataset:', error.message);
      return [];
    }
  }

  exportAsCSV(filename = 'rules_dataset.csv') {
    try {
      const rules = this.getAllRules();
      let csv = 'id,timestamp,pattern_name,logic_threshold,vulnerability_type,confidence_score,was_mitigated,source_pattern,sink_pattern\n';
      
      rules.forEach(r => {
        csv += `"${r.id}","${r.timestamp}","${r.rule.pattern_name}","${r.rule.logic_threshold}","${r.vulnerability.type}",${r.rule.confidence_factors.severity_score},${r.rule.training_data.was_mitigated},"${r.rule.training_data.source_pattern}","${r.rule.training_data.sink_pattern}"\n`;
      });

      const outputPath = path.join(this.storageDir, filename);
      fs.writeFileSync(outputPath, csv);
      console.log(`[PERSISTENCE] Exported ${rules.length} rules to ${outputPath}`);
      return outputPath;
    } catch (error) {
      console.error('[PERSISTENCE] Error exporting CSV:', error.message);
      return null;
    }
  }

  getStatistics() {
    try {
      const rules = this.getAllRules();
      const patterns = {}, severities = {}, sources = { gemini: 0, local_fallback: 0, unknown: 0 };

      rules.forEach(r => {
        patterns[r.rule.pattern_name] = (patterns[r.rule.pattern_name] || 0) + 1;
        severities[r.vulnerability.severity] = (severities[r.vulnerability.severity] || 0) + 1;
        sources[r.source] = (sources[r.source] || 0) + 1;
      });

      return {
        total_rules: rules.length,
        patterns_count: Object.keys(patterns).length,
        patterns: patterns,
        severities: severities,
        sources: sources,
        avg_confidence: rules.length > 0
          ? (rules.reduce((sum, r) => sum + r.rule.confidence_factors.severity_score, 0) / rules.length).toFixed(2)
          : 0
      };
    } catch (error) {
      console.error('[PERSISTENCE] Error calculating statistics:', error.message);
      return null;
    }
  }
}

module.exports = PersistenceAdapter;

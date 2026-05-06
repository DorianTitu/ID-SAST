/**
 * MongoDB Persistence Adapter
 * Manages storage and retrieval of generated security rules
 * Uses MongoDB Atlas for centralized, scalable rules management
 */

const { MongoClient } = require('mongodb');
const { config } = require('../../../config/env');

class MongoDBAdapter {
  constructor() {
    this.client = null;
    this.db = null;
    this.rulesCollection = null;
    this.analysisCollection = null;
    this.isConnected = false;
  }

  /**
   * Connect to MongoDB Atlas
   * @returns {Promise<boolean>} Connection success status
   */
  async connect() {
    try {
      if (this.isConnected) {
        console.log('[MongoDB] Already connected');
        return true;
      }

      this.client = new MongoClient(config.MONGODB_URI, {
        maxPoolSize: 10,
        minPoolSize: 2,
        useUnifiedTopology: true,
        ssl: true,
        retryWrites: true,
        w: 'majority',
        serverSelectionTimeoutMS: 15000,
        socketTimeoutMS: 15000,
      });

      await this.client.connect();
      this.db = this.client.db(config.MONGODB_DB_NAME);
      this.rulesCollection = this.db.collection(config.MONGODB_RULES_COLLECTION);
      this.analysisCollection = this.db.collection(config.MONGODB_ANALYSIS_COLLECTION);

      // Create indexes for better query performance
      await this.createIndexes();

      this.isConnected = true;
      console.log(' [MongoDB] Connected to Atlas');
      console.log(`   Database: ${config.MONGODB_DB_NAME}`);
      console.log(`   Rules Collection: ${config.MONGODB_RULES_COLLECTION}`);
      console.log(`   Analysis Collection: ${config.MONGODB_ANALYSIS_COLLECTION}`);

      return true;
    } catch (error) {
      console.error(' [MongoDB] Connection failed:', error.message);
      this.isConnected = false;
      return false;
    }
  }

  /**
   * Create MongoDB indexes for efficient queries
   */
  async createIndexes() {
    try {
      // Index for pattern_name queries
      await this.rulesCollection.createIndex({ 'rule.pattern_name': 1 });

      // Index for vulnerability type
      await this.rulesCollection.createIndex({ 'vulnerability.type': 1 });

      // Index for timestamp (for sorting)
      await this.rulesCollection.createIndex({ timestamp: -1 });

      // Index for source (gemini vs local_fallback)
      await this.rulesCollection.createIndex({ source: 1 });

      // TTL index for auto-deletion of old records (optional)
      // Uncomment if you want rules older than 365 days to auto-delete
      // await this.rulesCollection.createIndex({ timestamp: 1 }, { expireAfterSeconds: 31536000 });

      console.log('[MongoDB] Indexes created successfully');
    } catch (error) {
      console.error('[MongoDB] Error creating indexes:', error.message);
    }
  }

  /**
   * Save a generated deep learning rule
   * @param {Object} deepLearningRule - Rule object from Gemini/Local analysis
   * @param {Object} vulnerabilityAnalysis - Vulnerability context
   * @param {string} source - Source of rule ('gemini' or 'local_fallback')
   * @returns {Promise<string>} Rule ID (MongoDB _id)
   */
  async saveRule(deepLearningRule, vulnerabilityAnalysis, source = 'unknown') {
    try {
      if (!this.isConnected) {
        console.warn('[MongoDB] Not connected, attempting to save to local fallback');
        return null;
      }

      const ruleRecord = {
        _id: `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        source: source, // 'gemini' or 'local_fallback'
        rule: deepLearningRule,
        vulnerability: {
          type: vulnerabilityAnalysis.vulnerability_type,
          severity: vulnerabilityAnalysis.cwe_id,
          confidence: vulnerabilityAnalysis.confidence_score
        },
        metadata: {
          createdAt: new Date(),
          version: '2.0.0',
          system: 'js-sast'
        }
      };

      const result = await this.rulesCollection.insertOne(ruleRecord);
      console.log(`[MongoDB] Rule saved: ${ruleRecord._id}`);
      return ruleRecord._id;
    } catch (error) {
      console.error('[MongoDB] Error saving rule:', error.message);
      return null;
    }
  }

  /**
   * Get all rules from database
   * @returns {Promise<Array>} Array of rules
   */
  async getAllRules() {
    try {
      if (!this.isConnected) {
        console.warn('[MongoDB] Not connected');
        return [];
      }

      const rules = await this.rulesCollection
        .find({})
        .sort({ timestamp: -1 })
        .toArray();

      return rules;
    } catch (error) {
      console.error('[MongoDB] Error fetching all rules:', error.message);
      return [];
    }
  }

  /**
   * Get rules by pattern name
   * @param {string} patternName - Pattern name to search
   * @returns {Promise<Array>} Rules matching the pattern
   */
  async getRulesByPattern(patternName) {
    try {
      if (!this.isConnected) return [];

      const rules = await this.rulesCollection
        .find({ 'rule.pattern_name': patternName })
        .sort({ timestamp: -1 })
        .toArray();

      return rules;
    } catch (error) {
      console.error('[MongoDB] Error fetching rules by pattern:', error.message);
      return [];
    }
  }

  /**
   * Get rules by vulnerability type
   * @param {string} vulnerabilityType - Vulnerability type (CWE-89, CWE-79, etc.)
   * @returns {Promise<Array>} Rules for this vulnerability type
   */
  async getRulesByVulnerabilityType(vulnerabilityType) {
    try {
      if (!this.isConnected) return [];

      const rules = await this.rulesCollection
        .find({ 'vulnerability.type': vulnerabilityType })
        .sort({ timestamp: -1 })
        .toArray();

      return rules;
    } catch (error) {
      console.error('[MongoDB] Error fetching rules by type:', error.message);
      return [];
    }
  }

  /**
   * Get rules by source (gemini or local_fallback)
   * @param {string} source - Source type
   * @returns {Promise<Array>} Rules from this source
   */
  async getRulesBySource(source) {
    try {
      if (!this.isConnected) return [];

      const rules = await this.rulesCollection
        .find({ source: source })
        .sort({ timestamp: -1 })
        .toArray();

      return rules;
    } catch (error) {
      console.error('[MongoDB] Error fetching rules by source:', error.message);
      return [];
    }
  }

  /**
   * Get detailed statistics about the rules database
   * @returns {Promise<Object>} Statistics object
   */
  async getStatistics() {
    try {
      if (!this.isConnected) return null;

      const totalRules = await this.rulesCollection.countDocuments();

      // Get unique patterns
      const patterns = await this.rulesCollection.distinct('rule.pattern_name');

      // Get unique vulnerability types
      const vulnerabilityTypes = await this.rulesCollection.distinct('vulnerability.type');

      // Count rules by source
      const geminiRules = await this.rulesCollection.countDocuments({ source: 'gemini' });
      const fallbackRules = await this.rulesCollection.countDocuments({ source: 'local_fallback' });

      // Calculate average confidence
      const pipeline = [
        {
          $group: {
            _id: null,
            avgConfidence: { $avg: '$rule.confidence_factors.severity_score' }
          }
        }
      ];
      const avgResult = await this.rulesCollection.aggregate(pipeline).toArray();
      const avgConfidence = avgResult.length > 0 ? avgResult[0].avgConfidence.toFixed(2) : 0;

      // Get pattern counts
      const patternStats = await this.rulesCollection
        .aggregate([
          { $group: { _id: '$rule.pattern_name', count: { $sum: 1 } } },
          { $sort: { count: -1 } }
        ])
        .toArray();

      const patterns_count = patternStats.reduce((acc, p) => {
        acc[p._id] = p.count;
        return acc;
      }, {});

      return {
        total_rules: totalRules,
        patterns_count: patterns.length,
        patterns: patterns_count,
        vulnerability_types: vulnerabilityTypes.length,
        sources: {
          gemini: geminiRules,
          local_fallback: fallbackRules
        },
        avg_confidence: avgConfidence,
        database: config.MONGODB_DB_NAME,
        collection: config.MONGODB_RULES_COLLECTION
      };
    } catch (error) {
      console.error('[MongoDB] Error calculating statistics:', error.message);
      return null;
    }
  }

  /**
   * Save analysis result to database
   * @param {Object} analysisData - Complete analysis result
   * @returns {Promise<string>} Analysis ID
   */
  async saveAnalysis(analysisData) {
    try {
      if (!this.isConnected) return null;

      const analysisRecord = {
        _id: `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        ...analysisData,
        metadata: {
          createdAt: new Date(),
          version: '2.0.0',
          system: 'js-sast'
        }
      };

      const result = await this.analysisCollection.insertOne(analysisRecord);
      console.log(`[MongoDB] Analysis saved: ${analysisRecord._id}`);
      return analysisRecord._id;
    } catch (error) {
      console.error('[MongoDB] Error saving analysis:', error.message);
      return null;
    }
  }

  /**
   * Export rules as array (for CSV or other formats)
   * @returns {Promise<Array>} Rules ready for export
   */
  async exportRules() {
    try {
      if (!this.isConnected) return [];

      const rules = await this.getAllRules();

      return rules.map(r => ({
        id: r._id,
        timestamp: r.timestamp,
        pattern_name: r.rule.pattern_name,
        logic_threshold: r.rule.logic_threshold,
        vulnerability_type: r.vulnerability.type,
        confidence_score: r.rule.confidence_factors.severity_score,
        was_mitigated: r.rule.training_data.was_mitigated,
        source_pattern: r.rule.training_data.source_pattern,
        sink_pattern: r.rule.training_data.sink_pattern,
        source: r.source
      }));
    } catch (error) {
      console.error('[MongoDB] Error exporting rules:', error.message);
      return [];
    }
  }

  /**
   * Delete a rule by ID
   * @param {string} ruleId - Rule ID to delete
   * @returns {Promise<boolean>} Success status
   */
  async deleteRule(ruleId) {
    try {
      if (!this.isConnected) return false;

      const result = await this.rulesCollection.deleteOne({ _id: ruleId });
      console.log(`[MongoDB] Rule deleted: ${ruleId}`);
      return result.deletedCount > 0;
    } catch (error) {
      console.error('[MongoDB] Error deleting rule:', error.message);
      return false;
    }
  }

  /**
   * Update a rule
   * @param {string} ruleId - Rule ID to update
   * @param {Object} updateData - Data to update
   * @returns {Promise<boolean>} Success status
   */
  async updateRule(ruleId, updateData) {
    try {
      if (!this.isConnected) return false;

      const result = await this.rulesCollection.updateOne(
        { _id: ruleId },
        { $set: { ...updateData, updatedAt: new Date() } }
      );
      console.log(`[MongoDB] Rule updated: ${ruleId}`);
      return result.modifiedCount > 0;
    } catch (error) {
      console.error('[MongoDB] Error updating rule:', error.message);
      return false;
    }
  }

  /**
   * Close MongoDB connection
   */
  async disconnect() {
    try {
      if (this.client) {
        await this.client.close();
        this.isConnected = false;
        console.log('[MongoDB] Connection closed');
      }
    } catch (error) {
      console.error('[MongoDB] Error closing connection:', error.message);
    }
  }

  /**
   * Get database status
   * @returns {Object} Status information
   */
  getStatus() {
    return {
      connected: this.isConnected,
      database: this.isConnected ? config.MONGODB_DB_NAME : 'N/A',
      uri: config.MONGODB_URI,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = MongoDBAdapter;

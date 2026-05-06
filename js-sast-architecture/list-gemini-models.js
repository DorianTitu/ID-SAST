// List available models in Gemini API
require('dotenv').config({ path: require('path').join(__dirname, 'config/.env') });
const { GoogleGenerativeAI } = require('@google/generative-ai');

const apiKey = process.env.GOOGLE_GEMINI_API_KEY;

console.log('════════════════════════════════════════════════════════════════');
console.log('  LISTING AVAILABLE GEMINI MODELS');
console.log('════════════════════════════════════════════════════════════════');
console.log('');

(async () => {
  try {
    const genAI = new GoogleGenerativeAI(apiKey);
    
    // Try to list models (if available in SDK)
    console.log('Attempting to list available models...');
    console.log('');
    
    // Try each known model name
    const modelsToTest = [
      'gemini-1.5-pro',
      'gemini-1.5-pro-latest',
      'gemini-1.5-flash',
      'gemini-pro',
      'gemini-pro-vision',
      'gemini-2.0-pro',
      'gemini-2.0-flash',
    ];
    
    console.log('Testing model availability:');
    console.log('');
    
    for (const modelName of modelsToTest) {
      try {
        console.log(`Testing: ${modelName}...`);
        const model = genAI.getGenerativeModel({ model: modelName });
        
        // Try a simple request
        const result = await model.generateContent('test');
        console.log(`  ✅ SUCCESS - ${modelName} is available`);
        
      } catch (error) {
        if (error.message.includes('404')) {
          console.log(`  ❌ Not found - ${modelName}`);
        } else if (error.message.includes('403') || error.message.includes('Forbidden')) {
          console.log(`  ⚠️  Forbidden - ${modelName} (API key issue?)`);
        } else {
          console.log(`  ⚠️  Error - ${modelName}: ${error.message.substring(0, 80)}`);
        }
      }
    }
    
    console.log('');
    console.log('════════════════════════════════════════════════════════════════');
    
  } catch (error) {
    console.error('Error:', error.message);
  }
})();

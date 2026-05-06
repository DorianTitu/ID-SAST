// Test Google Gemini API directly
require('dotenv').config({ path: require('path').join(__dirname, 'config/.env') });
const { GoogleGenerativeAI } = require('@google/generative-ai');

const apiKey = process.env.GOOGLE_GEMINI_API_KEY;

console.log('════════════════════════════════════════════════════════════════');
console.log('  GOOGLE GEMINI API TEST');
console.log('════════════════════════════════════════════════════════════════');
console.log('');

if (!apiKey) {
  console.error('❌ No API key found in config/.env');
  process.exit(1);
}

console.log('Configuration:');
console.log('  API Key (first 30 chars):', apiKey.substring(0, 30) + '...');
console.log('  Model: gemini-1.5-pro');
console.log('');

(async () => {
  try {
    console.log('1. Initializing Google Generative AI...');
    const genAI = new GoogleGenerativeAI(apiKey);
    
    console.log('2. Getting model (gemini-1.5-pro)...');
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
    
    console.log('3. Sending test prompt...');
    const prompt = 'Responde SOLO con: {"test": "success"}';
    
    const result = await model.generateContent(prompt);
    
    if (!result.response) {
      console.error('❌ No response from model');
      process.exit(1);
    }
    
    const text = result.response.text();
    console.log('4. Response received');
    console.log('');
    
    console.log('Response Text (first 200 chars):');
    console.log(text.substring(0, 200));
    console.log('');
    
    // Try to parse JSON
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      try {
        const json = JSON.parse(jsonMatch[0]);
        console.log('✅ JSON Response:');
        console.log(JSON.stringify(json, null, 2));
      } catch (e) {
        console.warn('⚠️  Could not parse JSON:', e.message);
      }
    }
    
    console.log('');
    console.log('════════════════════════════════════════════════════════════════');
    console.log('✅ GEMINI API TEST PASSED');
    console.log('════════════════════════════════════════════════════════════════');
    
  } catch (error) {
    console.error('❌ GEMINI API TEST FAILED');
    console.error('');
    console.error('Error Details:');
    console.error('  Message:', error.message);
    console.error('  Code:', error.code);
    console.error('  Status:', error.status);
    console.error('');
    
    if (error.message.includes('404')) {
      console.error('Issue: 404 Not Found');
      console.error('  - The API endpoint is not found');
      console.error('  - This might mean the model name is incorrect');
      console.error('  - Try: gemini-pro, gemini-1.5-pro, or gemini-pro-vision');
    } else if (error.message.includes('403') || error.message.includes('Forbidden')) {
      console.error('Issue: 403 Forbidden');
      console.error('  - The API key might be invalid');
      console.error('  - Check that the API key is correct');
      console.error('  - Verify the API key has access to generative AI');
    } else if (error.message.includes('401') || error.message.includes('Unauthorized')) {
      console.error('Issue: 401 Unauthorized');
      console.error('  - The API key is not valid');
      console.error('  - Generate a new API key from Google AI Studio');
    } else if (error.message.includes('ENOTFOUND')) {
      console.error('Issue: Network connectivity');
      console.error('  - Could not reach the API server');
      console.error('  - Check your internet connection');
    }
    
    console.error('');
    console.error('To fix:');
    console.error('  1. Go to: https://aistudio.google.com/app/apikeys');
    console.error('  2. Create a new API key');
    console.error('  3. Update GOOGLE_GEMINI_API_KEY in config/.env');
    console.error('  4. Restart the server');
    
    process.exit(1);
  }
})();

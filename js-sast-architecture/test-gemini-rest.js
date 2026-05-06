// Direct REST API test for Gemini
require('dotenv').config({ path: require('path').join(__dirname, 'config/.env') });
const https = require('https');

const apiKey = process.env.GOOGLE_GEMINI_API_KEY;

console.log('════════════════════════════════════════════════════════════════');
console.log('  GOOGLE GEMINI REST API TEST');
console.log('════════════════════════════════════════════════════════════════');
console.log('');

if (!apiKey) {
  console.error('❌ No API key found');
  process.exit(1);
}

console.log('API Key:', apiKey.substring(0, 30) + '...');
console.log('');

// Test different model endpoints
const models = [
  'gemini-pro-vision',
  'gemini-pro',
  'gemini-1.5-pro',
  'gemini-1.5-pro-latest',
  'gemini-1.5-flash',
];

(async () => {
  for (const model of models) {
    console.log(`Testing: ${model}`);
    
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
      
      const data = JSON.stringify({
        contents: [{
          parts: [{
            text: 'test'
          }]
        }]
      });
      
      const options = {
        hostname: 'generativelanguage.googleapis.com',
        path: `/v1beta/models/${model}:generateContent?key=${apiKey}`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': data.length
        }
      };
      
      const response = await new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
          let body = '';
          res.on('data', (chunk) => body += chunk);
          res.on('end', () => resolve({ status: res.statusCode, body }));
        });
        
        req.on('error', reject);
        req.write(data);
        req.end();
      });
      
      if (response.status === 200) {
        console.log(`  ✅ SUCCESS - ${model} works!`);
        const result = JSON.parse(response.body);
        if (result.candidates && result.candidates[0].content.parts[0].text) {
          console.log(`     Response: ${result.candidates[0].content.parts[0].text.substring(0, 50)}`);
        }
      } else if (response.status === 404) {
        console.log(`  ❌ Not found - ${model}`);
      } else {
        console.log(`  ⚠️  Status ${response.status} - ${model}`);
      }
      
    } catch (error) {
      console.log(`  ❌ Error - ${model}: ${error.message}`);
    }
  }
  
  console.log('');
  console.log('════════════════════════════════════════════════════════════════');
})();

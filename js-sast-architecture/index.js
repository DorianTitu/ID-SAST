/**
 * JS-SAST Entry Point
 * Initializes and starts the API server with Clean Architecture
 */

const APIServer = require('./src/presentation/api/server');

// Create and start server
const server = new APIServer();
server.start();

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n Shutting down server...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n Terminating server...');
  process.exit(0);
});

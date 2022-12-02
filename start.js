const Server = require('./services/server');

start();
async function start() {
  const server = new Server();
  server.start();
}

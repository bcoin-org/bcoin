'use strict';

const Path = require('path');
const bweb = require('../');

const server = bweb.server({
  port: 8080,
  sockets: true
});

server.use('/', server.bodyParser());
server.use('/', server.cookieParser());
server.use('/', server.jsonRPC());
server.use('/', server.router());
server.use('/static', server.fileServer(Path.resolve(__dirname, '..')));

server.get('/', (req, res) => {
  res.html(200, '<a href="/static">static</a>\n');
});

server.add('test', async () => {
  return { foo: 'bar' };
});

server.on('error', (err) => {
  console.error(err.stack);
});

(async () => {
  await server.open();
})().catch((err) => {
  console.error(err.stack);
  process.exit(0);
});

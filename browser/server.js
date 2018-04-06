'use strict';

const bweb = require('bweb');
const fs = require('bfile');
const WSProxy = require('./wsproxy');

const index = fs.readFileSync(`${__dirname}/index.html`);
const app = fs.readFileSync(`${__dirname}/app.js`);
const worker = fs.readFileSync(`${__dirname}/worker.js`);

const proxy = new WSProxy({
  ports: [8333, 18333, 18444, 28333, 28901]
});

const server = bweb.server({
  port: Number(process.argv[2]) || 8080,
  sockets: false
});

server.use(server.router());

proxy.on('error', (err) => {
  console.error(err.stack);
});

server.on('error', (err) => {
  console.error(err.stack);
});

server.get('/', (req, res) => {
  res.send(200, index, 'html');
});

server.get('/app.js', (req, res) => {
  res.send(200, app, 'js');
});

server.get('/worker.js', (req, res) => {
  res.send(200, worker, 'js');
});

proxy.attach(server.http);

server.open();

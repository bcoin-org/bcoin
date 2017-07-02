'use strict';

const HTTPBase = require('../lib/http/base');
const WSProxy = require('./wsproxy');
const fs = require('fs');

const index = fs.readFileSync(`${__dirname}/index.html`);
const indexjs = fs.readFileSync(`${__dirname}/index.js`);
const bcoin = fs.readFileSync(`${__dirname}/bcoin.js`);
const master = fs.readFileSync(`${__dirname}/bcoin-master.js`);
const worker = fs.readFileSync(`${__dirname}/bcoin-worker.js`);

let proxy = new WSProxy({
  pow: process.argv.indexOf('--pow') !== -1,
  ports: [8333, 18333, 18444, 28333, 28901]
});

let server = new HTTPBase({
  port: +process.argv[2] || 8080,
  sockets: false
});

proxy.on('error', (err) => {
  console.error(err.stack + '');
});

server.on('error', (err) => {
  console.error(err.stack + '');
});

server.get('/favicon.ico', (req, res) => {
  res.send(404, '', 'txt');
});

server.get('/', (req, res) => {
  res.send(200, index, 'html');
});

server.get('/index.js', (req, res) => {
  res.send(200, indexjs, 'js');
});

server.get('/bcoin.js', (req, res) => {
  res.send(200, bcoin, 'js');
});

server.get('/bcoin-master.js', (req, res) => {
  res.send(200, master, 'js');
});

server.get('/bcoin-worker.js', (req, res) => {
  res.send(200, worker, 'js');
});

proxy.attach(server.server);

server.open();

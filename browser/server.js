'use strict';

var HTTPBase = require('../lib/http/base');
var WSProxy = require('./wsproxy');
var fs = require('fs');

var server = new HTTPBase();
var proxy = new WSProxy({
  pow: process.argv.indexOf('--pow') !== -1,
  ports: [8333, 18333, 18444, 28333, 28901]
});

proxy.on('error', function(err) {
  console.error(err.stack + '');
});

var index = fs.readFileSync(__dirname + '/index.html');
var bcoin = fs.readFileSync(__dirname + '/bcoin.js');
var worker = fs.readFileSync(__dirname + '/../lib/workers/worker.js');

server.get('/favicon.ico', function(req, res, next, send) {
  send(404, '', 'text');
});

server.get('/', function(req, res, next, send) {
  send(200, index, 'html');
});

server.get('/bcoin.js', function(req, res, next, send) {
  send(200, bcoin, 'js');
});

server.get('/bcoin-worker.js', function(req, res, next, send) {
  send(200, worker, 'js');
});

server.on('error', function(err) {
  console.error(err.stack + '');
});

proxy.attach(server.server);

server.listen(+process.argv[2] || 8080);

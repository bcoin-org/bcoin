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
var indexjs = fs.readFileSync(__dirname + '/index.js');
var bcoin = fs.readFileSync(__dirname + '/bcoin.js');
var master = fs.readFileSync(__dirname + '/bcoin-master.js');
var worker = fs.readFileSync(__dirname + '/bcoin-worker.js');

server.get('/favicon.ico', function(req, res, send, next) {
  send(404, '', 'text');
});

server.get('/', function(req, res, send, next) {
  send(200, index, 'html');
});

server.get('/index.js', function(req, res, send, next) {
  send(200, indexjs, 'js');
});

server.get('/bcoin.js', function(req, res, send, next) {
  send(200, bcoin, 'js');
});

server.get('/bcoin-master.js', function(req, res, send, next) {
  send(200, master, 'js');
});

server.get('/bcoin-worker.js', function(req, res, send, next) {
  send(200, worker, 'js');
});

server.on('error', function(err) {
  console.error(err.stack + '');
});

proxy.attach(server.server);

server.listen(+process.argv[2] || 8080);

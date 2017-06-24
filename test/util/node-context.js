'use strict';

var assert = require('assert');
var FullNode = require('../../lib/node/fullnode');
var Network = require('../../lib/protocol/network');
var co = require('../../lib/utils/co');
var Logger = require('../../lib/node/logger');

function NodeContext(network, size) {
  if (!(this instanceof NodeContext))
    return new NodeContext(network, size);

  this.network = Network.get(network);
  this.size = size || 4;
  this.nodes = [];

  this.init();
};

NodeContext.prototype.init = function() {
  var i, port, last, node;

  for (i = 0; i < this.size; i++) {
    port = this.network.port + i;
    last = port - 1;

    if (last < this.network.port) {
      // last = this.network.port + this.size - 1;
      last = port;
    }

    node = new FullNode({
      network: this.network,
      db: 'memory',
      network: 'regtest',
      logger: new Logger({
        level: 'debug',
        file: false,
        console: false
      }),
      listen: true,
      publicHost: '127.0.0.1',
      publicPort: port,
      httpPort: port + 100,
      host: '127.0.0.1',
      port: port,
      seeds: [
        '127.0.0.1:' + last
      ]
    });

    node.on('error', function(err) {
      node.logger.error(err);
    });

    this.nodes.push(node);
  }
};

NodeContext.prototype.open = function open() {
  var jobs = [];
  var i, node;

  for (i = 0; i < this.nodes.length; i++) {
    node = this.nodes[i];
    jobs.push(node.open());
  }

  return Promise.all(jobs);
};

NodeContext.prototype.close = function close() {
  var jobs = [];
  var i, node;

  for (i = 0; i < this.nodes.length; i++) {
    node = this.nodes[i];
    jobs.push(node.close());
  }

  return Promise.all(jobs);
};

NodeContext.prototype.connect = async function connect() {
  var i, node;

  for (i = 0; i < this.nodes.length; i++) {
    node = this.nodes[i];
    await node.connect();
    await co.timeout(1000);
  }
};

NodeContext.prototype.disconnect = async function disconnect() {
  var i, node;

  for (i = this.nodes.length - 1; i >= 0; i--) {
    node = this.nodes[i];
    await node.disconnect();
    await co.timeout(1000);
  }
});

NodeContext.prototype.startSync = function startSync() {
  var jobs = [];
  var i, node;

  for (i = 0; i < this.nodes.length; i++) {
    node = this.nodes[i];
    node.chain.synced = true;
    node.chain.emit('full');
    node.startSync();
  }
};

NodeContext.prototype.stopSync = function stopSync() {
  var jobs = [];
  var i, node;

  for (i = 0; i < this.nodes.length; i++) {
    node = this.nodes[i];
    node.stopSync();
  }
};

NodeContext.prototype.generate = async function generate(index, blocks) {
  var node = this.nodes[index];
  var i, block;

  assert(node);

  for (i = 0; i < blocks; i++) {
    block = await node.miner.mineBlock();
    await node.chain.add(block);
  }
};

NodeContext.prototype.height = function height(index) {
  var node = this.nodes[index];

  assert(node);

  return node.chain.height;
};

NodeContext.prototype.sync = async function sync() {
  await co.timeout(3000);
};

module.exports = NodeContext;

'use strict';

const assert = require('assert');
const FullNode = require('../../lib/node/fullnode');
const Network = require('../../lib/protocol/network');
const co = require('../../lib/utils/co');
const Logger = require('../../lib/node/logger');

function NodeContext(network, size) {
  if (!(this instanceof NodeContext))
    return new NodeContext(network, size);

  this.network = Network.get(network);
  this.size = size || 4;
  this.nodes = [];

  this.init();
};

NodeContext.prototype.init = function init() {
  for (let i = 0; i < this.size; i++) {
    const port = this.network.port + i;
    let last = port - 1;

    if (last < this.network.port)
      last = port;

    const node = new FullNode({
      network: this.network,
      db: 'memory',
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
        `127.0.0.1:${last}`
      ]
    });

    node.on('error', (err) => {
      node.logger.error(err);
    });

    this.nodes.push(node);
  }
};

NodeContext.prototype.open = function open() {
  const jobs = [];

  for (const node of this.nodes)
    jobs.push(node.open());

  return Promise.all(jobs);
};

NodeContext.prototype.close = function close() {
  const jobs = [];

  for (const node of this.nodes)
    jobs.push(node.close());

  return Promise.all(jobs);
};

NodeContext.prototype.connect = async function connect() {
  for (const node of this.nodes) {
    await node.connect();
    await co.timeout(1000);
  }
};

NodeContext.prototype.disconnect = async function disconnect() {
  for (let i = this.nodes.length - 1; i >= 0; i--) {
    const node = this.nodes[i];
    await node.disconnect();
    await co.timeout(1000);
  }
};

NodeContext.prototype.startSync = function startSync() {
  for (const node of this.nodes) {
    node.chain.synced = true;
    node.chain.emit('full');
    node.startSync();
  }
};

NodeContext.prototype.stopSync = function stopSync() {
  for (const node of this.nodes)
    node.stopSync();
};

NodeContext.prototype.generate = async function generate(index, blocks) {
  const node = this.nodes[index];

  assert(node);

  for (let i = 0; i < blocks; i++) {
    const block = await node.miner.mineBlock();
    await node.chain.add(block);
  }
};

NodeContext.prototype.height = function height(index) {
  const node = this.nodes[index];

  assert(node);

  return node.chain.height;
};

NodeContext.prototype.sync = async function sync() {
  await co.timeout(3000);
};

module.exports = NodeContext;

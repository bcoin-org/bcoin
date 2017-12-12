'use strict';

const assert = require('assert');
const FullNode = require('../../lib/node/fullnode');
const Network = require('../../lib/protocol/network');
const Logger = require('blgr');

class NodeContext {
  constructor(network, size) {
    this.network = Network.get(network);
    this.size = size || 4;
    this.nodes = [];

    this.init();
  }

  init() {
    for (let i = 0; i < this.size; i++) {
      const port = this.network.port + i;

      let last = port - 1;

      if (last < this.network.port)
        last = port;

      const node = new FullNode({
        network: this.network,
        memory: true,
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
  }

  open() {
    const jobs = [];

    for (const node of this.nodes)
      jobs.push(node.open());

    return Promise.all(jobs);
  }

  close() {
    const jobs = [];

    for (const node of this.nodes)
      jobs.push(node.close());

    return Promise.all(jobs);
  }

  async connect() {
    for (const node of this.nodes) {
      await node.connect();
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  async disconnect() {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const node = this.nodes[i];
      await node.disconnect();
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  startSync() {
    for (const node of this.nodes) {
      node.chain.synced = true;
      node.chain.emit('full');
      node.startSync();
    }
  }

  stopSync() {
    for (const node of this.nodes)
      node.stopSync();
  }

  async generate(index, blocks) {
    const node = this.nodes[index];

    assert(node);

    for (let i = 0; i < blocks; i++) {
      const block = await node.miner.mineBlock();
      await node.chain.add(block);
    }
  }

  height(index) {
    const node = this.nodes[index];

    assert(node);

    return node.chain.height;
  }

  async sync() {
    return new Promise(r => setTimeout(r, 3000));
  }
}

module.exports = NodeContext;

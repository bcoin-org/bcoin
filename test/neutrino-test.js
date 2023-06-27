'use strict';

const FullNode = require('../lib/node/fullnode');
const NeutrinoNode = require('../lib/node/neutrino');
const {forValue} = require('./util/common');
const assert = require('bsert');
describe('neutrino', function () {
  this.timeout(10000);

  const node1 = new NeutrinoNode({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    neutrino: true,
    only: '127.0.0.1'
  });

  const node2 = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true,
    indexFilter: true,
    bip157: true
  });

  async function mineBlocks(n) {
    while (n) {
      const block = await node2.miner.mineBlock();
      await node2.chain.add(block);
      n--;
    }
    await forValue(node1.chain, 'height', node2.chain.height);
  }

  before(async function () {
    const waitForConnection = new Promise((resolve, reject) => {
      node1.pool.once('peer open', async (peer) => {
        resolve(peer);
      });
    });

    await node1.open();
    await node2.open();
    await node1.connect();
    await node2.connect();
    node1.startSync();
    node2.startSync();
    await mineBlocks(200);
    await waitForConnection;
  });

  after(async () => {
    await node1.close();
    await node2.close();
  });

  describe('getcfheaders', () => {
    it('should getcfheaders', async () => {
        const headerHeight = node1.chain.getCFHeaderHeight();
        assert.equal(headerHeight, node1.chain.height);
    });
  });

  describe('getcfilters', () => {
    it('should getcfilters', async () => {
        const filterHeight = node1.chain.getCFHeaderHeight();
        assert.equal(filterHeight, node1.chain.height);
    });
  });

  describe('getheaders', () => {
    it('should getheaders', async () => {
      await mineBlocks(30);
      assert.equal(node1.chain.height, node2.chain.height);
    });
  });
});

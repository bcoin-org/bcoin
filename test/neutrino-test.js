'use strict';

const FullNode = require('../lib/node/fullnode');
const NeutrinoNode = require('../lib/node/neutrino');
const {forValue} = require('./util/common');
const assert = require('bsert');
describe('neutrino', function () {
  this.timeout(100000);

  const node1 = new NeutrinoNode({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    neutrino: true,
    logConsole: true,
    logLevel: 'debug',
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
      await new Promise(resolve => setTimeout(resolve, 20));
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
    await waitForConnection;
    await mineBlocks(1000);
  });

  after(async () => {
    await node1.close();
    await node2.close();
  });

  describe('getheaders', () => {
    it('should getheaders', async () => {
      await mineBlocks(10);
      assert.equal(node1.chain.height, node2.chain.height);
    });
  });

  describe('getcfheaders', () => {
    it('should getcfheaders', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const headerHeight = await node1.chain.getCFHeaderHeight();
        assert.equal(headerHeight, node1.chain.height);
    });
  });

  describe('getcfilters', () => {
    it('should getcfilters', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const filterHeight = await node1.chain.getCFilterHeight();
        assert.equal(filterHeight, node1.chain.height);
    });
  });

  describe('save filters', () => {
    it('should save filters correctly', async () => {
      const filterIndexer = node1.filterIndexers.get('BASIC');
      for (let i = 0; i < node1.chain.height; i++) {
          const hash = await node1.chain.getHash(i);
          const filterHeader = await filterIndexer.getFilterHeader(hash);
          assert(filterHeader);
          const filter = await filterIndexer.getFilter(hash);
          assert(filter);
          assert(filterHeader.equals(filter.header));
      }
    });
  });
});

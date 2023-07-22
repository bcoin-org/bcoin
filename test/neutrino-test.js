'use strict';

const Network = require('../lib/protocol/network');
const FullNode = require('../lib/node/fullnode');
const NeutrinoNode = require('../lib/node/neutrino');
const {forValue} = require('./util/common');
const assert = require('bsert');

const network = Network.get('regtest');

describe('Neutrino', function () {
  this.timeout(10000);

  const fullNode = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true,
    indexFilter: true,
    bip157: true
  });

  async function mineBlocks(n) {
    while (n) {
      const block = await fullNode.miner.mineBlock();
      await fullNode.chain.add(block);
      n--;
    }
  }

  before(async () => {
    await fullNode.open();
    await fullNode.connect();
    await mineBlocks(200);
  });

  after(async () => {
    await fullNode.close();
  });

  describe('No Checkpoints', function () {
    const neutrinoNode = new NeutrinoNode({
      network: 'regtest',
      memory: true,
      port: 10000,
      httpPort: 20000,
      neutrino: true,
      only: '127.0.0.1'
    });

    before(async () => {
      await neutrinoNode.open();
      await neutrinoNode.connect();
      assert.strictEqual(neutrinoNode.chain.height, 0);
      assert(neutrinoNode.chain.synced);
    });

    after(async () => {
      await neutrinoNode.close();
    });

    it('should initial sync', async () => {
      neutrinoNode.startSync();
      await forValue(neutrinoNode.chain, 'height', fullNode.chain.height);
    });

    it('should get new blocks headers-only', async () => {
      await mineBlocks(10);
      await new Promise(resolve => setTimeout(resolve, 400));
      assert.equal(neutrinoNode.chain.height, fullNode.chain.height);
    });

    it('should getcfheaders', async () => {
      await new Promise(resolve => setTimeout(resolve, 400));
      const headerHeight = await neutrinoNode.chain.getCFHeaderHeight();
      assert.equal(headerHeight, neutrinoNode.chain.height);
    });

    it('should getcfilters', async () => {
      await new Promise(resolve => setTimeout(resolve, 400));
      const filterHeight = await neutrinoNode.chain.getCFilterHeight();
      assert.equal(filterHeight, neutrinoNode.chain.height);
    });

    it('should save filters correctly', async () => {
      const filterIndexer = neutrinoNode.filterIndexers.get('BASIC');
      for (let i = 0; i < neutrinoNode.chain.height; i++) {
          const hash = await neutrinoNode.chain.getHash(i);
          const filterHeader = await filterIndexer.getFilterHeader(hash);
          assert(filterHeader);
          const filter = await filterIndexer.getFilter(hash);
          assert(filter);
          assert(filterHeader.equals(filter.header));
      }
    });
  });

  describe('With Checkpoints', function () {
    const neutrinoNode = new NeutrinoNode({
      network: 'regtest',
      memory: true,
      port: 10000,
      httpPort: 20000,
      logConsole: true,
      logLevel: 'debug',
      neutrino: true,
      only: '127.0.0.1'
    });

    before(async () => {
      // Set a new checkpoint from live regtrest chain
      const entry = await fullNode.chain.getEntry(fullNode.chain.tip.height - 20);
      network.checkpointMap[entry.height] = entry.hash;
      network.lastCheckpoint = entry.height;
      network.init();

      await neutrinoNode.open();
      await neutrinoNode.connect();
      assert.strictEqual(neutrinoNode.chain.height, 0);
      assert(!neutrinoNode.chain.synced);
    });

    after(async () => {
      await neutrinoNode.close();

      // Restore defaults
      network.checkpointMap = {};
      network.lastCheckpoint = 0;
    });

    it('should initial sync', async () => {
      let full = false;
      neutrinoNode.chain.on('full', () => {
        full = true;
      });

      neutrinoNode.startSync();
      await forValue(neutrinoNode.chain, 'height', fullNode.chain.height);
      assert(full);
      assert(neutrinoNode.chain.synced);
    });

    it('should get new blocks headers-only', async () => {
      await mineBlocks(10);
      await new Promise(resolve => setTimeout(resolve, 400));
      assert.equal(neutrinoNode.chain.height, fullNode.chain.height);
    });
  });
});

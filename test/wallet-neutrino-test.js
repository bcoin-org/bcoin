'use strict';

const FullNode = require('../lib/node/fullnode');
const Neutrino = require('../lib/node/neutrino');
const assert = require('bsert');
const { forValue } = require('./util/common');
const BasicFilter = require('../lib/golomb/basicFilter');
const Script = require('../lib/script/script');
const Address = require('../lib/primitives/address');

const node1 = new FullNode({
    network: 'regtest',
    memory: true,
    listen: true,
    indexFilter: true,
    plugins: [require('../lib/wallet/plugin')],
    bip157: true
});

const node2 = new Neutrino({
    network: 'regtest',
    memory: true,
    port: 10000,
    httpPort: 20000,
    neutrino: true,
    only: '127.0.0.1',
    plugins: [require('../lib/wallet/plugin')],
    env: {
        'BCOIN_WALLET_HTTP_PORT': '12221'
    }
});

const chain = node1.chain;
const miner = node1.miner;
const wdb1 = node1.require('walletdb').wdb;
const wdb2 = node2.require('walletdb').wdb;

let wallet1 = null;
let wallet2 = null;
const fwAddresses = [];
const nwAddresses = [];

async function mineBlocks(n, address) {
  for (let i = 0; i < n; i++) {
    const block = await miner.mineBlock(null, address);
    const entry = await chain.add(block);
    assert(entry);
  }
}

function parseAddress(raw, network) {
  return Address.fromString(raw, network);
}

describe('wallet-neutrino', function() {
    it('should open chain and miner', async () => {
        miner.mempool = null;
        await node1.open();
        await node2.open();
    });

    it('should open walletdb', async () => {
        wallet1 = await wdb1.create();
        wallet2 = await wdb2.create();
    });

    it('should create accounts', async () => {
      await wallet1.createAccount('fw');
      await wallet2.createAccount('nw');
    });

    it('should generate addresses', async () => {
      miner.addresses.length = 0;
      for (let i = 0; i < 10; i++) {
        const key = await wallet1.createReceive(0);
        const address = key.getAddress().toString(node1.network.type);
        fwAddresses.push(address);
      }
      miner.addAddress(fwAddresses[0]);
      for (let i = 0; i < 10; i++) {
        const key = await wallet2.createReceive(0);
        const address = key.getAddress().toString(node2.network.type);
        nwAddresses.push(address);
      }
    });

    it('should mine 40 blocks', async () => {
      for (const address of fwAddresses) {
        const add = parseAddress(address, node1.network);
        await mineBlocks(2, add);
      }
      for (const address of nwAddresses) {
        const add = parseAddress(address, node2.network);
        await mineBlocks(2, add);
      }
    });

    it('should connect nodes', async () => {
        await node1.connect();
        await node2.connect();
    });

    it('should start sync chain', async () => {
        node1.startSync();
        node2.startSync();
        await forValue(node2.chain, 'height', node1.chain.height);
    });

    it('should getheaders', async () => {
        assert.equal(node1.chain.height, node2.chain.height);
    });

    it('should getcfheaders', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const headerHeight = await node2.chain.getCFHeaderHeight();
        assert.equal(headerHeight, node2.chain.height);
    });

    it('should getcfilters', async () => {
        await new Promise(resolve => setTimeout(resolve, 400));
        const filterHeight = await node2.chain.getCFilterHeight();
        assert.equal(filterHeight, node2.chain.height);
    });

    it('should send filters to wallet', async () => {
      assert.equal(wdb2.filterHeight, node2.chain.height);
    });

    it('should match the filters', async () => {
      let j = 0;
      for (let i = 1;i <= 20; i++) {
        const filterIndexer = node2.filterIndexers.get('BASIC');
        const hash = await node2.chain.getHash(i);
        const filter = await filterIndexer.getFilter(hash);
        const basicFilter = new BasicFilter();
        const gcs = basicFilter.fromNBytes(filter.filter);
        const key = hash.slice(0, 16);
        const address = Address.fromString(fwAddresses[j], node1.network.type);
        if (i % 2 === 0)
          j++;
        const script = Script.fromAddress(address);
        assert(gcs.match(key, script.raw));
      }

      j = 0;
      for (let i = 21;i <= node2.chain.height; i++) {
        const filterIndexer = node2.filterIndexers.get('BASIC');
        const hash = await node2.chain.getHash(i);
        const filter = await filterIndexer.getFilter(hash);
        const basicFilter = new BasicFilter();
        const gcs = basicFilter.fromNBytes(filter.filter);
        const key = hash.slice(0, 16);
        const address = Address.fromString(nwAddresses[j], node2.network.type);
        if (i % 2 === 0)
          j++;
        const script = Script.fromAddress(address);
        assert(gcs.match(key, script.raw));
      }
    });

    it('should getblockfrompeer', async () => {
      for (let i = 21; i <= node2.chain.height; i++) {
        const hash = await node2.chain.getHash(i);
        const block = await node2.chain.getBlock(hash);
        assert(block);
      }
    });

    it('should cleanup', async () => {
        await node1.close();
        await node2.close();
    });
});

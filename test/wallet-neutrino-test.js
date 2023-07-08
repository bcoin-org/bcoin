'use strict';

const FullNode = require('../lib/node/fullnode');
const Neutrino = require('../lib/node/neutrino');
const MTX = require('../lib/primitives/mtx');
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

async function mineBlock(tx, address) {
    const job = await miner.createJob();

    if (!tx)
        return await job.mineAsync();

    const spend = new MTX();
    spend.addTX(tx, 0);
    spend.addOutput(address, 50000);

    spend.setLocktime(chain.height);
    await wallet1.sign(spend);

    job.addTX(spend.toTX(), spend.view);
    job.refresh();

    return await job.mineAsync();
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
        miner.addAddress(address);
      }
      for (let i = 0; i < 10; i++) {
        const key = await wallet2.createReceive(0);
        const address = key.getAddress().toString(node2.network.type);
        nwAddresses.push(address);
      }
    });

    it('should mine 10 blocks', async () => {
      for (const address of fwAddresses) {
        for (let i = 0; i < 2; i++) {
          const block = await mineBlock(null, address);
          await chain.add(block);
        }
      }
      for (const address of nwAddresses) {
        for (let i = 0; i < 2; i++) {
          const block = await mineBlock(null, address);
          await chain.add(block);
        }
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
      const filterIndexer = node2.filterIndexers.get('BASIC');
      for (let i = 0; i < fwAddresses.length; i++) {
        const hash = await node2.chain.getHash(i);
        const filter = await filterIndexer.getFilter(hash);
        const basicFilter = new BasicFilter();
        const gcs = basicFilter.fromNBytes(filter.filter);
        const key = hash.slice(0, 16);
        const address = Address.fromString(fwAddresses[i], node1.network.type);
        const script = Script.fromAddress(address);
        assert(gcs.match(key, script.raw));
      }
    });
});

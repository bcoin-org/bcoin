'use strict';

const assert = require('bsert');
const WalletDB = require('../lib/wallet/walletdb');
const { Network } = require('../lib/protocol');
const WorkerPool = require('../lib/workers/workerpool');
const Chain = require('../lib/blockchain/chain');
const BlockStore = require('../lib/blockstore/level');
const Miner = require('../lib/mining/miner');
const CoinView = require('../lib/coins/coinview');

const wdb = new WalletDB();

const network = Network.get('regtest');

const workers = new WorkerPool({
  enabled: true,
  size: 2
});

const blocks = new BlockStore({
    memory: true,
    network
  });

const chain = new Chain({
  memory: true,
  blocks,
  network,
  workers
});

const miner  = new Miner({
    chain,
    version: 4,
    workers
});

let wallet = null;
const addresses = [];
const minedBlocks = [];
const filters = [];

describe('wallet-neutrino', function() {
    before(async () => {
        await wdb.open();
    });

    after(async () => {
        await wdb.close();
    });

    it('should open wallet', async () => {
        wallet = await wdb.create();
    });

    it('should create accounts', async () => {
      await wallet.createAccount('foo');
    });

    it('should generate addresses', async () => {
      for (let i = 0; i < 3; i++) {
        const key = await wallet.createReceive(0);
        const address = key.getAddress();
        addresses.push(address);
      }
    });

    it('should create 3 match blocks', async () => {
        for (let i = 0; i < 3; i++) {
            const addr = addresses[i];
            const block = await miner.mineBlock(null, addr);
            minedBlocks.push(block);
        }
    });

    it('should create 2 non-match blocks', async () => {
        for (let i = 0; i < 2; i++) {
            const block = await miner.mineBlock(null, null);
            minedBlocks.push(block);
        }
    });

    it('should create filters', async () => {
        for (let i = 0; i < 5; i++) {
           const filter = minedBlocks[i].toBasicFilter(new CoinView());
           filters.push(filter);
        }
    });

    it('should match the filters', async () => {
        for (let i = 0; i < 3; i++) {
            const match = await wdb.checkFilter(minedBlocks[i].hash(), filters[i]);
            assert(match);
        }
    });

    it('should not match the filters', async () => {
        for (let i = 3; i < 5; i++) {
            const match = await wdb.checkFilter(minedBlocks[i].hash(), filters[i]);
            assert(!match);
        }
    });
});

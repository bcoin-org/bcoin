/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const SPVNode = require('../lib/node/spvnode');

const ports = {
  full: {
    p2p: 49331,
    node: 49332,
    wallet: 49333
  },
  spv: {
    p2p: 49431,
    node: 49432,
    wallet: 49433
  }
};

const node = new FullNode({
  network: 'regtest',
  workers: true,
  listen: true,
  bip37: true,
  port: ports.full.p2p,
  httpPort: ports.full.node,
  maxOutbound: 1,
  seeds: [],
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  env: {
    'BCOIN_WALLET_HTTP_PORT': (ports.full.wallet).toString()
  }
});

const spvnode = new SPVNode({
  network: 'regtest',
  workers: true,
  listen: true,
  port: ports.spv.p2p,
  httpPort: ports.spv.node,
  maxOutbound: 1,
  seeds: [],
  nodes: [`127.0.0.1:${ports.full.p2p}`],
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  env: {
    'BCOIN_WALLET_HTTP_PORT': (ports.spv.wallet).toString()
  }
});

const chain = node.chain;
const miner = node.miner;
const {wdb} = node.require('walletdb');
const {wdb: spvwdb} = spvnode.require('walletdb');

let wallet = null;
let spvwallet = null;
let spvaddr = null;
let tip1 = null;
let tip2 = null;

async function mineBlock(tip) {
  const job = await miner.createJob(tip);
  return await job.mineAsync();
}

async function event(obj, name) {
  return new Promise((resolve) => {
    obj.once(name, resolve);
  });
}

describe('SPV Node Sync', function() {
  this.timeout(10000);

  if (process.browser)
    this.skip();

  // const cbMaturity = consensus.COINBASE_MATURITY;
  before(async () => {
    // consensus.COINBASE_MATURITY = 0;
    await node.open();
    await spvnode.open();
    await node.connect();
    await spvnode.connect();
    await spvnode.startSync();
  });

  after(async () => {
    // consensus.COINBASE_MATURITY = cbMaturity;
    await node.close();
    await spvnode.close();
  });

  it('should check SPV is synced to fullnode', async () => {
    assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);
  });

  it('should open miner and wallets', async () => {
    wallet = await wdb.create();
    miner.addresses.length = 0;
    miner.addAddress(await wallet.receiveAddress());

    spvwallet = await spvwdb.create();
    spvaddr = await spvwallet.receiveAddress();
  });

  it('should mine 90 blocks', async () => {
    for (let i = 0; i < 90; i++) {
      const block = await miner.mineBlock();
      assert(block);
      await chain.add(block);

      // Check SPV & Full nodes are in sync
      await event(spvnode, 'block');
      assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);
    }
    // Full node wallet needs to catch up to miner
    await wdb.rescan(0);
  });

  it('should mine competing chains of 10 blocks', async function () {
    for (let i = 0; i < 10; i++) {
      const block1 = await mineBlock(tip1);
      const block2 = await mineBlock(tip2);

      await chain.add(block1);
      await chain.add(block2);

      assert.bufferEqual(chain.tip.hash, block1.hash());

      tip1 = await chain.getEntry(block1.hash());
      tip2 = await chain.getEntry(block2.hash());

      assert(tip1);
      assert(tip2);

      assert(!await chain.isMainChain(tip2));

      await new Promise(setImmediate);

      // Check SPV & Full nodes are in sync after every block
      await event(spvnode, 'block');
      assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);
    }
  });

  it('should send a tx from chain 1 to SPV node', async () => {
    await wallet.send({
      outputs: [{
        value: 1012345678,
        address: spvaddr
      }]
    });

    await event(spvwallet, 'balance');
    const balance = await spvwallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 1012345678);
  });

  it('should mine a block and confirm a tx', async () => {
    const block = await miner.mineBlock();
    assert(block);
    await chain.add(block);

    // Check SPV & Full nodes are in sync
    await event(spvnode, 'block');
    assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);

    // Check SPV wallet balance
    await event(spvwallet, 'balance');
    const balance = await spvwallet.getBalance();
    assert.strictEqual(balance.confirmed, 1012345678);
  });

  it('should handle a reorg', async () => {
    assert.strictEqual(chain.height, 101);

    // Main chain is ahead by 1 block now, catch the alt chain up
    const entry = await chain.getEntry(tip2.hash);
    const block1 = await miner.mineBlock(entry);
    await chain.add(block1);
    const entry1 = await chain.getEntry(block1.hash());
    assert(entry1);

    // Tie game!
    assert.strictEqual(chain.height, entry1.height);

    // Now reorg main chain by adding a block to alt chain
    const block2 = await miner.mineBlock(entry1);
    assert(block2);

    let forked = false;
    chain.once('reorganize', () => {
      forked = true;
    });

    await chain.add(block2);

    assert(forked);
    assert.bufferEqual(chain.tip.hash, block2.hash());
    assert(chain.tip.chainwork.gt(tip1.chainwork));

    // Give SPV node a second to catch up before checking sync with fullnode.
    // Waiting for specific events like 'block', 'full', or 'tip' is hard here
    // because we don't really know when we are at the proper tip.
    await new Promise(r => setTimeout(r, 5000));

    assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);
  });

  it('should mine a block after a reorg', async () => {
    const block = await mineBlock();

    await chain.add(block);

    // Check SPV & Full nodes are in sync
    await event(spvnode, 'block');
    assert.deepStrictEqual(node.chain.tip, spvnode.chain.tip);

    const entry = await chain.getEntry(block.hash());
    assert(entry);
    assert.bufferEqual(chain.tip.hash, entry.hash);

    const result = await chain.isMainChain(entry);
    assert(result);
  });

  it('should unconfirm tx after reorg', async () => {
    const balance = await spvwallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 1012345678);
  });
});

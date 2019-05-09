/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const WalletNode = require('../lib/wallet/node');
const Block = require('../lib/primitives/block');
const {WalletClient} = require('bclient');

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

const nodeWithPlugin = new FullNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  prune: true,
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  }});

const nodeNoWallet = new FullNode({
  network: 'regtest',
  memory: true,
  prune: true,
  port: ports.p2p,
  httpPort: ports.node
});

const wallet = new WalletNode({
  network: 'regtest',
  memory: true,
  nodePort: ports.node,
  httpPort: ports.wallet
});

const walletClient = new WalletClient({
  network: 'regtest',
  port: ports.wallet
});

describe('Pruned node with wallet plugin', function() {
  this.timeout(60000);

  before(async () => {
    await nodeWithPlugin.open();
  });

  after(async () => {
    await nodeWithPlugin.close();
  });

  it('should indicate prune in node chain options', async () => {
    assert.strictEqual(true, nodeWithPlugin.chain.options.prune);
  });

  it('should indicate prune in walletDB chainInfo', async () => {
    assert.strictEqual(
      true,
      nodeWithPlugin.plugins.walletdb.wdb.chainInfo.prune
    );
  });

  it('should generate 1000 blocks', async () => {
    for (let i = 0; i < 1000; i++) {
      const block = await nodeWithPlugin.miner.cpu.mineBlock();
      assert(block);
      assert(await nodeWithPlugin.chain.add(block));
    }
    assert.strictEqual(1000, nodeWithPlugin.chain.height);
  });

  it('should fail to rescan past prune height', async () => {
    const pruneHeight = 1000 - 288;

     // This block is not on disk
    assert.strictEqual(null, await nodeWithPlugin.getBlock(pruneHeight));

     // Try to rescan it anyway
    try {
      await nodeWithPlugin.plugins.walletdb.wdb.rescan(pruneHeight);
    } catch(e) {
      assert.strictEqual(
        e.message,
        'Rescan height must be greater than prune height of ' + pruneHeight
      );
    }
  });

   it('should succeed to rescan within prune height', async () => {
    const pruneHeight = 1000 - 288;
    // This block *IS* on disk
    assert((await nodeWithPlugin.getBlock(pruneHeight + 1)) instanceof Block);
    await nodeWithPlugin.plugins.walletdb.wdb.rescan(pruneHeight + 1);
  });
});

describe('Pruned node with separate wallet', function() {
  before(async () => {
    await nodeNoWallet.open();
    await wallet.open();
    await walletClient.open();
  });

  after(async () => {
    await walletClient.close();
    await wallet.close();
    await nodeNoWallet.close();
  });

  it('should indicate prune in node chain options', async () => {
    assert.strictEqual(true, nodeNoWallet.chain.options.prune);
  });

  it('should indicate prune in walletDB chainInfo', async () => {
    assert.strictEqual(true, wallet.wdb.chainInfo.prune);
  });

  it('should generate 1000 blocks', async () => {
    for (let i = 0; i < 1000; i++) {
      const block = await nodeNoWallet.miner.cpu.mineBlock();
      assert(block);
      assert(await nodeNoWallet.chain.add(block));
    }
    assert.strictEqual(1000, nodeNoWallet.chain.height);
  });

  it('should fail to rescan past prune height', async () => {
    const pruneHeight = 1000 - 288;

     // This block is not on disk
    assert.strictEqual(null, await nodeNoWallet.getBlock(pruneHeight));

     // Try to rescan it anyway
    try {
      await walletClient.rescan(pruneHeight);
    } catch(e) {
      assert.strictEqual(
        e.message,
        'Rescan height must be greater than prune height of ' + pruneHeight
      );
    }
  });

  it('should succeed to rescan within prune height', async () => {
    const pruneHeight = 1000 - 288;
    // This block *IS* on disk
    assert((await nodeNoWallet.getBlock(pruneHeight + 1)) instanceof Block);
    await walletClient.rescan(pruneHeight + 1);
  });
});

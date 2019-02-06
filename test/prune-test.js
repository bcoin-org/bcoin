/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const consensus = require('../lib/protocol/consensus');
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  memory: true,
  workers: true,
  plugins: [require('../lib/wallet/plugin')],
  prune: true
});

const {NodeClient, WalletClient} = require('bclient');

const nclient = new NodeClient({
  port: network.rpcPort,
  apiKey: 'foo'
});

const wclient = new WalletClient({
  port: network.walletPort,
  apiKey: 'foo'
});

let wallet = null;

describe('Pruned node', function() {
  this.timeout(60000);

  it('should open node', async () => {
    consensus.COINBASE_MATURITY = 0;
    await node.open();
    await nclient.open();
    await wclient.open();
  });

  it('should indicate prune in getInfo', async () => {
    const info = await nclient.getInfo();
    assert.strictEqual(true, info.chain.prune);
  });

  it('should create wallet', async () => {
    const info = await wclient.createWallet('test');
    assert.strictEqual(info.id, 'test');
    wallet = wclient.wallet('test', info.token);
    await wallet.open();
  });

  it('should generate 1000 blocks', async () => {
    for (let i = 0; i < 1000; i++) {
      const block = await node.miner.cpu.mineBlock();
      assert(block);
      assert(await node.chain.add(block));
    }
    const info = await nclient.getInfo();
    assert.strictEqual(1000, info.chain.height);
  });

  it('should fail to rescan past prune height', async () => {
    const pruneHeight = 1000 - 288;

    // This block is not on disk
    try {
      await nclient.getBlock(pruneHeight);
    } catch(e) {
      assert.strictEqual(e.message, 'Block not found.');
    }

    // HTTP API call
    try {
      await wclient.rescan(pruneHeight);
    } catch(e) {
      assert.strictEqual(
        e.message,
        'Rescan height must be greater than prune height of ' + pruneHeight
      );
    }

    // direct WalletDB call
    try {
      await node.plugins.walletdb.wdb.rescan(pruneHeight);
    } catch(e) {
      assert.strictEqual(
        e.message,
        'Rescan height must be greater than prune height of ' + pruneHeight
      );
    }
  });

  it('should succeed to rescan within prune height', async () => {
    const pruneHeight = 1000 - 288;
    assert(await nclient.getBlock(pruneHeight + 1));
    assert(await wclient.rescan(pruneHeight + 1));
  });

  it('should cleanup', async () => {
    consensus.COINBASE_MATURITY = 100;
    await wallet.close();
    await wclient.close();
    await nclient.close();
    await node.close();
  });
});

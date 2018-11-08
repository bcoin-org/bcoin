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

  it('should create wallet', async () => {
    const info = await wclient.createWallet('test');
    assert.strictEqual(info.id, 'test');
    wallet = wclient.wallet('test', info.token);
    await wallet.open();
  });

  it('should generate 1000 blocks', async () => {
    const addr = await wallet.createAddress('default');
    assert(await nclient.execute('generatetoaddress', [500, addr.address]));
    assert(await nclient.execute('generatetoaddress', [500, addr.address]));
    const info = await nclient.getInfo();
    assert.strictEqual(1000, info.chain.height);
  });

  it('should fail to rescan past prune height', async () => {
    const pruneHeight = 1000 - 288;

    try {
      await nclient.getBlock(pruneHeight);
    } catch(e) {
      assert.strictEqual(e.message, 'Block not found.');
    }

    try {
      await wclient.rescan(pruneHeight);
    } catch(e) {
      assert.strictEqual(
        e.message,
        'Cannot rescan past prune depth of ' + pruneHeight
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

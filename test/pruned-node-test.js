/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const WalletNode = require('../lib/wallet/node');

const nodeWithPlugin = new FullNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  prune: true
});

const nodeNoWallet = new FullNode({
  network: 'regtest',
  memory: true,
  prune: true
});

const wallet = new WalletNode({
  network: 'regtest',
  memory: true
});

describe('Pruned node with wallet plugin', function() {
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
});

describe('Pruned node with separate wallet', function() {
  before(async () => {
    await nodeNoWallet.open();
    await wallet.open();
  });

  after(async () => {
    await wallet.close();
    await nodeNoWallet.close();
  });

  it('should indicate prune in node chain options', async () => {
    assert.strictEqual(true, nodeNoWallet.chain.options.prune);
  });

  it('should indicate prune in walletDB chainInfo', async () => {
    assert.strictEqual(true, wallet.wdb.chainInfo.prune);
  });
});

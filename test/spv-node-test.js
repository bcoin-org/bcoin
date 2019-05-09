/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const SPVNode = require('../lib/node/spvnode');
const WalletNode = require('../lib/wallet/node');

const nodeWithPlugin = new SPVNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')]
});

const nodeNoWallet = new SPVNode({
  network: 'regtest',
  memory: true
});

const wallet = new WalletNode({
  network: 'regtest',
  memory: true
});

describe('SPV node with wallet plugin', function() {
  before(async () => {
    await nodeWithPlugin.open();
  });

  after(async () => {
    await nodeWithPlugin.close();
  });

  it('should indicate SPV in node chain options', async () => {
    assert.strictEqual(true, nodeWithPlugin.chain.options.spv);
  });

  it('should indicate SPV in walletDB chainInfo', async () => {
    assert.strictEqual(true, nodeWithPlugin.plugins.walletdb.wdb.chainInfo.spv);
  });
});

describe('SPV node with separate wallet', function() {
  before(async () => {
    await nodeNoWallet.open();
    await wallet.open();
  });

  after(async () => {
    await wallet.close();
    await nodeNoWallet.close();
  });

  it('should indicate SPV in node chain options', async () => {
    assert.strictEqual(true, nodeNoWallet.chain.options.spv);
  });

  it('should indicate SPV in walletDB chainInfo', async () => {
    assert.strictEqual(true, wallet.wdb.chainInfo.spv);
  });
});

/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const SPVNode = require('../lib/node/spvnode');

const nodeWithPlugin = new SPVNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')]
});

describe('SPV node with wallet plugin', function() {
  before(async () => {
    await nodeWithPlugin.open();
  });

  after(async () => {
    await nodeWithPlugin.close();
  });

  it('node should have SPV and prune properties', async () => {
    assert.strictEqual(true, nodeWithPlugin.spv);
    assert.strictEqual(false, nodeWithPlugin.prune);
  });

  it('should indicate SPV and prune in walletDB nodeInfo', async () => {
    assert.strictEqual(true, nodeWithPlugin.plugins.walletdb.wdb.spv);
    assert.strictEqual(
      false,
      nodeWithPlugin.plugins.walletdb.wdb.prune
    );
  });
});

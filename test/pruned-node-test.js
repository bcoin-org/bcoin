/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');

const nodeWithPlugin = new FullNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  prune: true
});

describe('Pruned node with wallet plugin', function() {
  before(async () => {
    await nodeWithPlugin.open();
  });

  after(async () => {
    await nodeWithPlugin.close();
  });

  it('node should have SPV and prune properties', async () => {
    assert.strictEqual(true, nodeWithPlugin.prune);
    assert.strictEqual(false, nodeWithPlugin.spv);
  });

  it('should indicate SPV and prune in walletDB nodeInfo', async () => {
    assert.strictEqual(
      true,
      nodeWithPlugin.plugins.walletdb.wdb.prune
    );
    assert.strictEqual(
      false,
      nodeWithPlugin.plugins.walletdb.wdb.spv
    );
  });
});

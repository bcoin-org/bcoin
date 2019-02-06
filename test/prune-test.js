/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const FullNode = require('../lib/node/fullnode');
const Block = require('../lib/primitives/block');

const node = new FullNode({
  network: 'regtest',
  memory: true,
  plugins: [require('../lib/wallet/plugin')],
  prune: true
});

describe('Pruned node', function() {
  this.timeout(60000);

  it('should open node', async () => {
    await node.open();
  });

  it('should indicate prune in getInfo', async () => {
    assert.strictEqual(true, node.chain.options.prune);
  });

  it('should generate 1000 blocks', async () => {
    for (let i = 0; i < 1000; i++) {
      const block = await node.miner.cpu.mineBlock();
      assert(block);
      assert(await node.chain.add(block));
    }
    assert.strictEqual(1000, node.chain.height);
  });

  it('should fail to rescan past prune height', async () => {
    const pruneHeight = 1000 - 288;

    // This block is not on disk
    assert.strictEqual(null, await node.getBlock(pruneHeight));

    // Try to rescan it anyway
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
    // This block *IS* on disk
    assert((await node.getBlock(pruneHeight + 1)) instanceof Block);
    await node.plugins.walletdb.wdb.rescan(pruneHeight + 1);
  });

  it('should cleanup', async () => {
    await node.close();
  });
});

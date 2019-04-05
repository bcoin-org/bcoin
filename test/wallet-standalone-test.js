/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const FullNode = require('../lib/node/fullnode');
const SPVNode = require('../lib/node/spvnode');
const WalletNode = require('../lib/wallet/node');

const fullNode = new FullNode({
  network: 'regtest',
  memory: true
});

const prunedNode = new FullNode({
  network: 'regtest',
  memory: true,
  prune: true
});

const spvNode = new SPVNode({
  network: 'regtest',
  memory: true
});

const wallet = new WalletNode({
  network: 'regtest',
  memory: true
});

describe('Standalone Wallet', function() {
  describe('With full node', function() {
    before(async () => {
      const waiter = new Promise(resolve =>
        wallet.wdb.once('node info', () => {
          resolve();
        })
      );
      await fullNode.open();
      await wallet.open();
      await waiter;
    });

    after(async () => {
      await wallet.close();
      await fullNode.close();
    });

    it('should get full node settings', () => {
      assert.strictEqual(false, wallet.wdb.prune);
      assert.strictEqual(false, wallet.wdb.spv);
    });
  });

  describe('With pruned node', function() {
    before(async () => {
      const waiter = new Promise(resolve =>
        wallet.wdb.once('node info', () => {
          resolve();
        })
      );
      await prunedNode.open();
      await wallet.open();
      await waiter;
    });

    after(async () => {
      await wallet.close();
      await prunedNode.close();
    });

    it('should get pruned node settings', () => {
      assert.strictEqual(true, wallet.wdb.prune);
      assert.strictEqual(false, wallet.wdb.spv);
    });
  });

  describe('With SPV node', function() {
    before(async () => {
      const waiter = new Promise(resolve =>
        wallet.wdb.once('node info', () => {
          resolve();
        })
      );
      await spvNode.open();
      await wallet.open();
      await waiter;
    });

    after(async () => {
      await wallet.close();
      await spvNode.close();
    });

    it('should get SPV node settings', () => {
      assert.strictEqual(false, wallet.wdb.prune);
      assert.strictEqual(true, wallet.wdb.spv);
    });
  });
});

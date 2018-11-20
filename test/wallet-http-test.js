/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const path = require('path');
const assert = require('./util/assert');
const rimraf = require('./util/rimraf');
const sleep = require('./util/sleep');

const {
  initFullNode,
  initSPVNode,
  initNodeClient,
  initWalletClient,
  initWallet,
  generateInitialBlocks,
  generateReorg,
  generateTxs
} = require('./util/regtest');

const testPrefix = '/tmp/bcoin-fullnode';
const spvTestPrefix = '/tmp/bcoin-spvnode';
const genesisTime = 1534965859;
const genesisDate = new Date(genesisTime * 1000);

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
}

describe('Wallet TX Pagination', function() {
  this.timeout(30000);

  let node, spvnode, wallet = null;
  let nclient, wclient, spvwclient = null;
  let coinbase = null;
  let unconfirmedTime = null;

  before(async () => {
    await rimraf(testPrefix);
    await rimraf(spvTestPrefix);

    node = await initFullNode({ports, prefix: testPrefix, logLevel: 'none'});
    spvnode = await initSPVNode({ports, prefix: spvTestPrefix, logLevel: 'none'});

    nclient = await initNodeClient({ports: ports.full});
    wclient = await initWalletClient({ports: ports.full});
    spvwclient = await initWalletClient({ports: ports.spv});
    wallet = await initWallet(wclient);

    await wclient.execute('selectwallet', ['test']);
    coinbase = await wclient.execute('getnewaddress', ['blue']);

    await generateInitialBlocks({
      nclient,
      wclient,
      coinbase,
      genesisTime,
      blocks: 125
    });

    // TODO remove this
    await sleep(5000);

    unconfirmedTime = new Date();

    // Generate unconfirmed transactions for the
    // fullnode wallet
    await generateTxs({
      wclient,
      count: 195,
      amount: 0.0001,
      gap: true
    });
  });

  after(async () => {
    await wallet.close();
    await wclient.close();
    await spvwclient.close();
    await nclient.close();
    await node.close();
    await spvnode.close();
  });

  describe('full node', function() {
    describe('confirmed txs (dsc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 100,
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(history[0].confirmations, 1);
        assert.strictEqual(history[99].confirmations, 2);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 100,
          reverse: true
        });
        assert.strictEqual(one.length, 100);
        assert.strictEqual(one[0].confirmations, 1);
        assert.strictEqual(one[99].confirmations, 2);

        const after = one[99].hash;

        const two = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          after: after,
          limit: 100,
          reverse: true
        });

        assert.strictEqual(two.length, 100);
        assert.strictEqual(two[0].confirmations, 2);
        assert.strictEqual(two[99].confirmations, 4);
        assert.notStrictEqual(two[0].hash, one[11].hash);
      });
    });

    describe('confirmed txs (asc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 12,
          reverse: false
        });
        assert.strictEqual(history.length, 12);
        assert.strictEqual(history[0].confirmations, 125);
        assert.strictEqual(history[11].confirmations, 114);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 12,
          reverse: false
        });
        assert.strictEqual(one.length, 12);
        assert.strictEqual(one[0].confirmations, 125);
        assert.strictEqual(one[11].confirmations, 114);

        const after = one[11].hash;

        const two = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          after: after,
          limit: 12,
          reverse: false
        });
        assert.strictEqual(two.length, 12);
        assert.strictEqual(two[0].confirmations, 113);
        assert.strictEqual(two[11].confirmations, 102);
        assert.notStrictEqual(two[0].hash, one[11].hash);
      });
    });

    describe('unconfirmed txs (dsc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          limit: 100,
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[99].confirmations, 0);
        const b = history[99].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          limit: 100,
          reverse: true
        });

        const after = one[99].hash;

        const two = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          after: after,
          limit: 100,
          reverse: true
        });

        assert.strictEqual(two.length, 95);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[94].confirmations, 0);
        const b = two[94].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);

        assert.notStrictEqual(two[0].hash, one[99].hash);
      });
    });

    describe('unconfirmed txs (asc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          limit: 100,
          reverse: false
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[99].confirmations, 0);
        const b = history[99].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a < b, true);
      });
      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          limit: 100,
          reverse: false
        });

        const after = one[99].hash;

        const two = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          after: after,
          limit: 100,
          reverse: false
        });

        assert.strictEqual(two.length, 95);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[94].confirmations, 0);
        const b = two[94].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a < b, true);

        assert.notStrictEqual(two[0].hash, one[99].hash);
      });
    });
  });

  describe.skip('spv node', function() {
    describe('confirmed txs (dsc)', function() {
      it('first page', async () => {
      });
      it('second page', async () => {
      });
    });

    describe('confirmed txs (asc)', function() {
      it('first page', async () => {
      });
      it('second page', async () => {
      });
    });

    describe('unconfirmed txs (dsc)', function() {
      it('first page', async () => {
      });
      it('second page', async () => {
      });
    });

    describe('unconfirmed txs (asc)', function() {
      it('first page', async () => {
      });
      it('second page', async () => {
      });
    });
  });
});

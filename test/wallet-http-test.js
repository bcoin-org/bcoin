/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const {rimraf, sleep} = require('./util/common');

const {
  initFullNode,
  initSPVNode,
  initNodeClient,
  initWalletClient,
  initWallet,
  generateInitialBlocks,
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
};

describe('Wallet TX HTTP Pagination', function() {
  this.timeout(60000);

  let node, spvnode, wallet = null;
  let nclient, wclient, spvwclient = null;
  let coinbase = null;
  let unconfirmedTime = null;
  let unconfirmedDate = null;

  before(async () => {
    await rimraf(testPrefix);
    await rimraf(spvTestPrefix);

    node = await initFullNode({
      ports,
      prefix: testPrefix,
      logLevel: 'none'
    });

    spvnode = await initSPVNode({
      ports,
      prefix: spvTestPrefix,
      logLevel: 'none'
    });

    nclient = await initNodeClient({ports: ports.full});
    wclient = await initWalletClient({ports: ports.full});
    spvwclient = await initWalletClient({ports: ports.spv});
    wallet = await initWallet(wclient);
    await initWallet(spvwclient);

    await wclient.execute('selectwallet', ['test']);
    coinbase = await wclient.execute('getnewaddress', ['blue']);

    await spvwclient.execute('selectwallet', ['test']);

    await generateInitialBlocks({
      nclient,
      wclient,
      spvwclient,
      coinbase,
      genesisTime,
      blocks: 125
    });

    // Generate unconfirmed transactions for the
    // fullnode and spv wallet
    unconfirmedTime = Math.floor(Date.now() / 1000);
    unconfirmedDate = new Date(unconfirmedTime * 1000);

    // TODO remove this
    await sleep(5000);

    await generateTxs({
      wclient,
      spvwclient,
      count: 19,
      amount: 0.0001,
      gap: 6,
      sleep: 2000
    });

    // TODO remove this. It's necessary to wait because
    // the transactions need to be broadcast to the
    // spv node. However the above await continues
    // before broadcast.
    await sleep(5000);
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
          limit: 100,
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(history[0].confirmations, 1);
        assert.strictEqual(history[99].confirmations, 2);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/history', {
          limit: 100,
          reverse: true
        });
        assert.strictEqual(one.length, 100);
        assert.strictEqual(one[0].confirmations, 1);
        assert.strictEqual(one[99].confirmations, 2);

        const after = one[99].hash;

        const two = await wclient.get('/wallet/test/tx/history', {
          after: after,
          limit: 100,
          reverse: true
        });

        assert.strictEqual(two.length, 100);
        assert.strictEqual(two[0].confirmations, 2);
        assert.strictEqual(two[99].confirmations, 4);
        assert.notStrictEqual(two[0].hash, one[11].hash);
      });

      it('first page (w/ account)', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 100,
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(history[0].confirmations, 1);
        assert.strictEqual(history[99].confirmations, 75);
      });

      it('second page (w/ account)', async () => {
        const one = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          limit: 100,
          reverse: true
        });
        assert.strictEqual(one.length, 100);

        const after = one[99].hash;

        const two = await wclient.get('/wallet/test/tx/history', {
          account: 'blue',
          after: after,
          limit: 100,
          reverse: true
        });
        assert.strictEqual(two.length, 50);
        assert.strictEqual(two[0].confirmations, 76);
        assert.strictEqual(two[49].confirmations, 125);
        assert.notStrictEqual(two[0].hash, one[99].hash);
      });

      it('with datetime (MTP in ISO 8601)', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          limit: 100,
          date: new Date(),
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert(history[0].confirmations < history[99].confirmations);
      });

      it('with datetime (MTP in epoch seconds)', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          limit: 100,
          time: Math.ceil(Date.now() / 1000),
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert(history[0].confirmations < history[99].confirmations);
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

      it('with datetime (MTP in ISO 8601)', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          limit: 100,
          date: genesisDate.toString(),
          reverse: false
        });
        assert.strictEqual(history.length, 100);
        assert(history[0].confirmations > history[99].confirmations);
      });

      it('with datetime (MTP in epoch seconds)', async () => {
        const history = await wclient.get('/wallet/test/tx/history', {
          limit: 100,
          time: genesisTime,
          reverse: false
        });
        assert.strictEqual(history.length, 100);
        assert(history[0].confirmations > history[99].confirmations);
      });
    });

    describe('unconfirmed txs (dsc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 50,
          reverse: true
        });
        assert.strictEqual(history.length, 19);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[18].confirmations, 0);
        const b = history[18].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 4,
          reverse: true
        });

        const after = one[3].hash;

        const two = await wclient.get('/wallet/test/tx/unconfirmed', {
          after: after,
          limit: 25,
          reverse: true
        });

        assert.strictEqual(two.length, 15);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[14].confirmations, 0);
        const b = two[14].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);

        assert.notStrictEqual(two[0].hash, one[3].hash);
      });

      it('with datetime (MTP in ISO 8601)', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 100,
          date: new Date(Date.now() + 2000),
          reverse: true
        });
        assert.strictEqual(history.length, 19);
        assert(history[0].mtime > history[18].mtime);
      });

      it('with datetime (MTP in epoch seconds)', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 100,
          time: Math.ceil((Date.now() + 2000) / 1000),
          reverse: true
        });
        assert.strictEqual(history.length, 19);
        assert(history[0].mtime > history[18].mtime);
      });
    });

    describe('unconfirmed txs (asc)', function() {
      it('first page', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 50,
          reverse: false
        });
        assert.strictEqual(history.length, 19);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[18].confirmations, 0);
        const b = history[18].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a < b, true);
      });

      it('first page (w/ account)', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          account: 'blue',
          limit: 50,
          reverse: false
        });
        assert.strictEqual(history.length, 1);
      });

      it('second page', async () => {
        const one = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 4,
          reverse: false
        });
        assert.strictEqual(one.length, 4);

        const after = one[3].hash;

        const two = await wclient.get('/wallet/test/tx/unconfirmed', {
          after: after,
          limit: 25,
          reverse: false
        });

        assert.strictEqual(two.length, 15);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[14].confirmations, 0);
        const b = two[14].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a < b, true);

        assert.notStrictEqual(two[0].hash, one[3].hash);
      });

      it('with datetime (MTP in ISO 8601)', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 100,
          date: unconfirmedDate.toString(),
          reverse: false
        });
        assert.strictEqual(history.length, 19);
        assert(history[0].mtime < history[18].mtime);
      });

      it('with datetime (MTP in epoch seconds)', async () => {
        const history = await wclient.get('/wallet/test/tx/unconfirmed', {
          limit: 100,
          time: unconfirmedTime,
          reverse: false
        });
        assert.strictEqual(history.length, 19);
        assert(history[0].mtime < history[18].mtime);
      });
    });
  });

  describe('spv node', function() {
    describe('confirmed txs (dsc)', function() {
      it('first page', async () => {
        const history = await spvwclient.get('/wallet/test/tx/history', {
          limit: 100,
          reverse: true
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(
          history[0].confirmations < history[99].confirmations, true);
      });
      it('second page', async () => {
        const one = await spvwclient.get('/wallet/test/tx/history', {
          limit: 100,
          reverse: true
        });
        assert.strictEqual(one.length, 100);
        assert.strictEqual(one[0].confirmations < one[99].confirmations, true);

        const after = one[99].hash;

        const two = await spvwclient.get('/wallet/test/tx/history', {
          after: after,
          limit: 100,
          reverse: true
        });

        assert.strictEqual(two.length, 100);
        assert.strictEqual(
          two[0].confirmations < two[99].confirmations, true);
        assert.notStrictEqual(two[0].hash, one[11].hash);
      });
    });

    describe('confirmed txs (asc)', function() {
      it('first page', async () => {
        const history = await spvwclient.get('/wallet/test/tx/history', {
          limit: 100,
          reverse: false
        });
        assert.strictEqual(history.length, 100);
        assert.strictEqual(
          history[0].confirmations > history[99].confirmations, true);
      });
      it('second page', async () => {
        const one = await spvwclient.get('/wallet/test/tx/history', {
          limit: 100,
          reverse: false
        });
        assert.strictEqual(one.length, 100);

        const after = one[99].hash;

        const two = await spvwclient.get('/wallet/test/tx/history', {
          after: after,
          limit: 100,
          reverse: false
        });

        assert.strictEqual(two.length, 100);
        assert.strictEqual(
          two[0].confirmations > two[99].confirmations, true);
        assert.notStrictEqual(two[0].hash, one[11].hash);
      });
    });

    describe('unconfirmed txs (dsc)', function() {
      it('first page', async () => {
        const history = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          limit: 50,
          reverse: true
        });
        assert.strictEqual(history.length, 19);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[18].confirmations, 0);
        const b = history[18].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);
      });
      it('second page', async () => {
        const one = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          limit: 4,
          reverse: true
        });
        assert.strictEqual(one.length, 4);

        const after = one[3].hash;

        const two = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          after: after,
          limit: 25,
          reverse: true
        });

        assert.strictEqual(two.length, 15);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[14].confirmations, 0);
        const b = two[14].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a > b, true);

        assert.notStrictEqual(two[0].hash, one[3].hash);
      });
    });

    describe('unconfirmed txs (asc)', function() {
      it('first page', async () => {
        const history = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          limit: 50,
          reverse: false
        });
        assert.strictEqual(history.length, 19);
        assert.strictEqual(history[0].confirmations, 0);
        const a = history[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(history[18].confirmations, 0);
        const b = history[18].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a < b, true);
      });
      it('second page', async () => {
        const one = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          limit: 4,
          reverse: false
        });
        assert.strictEqual(one.length, 4);

        const after = one[3].hash;

        const two = await spvwclient.get('/wallet/test/tx/unconfirmed', {
          after: after,
          limit: 25,
          reverse: false
        });

        assert.strictEqual(two.length, 15);
        assert.strictEqual(two[0].confirmations, 0);
        const a = two[0].mtime;
        assert.strictEqual(Number.isInteger(a), true);
        assert.strictEqual(two[14].confirmations, 0);
        const b = two[14].mtime;
        assert.strictEqual(Number.isInteger(b), true);
        assert.strictEqual(a <= b, true);
        assert.notStrictEqual(two[0].hash, one[3].hash);
      });
    });
  });
});

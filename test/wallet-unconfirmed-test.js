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
  generateBlocks,
  generateRollback,
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

async function getAllUnconfirmed(wclient) {
  let txs = await wclient.execute('listunconfirmed', ['blue', 100, true]);

  while (txs.length) {
    let after = txs[txs.length - 1].txid;
    let res = await wclient.execute('listunconfirmedafter',
                                    ['blue', after, 100, true]);
    if (res.length) {
      txs = txs.concat(res);
    } else {
      break;
    }
  }

  return txs;
}

describe('Wallet Unconfirmed TX', function() {
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

    await generateTxs({
      wclient,
      count: 195,
      amount: 0.0001,
      gap: 50,
      sleep: 1000
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

  it('should get correct transaction count', async () => {
    const count = await wclient.execute('listhistorycount', ['blue']);
    assert.strictEqual(count, 575);
  });

  describe('get unconfirmed transaction history (dsc)', function() {
    it('first page', async () => {
      const history = await wclient.execute('listunconfirmed', ['blue', 100, true]);
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 0);
      const a = history[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 0);
      const b = history[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a > b, true);
    });

    it('second page', async () => {
      const one = await wclient.execute('listunconfirmed', ['blue', 100, true]);
      assert.strictEqual(one[0].account, 'blue');
      assert.strictEqual(one[0].confirmations, 0);
      const a = one[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(one[99].account, 'blue');
      assert.strictEqual(one[99].confirmations, 0);
      const b = one[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a > b, true);

      const after = one[99].txid;

      const two = await wclient.execute('listunconfirmedafter', ['blue', after, 100, true]);
      assert.strictEqual(two.length, 95);
      assert.strictEqual(two[0].account, 'blue');
      assert.strictEqual(two[0].confirmations, 0);
      const c = two[0].timereceived;
      assert.strictEqual(Number.isInteger(c), true);
      assert.strictEqual(two[94].account, 'blue');
      assert.strictEqual(two[94].confirmations, 0);
      const d = two[94].timereceived;
      assert.strictEqual(Number.isInteger(d), true);
      assert.strictEqual(a > b, true);
    });

    // TODO
    // - third page after new block (no shifting)
    // - last page
  });

  describe('get transaction history (asc)', () => {
    it('first page', async () => {
      const history = await wclient.execute('listunconfirmed', ['blue', 100, false]);
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 0);
      const a = history[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 0);
      const b = history[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a < b, true);
    });

    it('second page', async () => {
      const one = await wclient.execute('listunconfirmed', ['blue', 100, false]);
      assert.strictEqual(one.length, 100);
      assert.strictEqual(one[0].account, 'blue');
      assert.strictEqual(one[0].confirmations, 0);
      const a = one[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(one[99].account, 'blue');
      assert.strictEqual(one[99].confirmations, 0);
      const b = one[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a < b, true);

      const after = one[99].txid;

      const two = await wclient.execute('listunconfirmedafter', ['blue', after, 95, false]);
      assert.strictEqual(two.length, 95);
      assert.strictEqual(two[0].account, 'blue');
      assert.strictEqual(two[0].confirmations, 0);
      const c = one[0].timereceived;
      assert.strictEqual(Number.isInteger(c), true);
      assert.strictEqual(two[94].account, 'blue');
      assert.strictEqual(two[94].confirmations, 0);
      const d = one[0].timereceived;
      assert.strictEqual(Number.isInteger(d), true);
      assert.strictEqual(a < b, true);

      assert.notStrictEqual(two[0].txid, one[99].txid);
    });

    // TODO
    // - third page after new block (no shifting)
    // - last page
  });

  describe('get transaction history by timestamp (asc)', () => {
    it('older to newer', async () => {
      const history = await wclient.execute(
        'listunconfirmedbytime',
        ['blue', unconfirmedTime, 100, false]
      );
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 0);
      const a = history[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 0);
      const b = history[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a < b, true);
    });

    it('newer to older', async () => {
      const history = await wclient.execute(
        'listunconfirmedbytime',
        ['blue', new Date(), 100, true]
      );
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 0);
      const a = history[0].timereceived;
      assert.strictEqual(Number.isInteger(a), true);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 0);
      const b = history[99].timereceived;
      assert.strictEqual(Number.isInteger(b), true);
      assert.strictEqual(a > b, true);
    });

    // TODO
    // - arbitrary date
  });

  describe('chain rollback', () => {
    it('confirm and unconfirm indexes', async() => {
      const validated = await generateBlocks(5, nclient, coinbase);
      await sleep(1000);

      let txs = await getAllUnconfirmed(wclient);
      assert.strictEqual(txs.length, 0);

      const invalidated = await generateRollback(5, nclient);
      await sleep(1000);

      txs = await getAllUnconfirmed(wclient);
      assert.strictEqual(txs.length, 196);
    });
  });
});

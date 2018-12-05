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
  generateReorg
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

    // TODO use an event here instead.
    // We need to wait for blocks to confirm.
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

  it('should get correct transaction count', async () => {
    const count = await wclient.execute('listhistorycount', ['blue']);
    assert.strictEqual(count, 575);
  });

  describe('get transaction history (dsc)', function() {
    it('first page', async () => {
      const history = await wclient.execute('listhistory', ['blue', 100, true]);
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 1);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 2);
    });

    it('second page', async () => {
      const one = await wclient.execute('listhistory', ['blue', 100, true]);
      assert.strictEqual(one[0].account, 'blue');
      assert.strictEqual(one[0].confirmations, 1);
      assert.strictEqual(one[99].account, 'blue');
      assert.strictEqual(one[99].confirmations, 2);

      const after = one[99].txid;

      const two = await wclient.execute('listhistoryafter', ['blue', after, 100, true]);
      assert.strictEqual(two.length, 100);
      assert.strictEqual(two[0].account, 'blue');
      assert.strictEqual(two[0].confirmations, 2);
      assert.strictEqual(two[99].account, 'blue');
      assert.strictEqual(two[99].confirmations, 4);
    });

    // TODO
    // - third page after new block (no shifting)
    // - last page
  });

  describe('get transaction history (asc)', () => {
    it('first page', async () => {
      const history = await wclient.execute('listhistory', ['blue', 12, false]);
      assert.strictEqual(history.length, 12);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 125);
      assert.strictEqual(history[11].account, 'blue');
      assert.strictEqual(history[11].confirmations, 114);
    });

    it('second page', async () => {
      const one = await wclient.execute('listhistory', ['blue', 12, false]);
      assert.strictEqual(one.length, 12);
      assert.strictEqual(one[0].account, 'blue');
      assert.strictEqual(one[0].confirmations, 125);
      assert.strictEqual(one[11].account, 'blue');
      assert.strictEqual(one[11].confirmations, 114);

      const after = one[11].txid;

      const two = await wclient.execute('listhistoryafter', ['blue', after, 12, false]);
      assert.strictEqual(two.length, 12);
      assert.strictEqual(two[0].account, 'blue');
      assert.strictEqual(two[0].confirmations, 113);
      assert.strictEqual(two[11].account, 'blue');
      assert.strictEqual(two[11].confirmations, 102);
      assert.notStrictEqual(two[0].txid, one[11].txid);
    });

    // TODO
    // - third page after new block (no shifting)
    // - last page
  });

  describe('get transaction history by timestamp (asc)', () => {
    it('genesis to latest', async () => {
      const history = await wclient.execute('listhistorybytime', ['blue', genesisDate, 12, false]);
      assert.strictEqual(history.length, 12);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 125);
      assert.strictEqual(history[11].account, 'blue');
      assert.strictEqual(history[11].confirmations, 114);
    });

    it('latest to genesis', async () => {
      const history = await wclient.execute('listhistorybytime', ['blue', new Date(), 100, true]);
      assert.strictEqual(history.length, 100);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 1);
      assert.strictEqual(history[99].account, 'blue');
      assert.strictEqual(history[99].confirmations, 3); // TODO this will sometimes be 2
    });

    // TODO
    // - last arbitrary date
  });

  describe('chain reorganizations', () => {
    const depth = 1;
    let previous = null;
    const now = new Date() + 10000;
    let txids = new Map();

    before(async () => {
      previous = await wclient.execute('listhistorybytime', ['blue', now, 100, true]);

      const result = await generateReorg(depth, nclient, wclient, coinbase);
      assert.notStrictEqual(result.invalidated[0], result.validated[0]);

      for (let txid of result.txids)
        txids.set(txid);

      // TODO remove this
      await sleep(5000);
    });

    it('reorganize count and monotonic time indexes', async() => {
      const current = await wclient.execute('listhistorybytime', ['blue', now, 100, true]);

      let currentMap = new Map();

      for (let p of current)
        currentMap.set(p.txid, p);

      for (let txid of txids.keys())
        assert.strictEqual(currentMap.has(txid), true);
    });

  });
});

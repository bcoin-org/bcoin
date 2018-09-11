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
  generateBlock,
  generateInitialBlocks
} = require('./util/regtest');

const testPrefix = '/tmp/bcoin-fullnode';
const spvTestPrefix = '/tmp/bcoin-spvnode';
const genesisTime = 1534965859;

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
      blocks: 120
    });

    // TODO use an event here instead.
    // We need to wait for blocks to confirm.
    await sleep(10000);
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
    assert.strictEqual(count, 570);
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

    it('third page after new block (no shifting)', async () => {

    });

    it('last page', async () => {
    });
  });

  describe('get transaction history (asc)', () => {
    it('first page', async () => {
      const history = await wclient.execute('listhistory', ['blue', 12, false]);
      assert.strictEqual(history.length, 12);
      assert.strictEqual(history[0].account, 'blue');
      assert.strictEqual(history[0].confirmations, 120);
      assert.strictEqual(history[11].account, 'blue');
      assert.strictEqual(history[11].confirmations, 109);
    });

    it('second page', async () => {
      const one = await wclient.execute('listhistory', ['blue', 12, false]);
      assert.strictEqual(one.length, 12);
      assert.strictEqual(one[0].account, 'blue');
      assert.strictEqual(one[0].confirmations, 120);
      assert.strictEqual(one[11].account, 'blue');
      assert.strictEqual(one[11].confirmations, 109);

      const after = one[11].txid;

      const two = await wclient.execute('listhistoryafter', ['blue', after, 12, false]);
      assert.strictEqual(two.length, 12);
      assert.strictEqual(two[0].account, 'blue');
      assert.strictEqual(two[0].confirmations, 108);
      assert.strictEqual(two[11].account, 'blue');
      assert.strictEqual(two[11].confirmations, 97);
      assert.notStrictEqual(two[0].txid, one[11].txid);
    });

    it('third page after new block (no shifting)', async () => {

    });

    it('last page', async () => {

    });
  });

  describe('get transaction history by timestamp (asc)', () => {
    it('genesis to latest', async () => {

    });

    it('latest to genesis', async () => {

    });

    it('arbitrary date', async () => {

    });
  });
});

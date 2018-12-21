/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const {rimraf, sleep} = require('./util/common');
const KeyRing = require('../lib/primitives/keyring');

const {
  initFullNode,
  initNodeClient,
  initWalletClient,
  initWallet,
  generateInitialBlocks,
  generateBlocks,
  sendCoinbase
} = require('./util/regtest');

const testPrefix = '/tmp/bcoin-fullnode';
const genesisTime = 1534965859;

const ports = {
  full: {
    p2p: 49331,
    node: 49332,
    wallet: 49333
  }
};

describe('Wallet Rescan', function() {
  this.timeout(30000);

  // SPV isn't tested here as rescanning will
  // not work in that case, furthermore it will also
  // not work for pruned nodes. There may need to be
  // additional error messages on related APIs that
  // assume use of rescan.

  let node, wallet = null;
  let nclient, wclient = null;
  let coinbase, coinbaseKey = null;
  let fulladdr = null;
  let key1 = null;

  before(async () => {
    await rimraf(testPrefix);

    node = await initFullNode({
      ports,
      prefix: testPrefix,
      logLevel: 'none'
    });

    nclient = await initNodeClient({ports: ports.full});
    wclient = await initWalletClient({ports: ports.full});
    wallet = await initWallet(wclient);

    coinbaseKey = KeyRing.generate();

    await wclient.execute('selectwallet', ['test']);

    fulladdr = await wclient.execute('getnewaddress', ['blue']);

    // Use coinbase outside of any wallet so
    // that we can send funds to various addresses
    // without affecting the wallets.
    coinbase = coinbaseKey.getAddress('base58', 'regtest').toString();

    await generateInitialBlocks({
      nclient,
      coinbase,
      genesisTime,
      blocks: 200
    });

    // TODO remove this
    await sleep(1000);

    key1 = KeyRing.generate();

    let height = 0;

    // Send funds to the existing wallets
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await generateBlocks(1, nclient, coinbase);

    // Send funds to the addresses to be imported
    let importTotal = 0;
    for (++height; height < 14; height++) {
      const address = key1.getAddress('base58', 'regtest').toString();
      await sendCoinbase({
        nclient,
        height,
        coinbaseKey,
        address
      });
      importTotal++;
    }

    assert.strictEqual(importTotal, 12);

    await generateBlocks(1, nclient, coinbase);

    // Send more funds to the wallets after the
    // addresses to be imported
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await generateBlocks(1, nclient, coinbase);

    // TODO remove this
    await sleep(1000);

    const history = await wclient.execute('listhistory',
                                          [null, 100, true]);
    assert.strictEqual(history.length, 2);

    // Import keys into wallets and rescan
    const key1Priv = key1.getPrivateKey('base58', 'regtest');
    await wclient.execute('importprivkey',
                          [key1Priv, null, true]);

    // TODO remove this
    await sleep(1000);
  });

  after(async () => {
    await wallet.close();
    await wclient.close();
    await nclient.close();
    await node.close();
  });

  it('will include txs of imported addresses', async () => {
    const history = await wclient.execute('listhistory',
                                          [null, 100, true]);
    assert.strictEqual(history.length, 14);
  });

  it('will include txs in correct order', async() => {
    const history = await wclient.execute('listhistory',
                                          [null, 100, true]);
    assert.strictEqual(history[0].account, 'blue');

    for (let i = 1; i < 13; i++)
      assert.strictEqual(history[i].account, 'default');

    assert.strictEqual(history[13].account, 'blue');
  });
});

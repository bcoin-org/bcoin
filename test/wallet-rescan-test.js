/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const path = require('path');
const assert = require('./util/assert');
const rimraf = require('./util/rimraf');
const sleep = require('./util/sleep');
const KeyRing = require('../lib/primitives/keyring');

const {
  initFullNode,
  initSPVNode,
  initNodeClient,
  initWalletClient,
  initWallet,
  generateInitialBlocks,
  generateBlocks,
  generateReorg,
  generateTxs,
  sendCoinbase
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

describe('Wallet Rescan', function() {
  this.timeout(30000);

  let node, spvnode, wallet, spvwallet = null;
  let nclient, wclient, spvwclient = null;
  let coinbase, coinbaseKey = null;
  let fulladdr, spvaddr = null;
  let key1, key2, key3 = null;

  before(async () => {
    await rimraf(testPrefix);
    await rimraf(spvTestPrefix);

    node = await initFullNode({ports, prefix: testPrefix, logLevel: 'none'});
    spvnode = await initSPVNode({ports, prefix: spvTestPrefix, logLevel: 'none'});

    nclient = await initNodeClient({ports: ports.full});
    wclient = await initWalletClient({ports: ports.full});
    spvwclient = await initWalletClient({ports: ports.spv});
    wallet = await initWallet(wclient);
    spvwallet = await initWallet(spvwclient);

    coinbaseKey = KeyRing.generate();

    await wclient.execute('selectwallet', ['test']);
    await spvwclient.execute('selectwallet', ['test']);

    fulladdr = await wclient.execute('getnewaddress', ['blue']);
    spvaddr = await spvwclient.execute('getnewaddress', ['blue']);

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
    await sleep(5000);

    key1 = KeyRing.generate();
    key2 = KeyRing.generate();
    key3 = KeyRing.generate();

    let height = 0;

    // Send funds to the existing wallets
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: spvaddr
    });

    await generateBlocks(1, nclient, coinbase);

    // Send funds to the addresses to be imported
    for (++height; height < 13; height++) {
      const address = key1.getAddress('base58', 'regtest').toString();
      await sendCoinbase({
        nclient,
        height,
        coinbaseKey,
        address
      });
    }

    await generateBlocks(1, nclient, coinbase);

    // Send more funds to the wallets after the
    // addresses to be imported
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: spvaddr
    });

    await generateBlocks(1, nclient, coinbase);

    // Import keys into wallets and rescan
    const key1Priv = key1.getPrivateKey('base58', 'regtest');
    await wclient.execute('importprivkey', [key1Priv, null, true]);
    await spvwclient.execute('importprivkey', [key1Priv, null, true]);

    // TODO remove this
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

  describe('full node wallet', function() {
    it('has the correct number of txs', async () => {
      const history = await wclient.execute('listhistory', ['blue', 100, true]);
      assert.strictEqual(history.length, 14);
    });

    it('wallet should include txs of imported addresses', async () => {
    });
  });

  describe('spv node wallet', function() {
    it('has the correct number of txs', async () => {
      const history = await spvwclient.execute('listhistory', ['blue', 100, true]);
      assert.strictEqual(history.length, 14);
    });

    it('wallet should include txs of imported addresses', async () => {
    });
  });
});

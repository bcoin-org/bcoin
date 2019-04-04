/* eslint-env mocha */

'use strict';

const {NodeClient, WalletClient} = require('bclient');
const assert = require('./util/assert');
const {testdir, rimraf, event} = require('./util/common');
const KeyRing = require('../lib/primitives/keyring');
const Coin = require('../lib/primitives/coin');
const MTX = require('../lib/primitives/mtx');
const FullNode = require('../lib/node/fullnode');

const COINBASE = Buffer.from(
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex');

const KEY1 = Buffer.from(
  '3d35a74bb0a8b883682bfe3209e967aeda3bfd73fe8e740bc700f5fe5c4c265d', 'hex');

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

async function sendCoinbase(options) {
  const {
    nclient,
    height,
    address,
    coinbaseKey
  } = options;

  const hash = await nclient.execute('getblockhash', [height]);
  const block = await nclient.execute('getblock', [hash, true, true]);

  const script = Buffer.from(block.tx[0].vout[0].scriptPubKey.hex, 'hex');
  const prevhash = Buffer.from(block.tx[0].txid, 'hex');
  prevhash.reverse();

  const mtx = new MTX();

  mtx.addCoin(Coin.fromOptions({
    value: 5000000000,
    script: script,
    hash: prevhash,
    index: 0
  }));

  mtx.addOutput({
    address: address,
    value: 4999000000
  });

  mtx.sign(coinbaseKey);

  const tx = mtx.toTX();

  await nclient.execute('sendrawtransaction',
                        [tx.toRaw().toString('hex')]);
}

describe('Wallet Rescan', function() {
  this.timeout(30000);

  const prefix = testdir('rescan');

  let node, wallet = null;
  let nclient, wclient = null;
  let coinbase, coinbaseKey = null;
  let fulladdr = null;
  let key1 = null;

  before(async () => {
    await rimraf(prefix);

    // Setup the full node.
    node = new FullNode({
      prefix: prefix,
      network: 'regtest',
      port: ports.p2p,
      httpPort: ports.node,
      memory: false,
      plugins: [require('../lib/wallet/plugin')],
      env: {
        'BCOIN_WALLET_HTTP_PORT': (ports.wallet).toString()
      },
      logLevel: 'none'
    });

    await node.ensure();
    await node.open();

    // Setup the node client.
    nclient = new NodeClient({
      network: 'regtest',
      port: ports.node
    });

    await nclient.open();

    // Setup the wallet client.
    wclient = new WalletClient({
      network: 'regtest',
      port: ports.wallet
    });

    await wclient.open();

    // Initialize the wallet.
    const winfo = await wclient.createWallet('test');
    assert.strictEqual(winfo.id, 'test');

    wallet = wclient.wallet('test');
    await wallet.open();

    const info = await wallet.createAccount('blue', {
      witness: true
    });

    assert(info.initialized);
    assert.strictEqual(info.name, 'blue');
    assert.strictEqual(info.accountIndex, 1);
    assert.strictEqual(info.m, 1);
    assert.strictEqual(info.n, 1);

    // Setup key receive the block coinbase
    // for mining that is not tracked by
    // the wallet.
    coinbaseKey = new KeyRing({
      privateKey: COINBASE,
      witness: true
    });

    // Setup the key to be imported that is
    // not initially tracked by the wallet.
    key1 = new KeyRing({
      privateKey: KEY1,
      witness: true
    });

    await wclient.execute('selectwallet', ['test']);

    fulladdr = await wclient.execute('getnewaddress', ['blue']);

    // Use coinbase outside of any wallet so
    // that we can send funds to various addresses
    // without affecting the wallets.
    coinbase = coinbaseKey.getAddress('string', 'regtest').toString();

    // Generate the initial blocks.
    await nclient.execute('generatetoaddress', [120, coinbase]);

    let height = 0;

    // Send funds to the existing wallets.
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await nclient.execute('generatetoaddress', [1, coinbase]);

    // Send funds to the addresses to be imported.
    let importTotal = 0;
    for (++height; height < 14; height++) {
      const address = key1.getAddress('string', 'regtest').toString();
      await sendCoinbase({
        nclient,
        height,
        coinbaseKey,
        address
      });
      importTotal++;
    }

    assert.strictEqual(importTotal, 12);
    await nclient.execute('generatetoaddress', [1, coinbase]);

    // Send more funds to the wallets after the
    // addresses to be imported.
    await sendCoinbase({
      nclient,
      height: ++height,
      coinbaseKey,
      address: fulladdr
    });

    await nclient.execute('generatetoaddress', [1, coinbase]);

    // Wait for the wallet to be confirmed.
    await event(wallet, 'confirmed');

    // Verify the initial state of the wallet to
    // have the correct information.
    const history = await wclient.execute('listtransactions');
    assert.strictEqual(history.length, 2);
    const balance = await wclient.execute('getbalance');
    assert.strictEqual(balance, 99.98);

    // Import keys into wallets and rescan.
    const key1Priv = key1.getPrivateKey('base58', 'regtest');
    await wclient.execute('importprivkey',
                          [key1Priv, null, true]);
  });

  after(async () => {
    await wallet.close();
    await wclient.close();
    await nclient.close();
    await node.close();
    await rimraf(prefix);
  });

  it('will include balance of imported addresses', async () => {
    const balance = await wclient.execute('getbalance');
    assert.strictEqual(balance, 699.86);
  });

  it('will include txs of imported addresses', async () => {
    const history = await wclient.execute('listtransactions', [null, 100]);
    assert.strictEqual(history.length, 14);
  });
});

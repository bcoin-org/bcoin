/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const consensus = require('../lib/protocol/consensus');
const Address = require('../lib/primitives/address');
const FullNode = require('../lib/node/fullnode');

const ports = {
  p2p: 49331,
  node: 49332,
  wallet: 49333
};

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  memory: true,
  workers: true,
  plugins: [require('../lib/wallet/plugin')],
  port: ports.p2p,
  httpPort: ports.node,
  env: {
    'BCOIN_WALLET_HTTP_PORT': ports.wallet.toString()
  }});

const {NodeClient, WalletClient} = require('bclient');

const nclient = new NodeClient({
  port: ports.node,
  apiKey: 'foo'
});

const wclient = new WalletClient({
  port: ports.wallet,
  apiKey: 'foo'
});

const {wdb} = node.require('walletdb');
const defaultCoinbaseMaturity = consensus.COINBASE_MATURITY;

let addressHot = null;
let addressMiner = null;
let walletHot = null;
let walletMiner = null;
let blocks = null;
let txid = null;
let utxo = null;

describe('RPC', function() {
  this.timeout(15000);

  before(() => {
    consensus.COINBASE_MATURITY = 0;
  });

  after(() => {
    consensus.COINBASE_MATURITY = defaultCoinbaseMaturity;
  });

  it('should open node and create wallets', async () => {
    await node.open();
    await nclient.open();
    await wclient.open();

    const walletHotInfo = await wclient.createWallet('hot');
    walletHot = wclient.wallet('hot', walletHotInfo.token);
    const walletMinerInfo = await wclient.createWallet('miner');
    walletMiner = wclient.wallet('miner', walletMinerInfo.token);
    await walletHot.open();
    await walletMiner.open();
  });

  it('should rpc help', async () => {
    assert(await nclient.execute('help', []));
    assert(await wclient.execute('help', []));

    await assert.asyncThrows(async () => {
      await nclient.execute('help', ['getinfo']);
    }, 'getinfo');

    await assert.asyncThrows(async () => {
      await wclient.execute('help', ['getbalance']);
    }, 'getbalance');
  });

  it('should rpc getinfo', async () => {
    const info = await nclient.execute('getinfo', []);
    assert.strictEqual(info.blocks, 0);
  });

  it('should rpc selectwallet', async () => {
    const response = await wclient.execute('selectwallet', ['miner']);
    assert.strictEqual(response, null);
  });

  it('should rpc getnewaddress from default account', async () => {
    const acctAddr = await wclient.execute('getnewaddress', []);
    assert(Address.fromString(acctAddr.toString()));
  });

  it('should fail rpc getnewaddress from nonexistent account', async () => {
    await assert.asyncThrows(async () => {
      await wclient.execute('getnewaddress', ['bad-account-name']);
    }, 'Account not found.');
  });

  it('should rpc getaccountaddress', async () => {
    addressMiner = await wclient.execute('getaccountaddress', ['default']);
    assert(Address.fromString(addressMiner.toString()));
  });

  it('should rpc generatetoaddress', async () => {
    blocks = await nclient.execute('generatetoaddress',
      [10, addressMiner]);
    assert.strictEqual(blocks.length, 10);
  });

  it('should rpc sendtoaddress', async () => {
    const acctHotDefault = await walletHot.getAccount('default');
    addressHot = acctHotDefault.receiveAddress;

    txid = await wclient.execute('sendtoaddress', [addressHot, 0.1234]);
    assert.strictEqual(txid.length, 64);
  });

  it('should rpc sendmany', async () => {
    const sendTo = {};
    sendTo[addressHot] = 1.0;
    sendTo[addressMiner] = 0.1111;
    txid = await wclient.execute('sendmany', ['default', sendTo]);
    assert.strictEqual(txid.length, 64);
  });

  it('should fail malformed rpc sendmany', async () => {
    await assert.asyncThrows(async () => {
      await wclient.execute('sendmany', ['default', null]);
    }, 'Invalid send-to address');

    const sendTo = {};
    sendTo[addressHot] = null;
    await assert.asyncThrows(async () => {
      await wclient.execute('sendmany', ['default', sendTo]);
    }, 'Invalid amount.');
  });

  it('should rpc listreceivedbyaddress', async () => {
    await wclient.execute('selectwallet', ['hot']);

    const listZeroConf = await wclient.execute('listreceivedbyaddress',
      [0, false, false]);
    assert.deepStrictEqual(listZeroConf, [{
      'involvesWatchonly': false,
      'address': addressHot,
      'account': 'default',
      'amount': 1.1234,
      'confirmations': 0,
      'label': ''
    }]);

    blocks.push(await nclient.execute('generatetoaddress', [1, addressMiner]));
    await wdb.syncChain();

    const listSomeConf = await wclient.execute('listreceivedbyaddress',
      [1, false, false]);
    assert.deepStrictEqual(listSomeConf, [{
      'involvesWatchonly': false,
      'address': addressHot,
      'account': 'default',
      'amount': 1.1234,
      'confirmations': 1,
      'label': ''
    }]);

    const listTooManyConf = await wclient.execute('listreceivedbyaddress',
      [100, false, false]);
    assert.deepStrictEqual(listTooManyConf, []);
  });

  it('should rpc listtransactions with no args', async () => {
    const txs = await wclient.execute('listtransactions', []);
    assert.strictEqual(txs.length, 2);
    assert.strictEqual(txs[0].amount + txs[1].amount, 1.1234);
    assert.strictEqual(txs[0].account, 'default');
  });

  it('should rpc listtransactions from specified account', async () => {
    const wallet = await wclient.wallet('hot');
    await wallet.createAccount('foo');

    const txs = await wclient.execute('listtransactions', ['foo']);
    assert.strictEqual(txs.length, 0);
  });

  it('should fail rpc listtransactions from nonexistent account', async () => {
    assert.asyncThrows(async () => {
      await wclient.execute('listtransactions', ['nonexistent']);
    }, 'Account not found.');
  });

  it('should rpc listunspent', async () => {
    utxo = await wclient.execute('listunspent', []);
    assert.strictEqual(utxo.length, 2);
  });

  it('should rpc lockunspent and listlockunspent', async () => {
    let result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, []);

    // lock one utxo
    const output = utxo[0];
    const outputsToLock = [{'txid': output.txid, 'vout': output.vout}];
    result = await wclient.execute('lockunspent', [false, outputsToLock]);
    assert(result);

    result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, outputsToLock);

    // unlock all
    result = await wclient.execute('lockunspent', [true]);
    assert(result);

    result = await wclient.execute('listlockunspent', []);
    assert.deepStrictEqual(result, []);
  });

  it('should rpc listsinceblock', async () => {
    const listNoBlock = await wclient.execute('listsinceblock', []);
    assert.strictEqual(listNoBlock.transactions.length, 2);
    // txs returned in unpredictable order
    const txids = [
      listNoBlock.transactions[0].txid,
      listNoBlock.transactions[1].txid
    ];
    assert(txids.includes(txid));

    const block5 = blocks[5];
    const listOldBlock = await wclient.execute('listsinceblock', [block5]);
    assert.strictEqual(listOldBlock.transactions.length, 2);

    const nonexistentBlock = consensus.ZERO_HASH.toString('hex');
    await assert.asyncThrows(async () => {
      await wclient.execute('listsinceblock', [nonexistentBlock]);
    }, 'Block not found');
  });

  it('should cleanup', async () => {
    await walletHot.close();
    await walletMiner.close();
    await wclient.close();
    await nclient.close();
    await node.close();
  });
});

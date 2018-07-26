/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const consensus = require('../lib/protocol/consensus');
const FullNode = require('../lib/node/fullnode');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');

const node = new FullNode({
  network: 'regtest',
  apiKey: 'foo',
  walletAuth: true,
  memory: true,
  workers: true,
  plugins: [require('../lib/wallet/plugin')]
});

const {NodeClient, WalletClient} = require('bclient');

const nclient = new NodeClient({
  port: network.rpcPort,
  apiKey: 'foo'
});

const wclient = new WalletClient({
  port: network.walletPort,
  apiKey: 'foo'
});

const {wdb} = node.require('walletdb');

let addressHot = null;
let addressMiner = null;
let walletHot = null;
let walletMiner = null;
let blocks = null;
let txid = null;
let utxo = null;

describe('RPC', function() {
  this.timeout(15000);

  it('should open node and create wallets', async () => {
    consensus.COINBASE_MATURITY = 0;
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
    assert( await nclient.execute('help', []) );
    assert( await wclient.execute('help', []) );

    await assert.rejects( async () => await nclient.execute('help',
      ['getinfo']) );

    await assert.rejects( async () => await wclient.execute('help',
      ['getbalance']) );
  });

  it('should rpc getinfo', async () => {
    const info = await nclient.execute('getinfo', []);
    assert.strictEqual(info.blocks, 0);
  });

  it('should rpc selectwallet', async () => {
    const response = await wclient.execute('selectwallet', ['miner']);
    assert.strictEqual(response, null);
  });

  it('should rpc getaccountaddress', async () => {
    addressMiner = await wclient.execute('getaccountaddress', ['default']);
    assert(addressMiner);
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

  it('should rpc listreceivedbyaddress', async () => {
    await wclient.execute('selectwallet', ['hot']);

    const listZeroConf = await wclient.execute('listreceivedbyaddress',
      [0, false, false]);
    assert.deepStrictEqual(listZeroConf, [{
      'involvesWatchonly': false,
      'address': addressHot,
      'account': 'default',
      'amount': .1234,
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
      'amount': .1234,
      'confirmations': 1,
      'label': ''
    }]);

    const listTooManyConf = await wclient.execute('listreceivedbyaddress',
      [100, false, false]);
    assert.deepStrictEqual(listTooManyConf, []);
  });

  it('should rpc listunspent', async () => {
    utxo = await wclient.execute('listunspent', []);
    assert.strictEqual(utxo.length, 1);
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

  it('should rpv listsinceblock', async () => {
    const listNoBlock = await wclient.execute('listsinceblock', []);
    assert.strictEqual(listNoBlock.transactions[0].txid, txid);

    const block5 = blocks[5];
    const listOldBlock = await wclient.execute('listsinceblock', [block5]);
    assert.strictEqual(listOldBlock.transactions[0].txid, txid);
  });
});

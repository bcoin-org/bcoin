/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const consensus = require('../lib/protocol/consensus');
const Address = require('../lib/primitives/address');
const Script = require('../lib/script/script');
const Outpoint = require('../lib/primitives/outpoint');
const MTX = require('../lib/primitives/mtx');
const FullNode = require('../lib/node/fullnode');
const pkg = require('../lib/pkg');
const Network = require('../lib/protocol/network');
const network = Network.get('regtest');

if (process.browser)
  return;

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

let wallet = null;

const {wdb} = node.require('walletdb');

let addr = null;
let hash = null;
let rawtx = null;

describe('HTTP', function() {
  this.timeout(15000);

  it('should open node', async () => {
    consensus.COINBASE_MATURITY = 0;
    await node.open();
    await nclient.open();
    await wclient.open();
  });

  it('should create wallet', async () => {
    const info = await wclient.createWallet('test');
    assert.strictEqual(info.id, 'test');
    wallet = wclient.wallet('test', info.token);
    await wallet.open();
  });

  it('should get info', async () => {
    const info = await nclient.getInfo();
    assert.strictEqual(info.network, node.network.type);
    assert.strictEqual(info.version, pkg.version);
    assert.typeOf(info.pool, 'object');
    assert.strictEqual(info.pool.agent, node.pool.options.agent);
    assert.typeOf(info.chain, 'object');
    assert.strictEqual(info.chain.height, 0);
  });

  it('should get wallet info', async () => {
    const info = await wallet.getInfo();
    assert.strictEqual(info.id, 'test');
    const acct = await wallet.getAccount('default');
    const str = acct.receiveAddress;
    assert.typeOf(str, 'string');
    addr = Address.fromString(str, node.network);
  });

  it('should fill with funds', async () => {
    const mtx = new MTX();
    mtx.addOutpoint(new Outpoint(consensus.ZERO_HASH, 0));
    mtx.addOutput(addr, 50460);
    mtx.addOutput(addr, 50460);
    mtx.addOutput(addr, 50460);
    mtx.addOutput(addr, 50460);

    const tx = mtx.toTX();

    let balance = null;
    wallet.once('balance', (b) => {
      balance = b;
    });

    let receive = null;
    wallet.once('address', (r) => {
      receive = r[0];
    });

    let details = null;
    wallet.once('tx', (d) => {
      details = d;
    });

    await wdb.addTX(tx);
    await new Promise(r => setTimeout(r, 300));

    assert(receive);
    assert.strictEqual(receive.name, 'default');
    assert.strictEqual(receive.type, 'pubkeyhash');
    assert.strictEqual(receive.branch, 0);
    assert(balance);
    assert.strictEqual(balance.confirmed, 0);
    assert.strictEqual(balance.unconfirmed, 201840);
    assert(details);
    assert.strictEqual(details.hash, tx.txid());
  });

  it('should get balance', async () => {
    const balance = await wallet.getBalance();
    assert.strictEqual(balance.confirmed, 0);
    assert.strictEqual(balance.unconfirmed, 201840);
  });

  it('should send a tx', async () => {
    const options = {
      rate: 10000,
      outputs: [{
        value: 10000,
        address: addr.toString(node.network)
      }]
    };

    const tx = await wallet.send(options);

    assert(tx);
    assert.strictEqual(tx.inputs.length, 1);
    assert.strictEqual(tx.outputs.length, 2);

    let value = 0;
    value += tx.outputs[0].value;
    value += tx.outputs[1].value;

    assert.strictEqual(value, 48190);

    hash = tx.hash;
  });

  it('should get a tx', async () => {
    const tx = await wallet.getTX(hash);
    assert(tx);
    assert.strictEqual(tx.hash, hash);
  });

  it('should generate new api key', async () => {
    const old = wallet.token.toString('hex');
    const result = await wallet.retoken(null);
    assert.strictEqual(result.token.length, 64);
    assert.notStrictEqual(result.token, old);
  });

  it('should get balance', async () => {
    const balance = await wallet.getBalance();
    assert.strictEqual(balance.unconfirmed, 199570);
  });

  it('should execute an rpc call', async () => {
    const info = await nclient.execute('getblockchaininfo', []);
    assert.strictEqual(info.blocks, 0);
  });

  it('should execute an rpc call with bool parameter', async () => {
    const info = await nclient.execute('getrawmempool', [true]);
    assert.deepStrictEqual(info, {});
  });

  it('should create account', async () => {
    const info = await wallet.createAccount('foo1');
    assert(info);
    assert(info.initialized);
    assert.strictEqual(info.name, 'foo1');
    assert.strictEqual(info.accountIndex, 1);
    assert.strictEqual(info.m, 1);
    assert.strictEqual(info.n, 1);
  });

  it('should create account', async () => {
    const info = await wallet.createAccount('foo2', {
      type: 'multisig',
      m: 1,
      n: 2
    });
    assert(info);
    assert(!info.initialized);
    assert.strictEqual(info.name, 'foo2');
    assert.strictEqual(info.accountIndex, 2);
    assert.strictEqual(info.m, 1);
    assert.strictEqual(info.n, 2);
  });

  it('should get a block template', async () => {
    const json = await nclient.execute('getblocktemplate', [{
      rules: ['segwit']
    }]);
    assert.deepStrictEqual(json, {
      capabilities: ['proposal'],
      mutable: ['time', 'transactions', 'prevblock'],
      version: 536870912,
      rules: ['!segwit'],
      vbavailable: {},
      vbrequired: 0,
      height: 1,
      previousblockhash:
        '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
      target:
        '7fffff0000000000000000000000000000000000000000000000000000000000',
      bits: '207fffff',
      noncerange: '00000000ffffffff',
      curtime: json.curtime,
      mintime: 1296688603,
      maxtime: json.maxtime,
      expires: json.expires,
      sigoplimit: 80000,
      sizelimit: 4000000,
      weightlimit: 4000000,
      longpollid:
        '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
        + '00000000',
      submitold: false,
      coinbaseaux: { flags: '6d696e65642062792062636f696e' },
      coinbasevalue: 5000000000,
      transactions: [],
      default_witness_commitment:
        '6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48beb'
        + 'd836974e8cf9'
    });
  });

  it('should send a block template proposal', async () => {
    const attempt = await node.miner.createBlock();
    const block = attempt.toBlock();
    const hex = block.toRaw().toString('hex');
    const json = await nclient.execute('getblocktemplate', [{
      mode: 'proposal',
      data: hex
    }]);
    assert.strictEqual(json, null);
  });

  it('should validate an address', async () => {
    const json = await nclient.execute('validateaddress', [
      addr.toString(node.network)
    ]);
    assert.deepStrictEqual(json, {
      isvalid: true,
      address: addr.toString(node.network),
      scriptPubKey: Script.fromAddress(addr).toRaw().toString('hex'),
      ismine: false,
      iswatchonly: false
    });
  });

  it('should rpc createrawtransaction single pubkeyhash', async () => {
    const txhash='0e690d6655767c8b388e7403d13dc9ebe49b68e3bd46248c840544f9d' +
      'a87d1e8';
    const txindex=1;

    const address='RStiqGLWA3aSMrWDyJvur4287GQ81AtLh1';
    const amount=48.99900000;
    const sendTo = {};
    sendTo[address] = amount;

    rawtx = await nclient.execute('createrawtransaction',
      [[{ txid: txhash, vout: txindex }], sendTo]);

    assert(rawtx);
  });

  it('should rpc signrawtransaction single pubkeyhash', async () => {
    const txhash='0e690d6655767c8b388e7403d13dc9ebe49b68e3bd46248c840544f9d' +
      'a87d1e8';
    const txindex=1;
    const scriptPubKey='76a914af92ad98c7f77559f96430dfef2a6805b87b24f888ac';
    const amount=48.99900000;
    const privkey='ELvsQiH9X1kgmbzD1j4ESAJnN47whh8qZHVF8B9DpSpecKQDcfX6';

    const signedTx = await nclient.execute('signrawtransaction', [
      rawtx,
      [{txid: txhash,
      vout: txindex,
      scriptPubKey: scriptPubKey,
      amount: amount}],
      [privkey]
    ]);

    assert(signedTx);
  });

    it('should rpc createrawtransaction 2-in 2-out pubkeyhash', async () => {
    const txhash1='0e690d6655767c8b388e7403d13dc9ebe49b68e3bd46248c840544f9d' +
      'a87d1e8';
    const txindex1=1;

    const txhash2='4c7846a8ff8415945e96937dea27bdb3144c15d793648d72560278482' +
      '6052586';
    const txindex2=4;

    const address1='RStiqGLWA3aSMrWDyJvur4287GQ81AtLh1';
    const amount1=48.99900000;
    const address2='RBQUN7J1earPLbu97MyvG4zhW5b8RAQxoG';
    const amount2=2.00003219;
    const sendTo = {};
    sendTo[address1] = amount1;
    sendTo[address2] = amount2;

    rawtx = await nclient.execute('createrawtransaction',
      [[{ txid: txhash1, vout: txindex1 }, { txid: txhash2, vout: txindex2 }],
      sendTo]);

    assert(rawtx);
  });

  it('should rpc signrawtransaction 2-in 2-out pubkeyhash', async () => {
    const txhash1='0e690d6655767c8b388e7403d13dc9ebe49b68e3bd46248c840544f9d' +
      'a87d1e8';
    const txindex1=1;
    const scriptPubKey1='76a914af92ad98c7f77559f96430dfef2a6805b87b24f888ac';
    const amount1=48.99900000;
    const privkey1='ELvsQiH9X1kgmbzD1j4ESAJnN47whh8qZHVF8B9DpSpecKQDcfX6';

    const txhash2='4c7846a8ff8415945e96937dea27bdb3144c15d793648d72560278482' +
      '6052586';
    const txindex2=4;
    const scriptPubKey2='76a914af92ad98c7f77559f96430dfef2a6805b87b24f888ac';
    const amount2=2.00003219;
    const privkey2='EPni2gZW3WrTU9sKRL8j73cZEffujYwx81LSvpMATGYavC88QN63';

    const signedTx = await nclient.execute('signrawtransaction', [
      rawtx,
      [{txid: txhash1,
      vout: txindex1,
      scriptPubKey: scriptPubKey1,
      amount: amount1},
      {txid: txhash2,
      vout: txindex2,
      scriptPubKey: scriptPubKey2,
      amount: amount2}],
      [privkey1, privkey2]
    ]);

    assert(signedTx);
  });

  it('should rpc signrawtransaction multisig', async () => {
    const rawtx = '010000000001019d5cd0f2b5189d306a0767314d64ba50544c8ab95b' +
      'fff8cbfb6caa1776d36e9f0000000000ffffffff02c78aa90000000000160014df08' +
      'ffbdcf266c576625fc2e5bc960d26d5ab4f425675c29010000002200204953e1d15b' +
      'c70ad4b858ce5ca4b8e59190712a74673e797fa491fcc51d4cebe305000000006952' +
      '2102a890b6d96b73a2496de20515409a3d427183613af109a0a201e7c82635636fce' +
      '21030b4a5df576b3682a88834f29144f7256f7a426af1a466cf000ef20d0898b1b65' +
      '2103503326c3e4af1c9da528d35ded2f49c683fe63501ad0c3ae2fc9d0f7af9c8174' +
      '53ae00000000';
    const txid = '9f6ed37617aa6cfbcbf8ff5bb98a4c5450ba644d3167076a309d18b5f' +
      '2d05c9d';
    const vout = 0;
    const scriptPubKey = '00200729217ad1f3b1b26e9c55f3599fff0fdefe71cb0eea1' +
      '6f5f90178f431b0bab1';
    const redeemScript = '522102a890b6d96b73a2496de20515409a3d427183613af10' +
      '9a0a201e7c82635636fce21030b4a5df576b3682a88834f29144f7256f7a426af1a4' +
      '66cf000ef20d0898b1b652103503326c3e4af1c9da528d35ded2f49c683fe63501ad' +
      '0c3ae2fc9d0f7af9c817453ae';
    const amount = 50.00000000;
    const privkey1 = 'EN8AMggHTHVDZ31vtbBQ7DmbpmskBmHV49QduvxgvkCZFAvnZLGD';
    const privkey2 = 'ENG2xwvv93pgpwfyDoqCrzRtFzD4VJd2iQxd12X5G1sbosW1WyAp';
    const privkey3 = 'EKhNK9y96rehBXvj8MfgUznXTxPoHTKiNuV4TNnQiJjK4q7P5yLa';

    const result = await nclient.execute('signrawtransaction', [
      rawtx,
      [{txid: txid,
        vout: vout,
        scriptPubKey: scriptPubKey,
        redeemScript: redeemScript,
        amount: amount}],
      [privkey1, privkey2, privkey3]
    ]);

    assert(result['complete']);
  });

  it('should cleanup', async () => {
    consensus.COINBASE_MATURITY = 100;
    await wallet.close();
    await wclient.close();
    await nclient.close();
    await node.close();
  });
});

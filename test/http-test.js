/* eslint-env mocha */

'use strict';

const assert = require('assert');
const consensus = require('../lib/protocol/consensus');
const encoding = require('../lib/utils/encoding');
const co = require('../lib/utils/co');
const Address = require('../lib/primitives/address');
const Script = require('../lib/script/script');
const Outpoint = require('../lib/primitives/outpoint');
const MTX = require('../lib/primitives/mtx');
const HTTP = require('../lib/http');
const FullNode = require('../lib/node/fullnode');
const pkg = require('../lib/pkg');

describe('HTTP', function() {
  let addr, hash;

  const node = new FullNode({
    network: 'regtest',
    apiKey: 'foo',
    walletAuth: true,
    db: 'memory',
    plugins: [require('../lib/wallet/plugin')]
  });

  const wallet = new HTTP.Wallet({
    network: 'regtest',
    apiKey: 'foo'
  });

  const wdb = node.require('walletdb');

  this.timeout(15000);

  it('should open node', async () => {
    consensus.COINBASE_MATURITY = 0;
    await node.open();
  });

  it('should create wallet', async () => {
    const info = await wallet.create({ id: 'test' });
    assert.equal(info.id, 'test');
  });

  it('should get info', async () => {
    const info = await wallet.client.getInfo();
    assert.equal(info.network, node.network.type);
    assert.equal(info.version, pkg.version);
    assert.equal(info.pool.agent, node.pool.options.agent);
    assert.equal(typeof info.chain, 'object');
    assert.equal(info.chain.height, 0);
  });

  it('should get wallet info', async () => {
    const info = await wallet.getInfo();
    assert.equal(info.id, 'test');
    addr = info.account.receiveAddress;
    assert.equal(typeof addr, 'string');
    addr = Address.fromString(addr);
  });

  it('should fill with funds', async () => {
    let tx, balance, receive, details;

    // Coinbase
    tx = new MTX();
    tx.addOutpoint(new Outpoint(encoding.NULL_HASH, 0));
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx = tx.toTX();

    wallet.once('balance', (b) => {
      balance = b;
    });

    wallet.once('address', (r) => {
      receive = r[0];
    });

    wallet.once('tx', (d) => {
      details = d;
    });

    await wdb.addTX(tx);
    await co.timeout(300);

    assert(receive);
    assert.equal(receive.id, 'test');
    assert.equal(receive.type, 'pubkeyhash');
    assert.equal(receive.branch, 0);
    assert(balance);
    assert.equal(balance.confirmed, 0);
    assert.equal(balance.unconfirmed, 201840);
    assert(details);
    assert.equal(details.hash, tx.rhash());
  });

  it('should get balance', async () => {
    const balance = await wallet.getBalance();
    assert.equal(balance.confirmed, 0);
    assert.equal(balance.unconfirmed, 201840);
  });

  it('should send a tx', async () => {
    let value = 0;

    const options = {
      rate: 10000,
      outputs: [{
        value: 10000,
        address: addr.toString()
      }]
    };

    const tx = await wallet.send(options);

    assert(tx);
    assert.equal(tx.inputs.length, 1);
    assert.equal(tx.outputs.length, 2);

    value += tx.outputs[0].value;
    value += tx.outputs[1].value;
    assert.equal(value, 48190);

    hash = tx.hash;
  });

  it('should get a tx', async () => {
    const tx = await wallet.getTX(hash);
    assert(tx);
    assert.equal(tx.hash, hash);
  });

  it('should generate new api key', async () => {
    const t = wallet.token.toString('hex');
    const token = await wallet.retoken(null);
    assert(token.length === 64);
    assert.notEqual(token, t);
  });

  it('should get balance', async () => {
    const balance = await wallet.getBalance();
    assert.equal(balance.unconfirmed, 199570);
  });

  it('should execute an rpc call', async () => {
    const info = await wallet.client.rpc.execute('getblockchaininfo', []);
    assert.equal(info.blocks, 0);
  });

  it('should execute an rpc call with bool parameter', async () => {
    const info = await wallet.client.rpc.execute('getrawmempool', [true]);
    assert.deepStrictEqual(info, {});
  });

  it('should create account', async () => {
    const info = await wallet.createAccount('foo1');
    assert(info);
    assert(info.initialized);
    assert.equal(info.name, 'foo1');
    assert.equal(info.accountIndex, 1);
    assert.equal(info.m, 1);
    assert.equal(info.n, 1);
  });

  it('should create account', async () => {
    const info = await wallet.createAccount('foo2', {
      type: 'multisig',
      m: 1,
      n: 2
    });
    assert(info);
    assert(!info.initialized);
    assert.equal(info.name, 'foo2');
    assert.equal(info.accountIndex, 2);
    assert.equal(info.m, 1);
    assert.equal(info.n, 2);
  });

  it('should get a block template', async () => {
    const json = await wallet.client.rpc.execute('getblocktemplate', []);
    assert.deepStrictEqual(json, {
      capabilities: [ 'proposal' ],
      mutable: [ 'time', 'transactions', 'prevblock' ],
      version: 536870912,
      rules: [],
      vbavailable: {},
      vbrequired: 0,
      height: 1,
      previousblockhash: '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
      target: '7fffff0000000000000000000000000000000000000000000000000000000000',
      bits: '207fffff',
      noncerange: '00000000ffffffff',
      curtime: json.curtime,
      mintime: 1296688603,
      maxtime: json.maxtime,
      expires: json.expires,
      sigoplimit: 20000,
      sizelimit: 1000000,
      longpollid: '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e22060000000000',
      submitold: false,
      coinbaseaux: { flags: '6d696e65642062792062636f696e' },
      coinbasevalue: 5000000000,
      transactions: []
    });
  });

  it('should send a block template proposal', async () => {
    const attempt = await node.miner.createBlock();
    const block = attempt.toBlock();
    const hex = block.toRaw().toString('hex');
    const json = await wallet.client.rpc.execute('getblocktemplate', [{
      mode: 'proposal',
      data: hex
    }]);
    assert.strictEqual(json, null);
  });

  it('should validate an address', async () => {
    const json = await wallet.client.rpc.execute('validateaddress', [addr.toString()]);
    assert.deepStrictEqual(json, {
      isvalid: true,
      address: addr.toString(),
      scriptPubKey: Script.fromAddress(addr).toRaw().toString('hex'),
      ismine: false,
      iswatchonly: false
    });
  });

  it('should cleanup', async () => {
    consensus.COINBASE_MATURITY = 100;
    await wallet.close();
    await node.close();
  });
});

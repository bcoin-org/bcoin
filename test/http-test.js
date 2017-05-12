'use strict';

var assert = require('assert');
var consensus = require('../lib/protocol/consensus');
var encoding = require('../lib/utils/encoding');
var co = require('../lib/utils/co');
var Amount = require('../lib/btc/amount');
var Address = require('../lib/primitives/address');
var Script = require('../lib/script/script');
var Outpoint = require('../lib/primitives/outpoint');
var MTX = require('../lib/primitives/mtx');
var HTTP = require('../lib/http');
var FullNode = require('../lib/node/fullnode');
var pkg = require('../lib/pkg');
var plugin = require('../lib/wallet/plugin');

describe('HTTP', function() {
  var node, wallet, walletdb, addr, hash;

  node = new FullNode({
    network: 'regtest',
    apiKey: 'foo',
    walletAuth: true,
    db: 'memory'
  });

  wallet = new HTTP.Wallet({
    network: 'regtest',
    apiKey: 'foo'
  });

  walletdb = node.use(plugin);

  node.on('error', function() {});

  this.timeout(15000);

  it('should open node', co(function* () {
    consensus.COINBASE_MATURITY = 0;
    yield node.open();
  }));

  it('should create wallet', co(function* () {
    var info = yield wallet.create({ id: 'test' });
    assert.equal(info.id, 'test');
  }));

  it('should get info', co(function* () {
    var info = yield wallet.client.getInfo();
    assert.equal(info.network, node.network.type);
    assert.equal(info.version, pkg.version);
    assert.equal(info.pool.agent, node.pool.options.agent);
    assert.equal(typeof info.chain, 'object');
    assert.equal(info.chain.height, 0);
  }));

  it('should get wallet info', co(function* () {
    var info = yield wallet.getInfo();
    assert.equal(info.id, 'test');
    addr = info.account.receiveAddress;
    assert.equal(typeof addr, 'string');
    addr = Address.fromString(addr);
  }));

  it('should fill with funds', co(function* () {
    var tx, balance, receive, details;

    // Coinbase
    tx = new MTX();
    tx.addOutpoint(new Outpoint(encoding.NULL_HASH, 0));
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx.addOutput(addr, 50460);
    tx = tx.toTX();

    wallet.once('balance', function(b) {
      balance = b;
    });

    wallet.once('address', function(r) {
      receive = r[0];
    });

    wallet.once('tx', function(d) {
      details = d;
    });

    yield walletdb.addTX(tx);
    yield co.timeout(300);

    assert(receive);
    assert.equal(receive.id, 'test');
    assert.equal(receive.type, 'pubkeyhash');
    assert.equal(receive.branch, 0);
    assert(balance);
    assert.equal(Amount.value(balance.confirmed), 0);
    assert.equal(Amount.value(balance.unconfirmed), 201840);
    assert(details);
    assert.equal(details.hash, tx.rhash());
  }));

  it('should get balance', co(function* () {
    var balance = yield wallet.getBalance();
    assert.equal(Amount.value(balance.confirmed), 0);
    assert.equal(Amount.value(balance.unconfirmed), 201840);
  }));

  it('should send a tx', co(function* () {
    var value = 0;
    var options, tx;

    options = {
      rate: 10000,
      outputs: [{
        value: 10000,
        address: addr.toString()
      }]
    };

    tx = yield wallet.send(options);

    assert(tx);
    assert.equal(tx.inputs.length, 1);
    assert.equal(tx.outputs.length, 2);

    value += Amount.value(tx.outputs[0].value);
    value += Amount.value(tx.outputs[1].value);
    assert.equal(value, 48190);

    hash = tx.hash;
  }));

  it('should get a tx', co(function* () {
    var tx = yield wallet.getTX(hash);
    assert(tx);
    assert.equal(tx.hash, hash);
  }));

  it('should generate new api key', co(function* () {
    var t = wallet.token.toString('hex');
    var token = yield wallet.retoken(null);
    assert(token.length === 64);
    assert.notEqual(token, t);
  }));

  it('should get balance', co(function* () {
    var balance = yield wallet.getBalance();
    assert.equal(Amount.value(balance.unconfirmed), 199570);
  }));

  it('should execute an rpc call', co(function* () {
    var info = yield wallet.client.rpc.execute('getblockchaininfo', []);
    assert.equal(info.blocks, 0);
  }));

  it('should execute an rpc call with bool parameter', co(function* () {
    var info = yield wallet.client.rpc.execute('getrawmempool', [true]);
    assert.deepStrictEqual(info, {});
  }));

  it('should create account', co(function* () {
    var info = yield wallet.createAccount('foo1');
    assert(info);
    assert(info.initialized);
    assert.equal(info.name, 'foo1');
    assert.equal(info.accountIndex, 1);
    assert.equal(info.m, 1);
    assert.equal(info.n, 1);
  }));

  it('should create account', co(function* () {
    var info = yield wallet.createAccount('foo2', {
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
  }));

  it('should get a block template', co(function* () {
    var json = yield wallet.client.rpc.execute('getblocktemplate', []);
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
  }));

  it('should send a block template proposal', co(function* () {
    var attempt = yield node.miner.createBlock();
    var block = attempt.toBlock();
    var hex = block.toRaw().toString('hex');
    var json = yield wallet.client.rpc.execute('getblocktemplate', [{
      mode: 'proposal',
      data: hex
    }]);
    assert.strictEqual(json, null);
  }));

  it('should validate an address', co(function* () {
    var json = yield wallet.client.rpc.execute('validateaddress', [addr.toString()]);
    assert.deepStrictEqual(json, {
       isvalid: true,
       address: addr.toString(),
       scriptPubKey: Script.fromAddress(addr).toRaw().toString('hex'),
       ismine: false,
       iswatchonly: false
     });
  }));

  it('should cleanup', co(function* () {
    consensus.COINBASE_MATURITY = 100;
    yield wallet.close();
    yield node.close();
  }));
});

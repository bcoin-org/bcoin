'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var network = bcoin.networks;
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var co = require('../lib/utils/co');
var Amount = require('../lib/btc/amount');
var cob = co.cob;

var dummyInput = {
  prevout: {
    hash: constants.NULL_HASH,
    index: 0
  },
  coin: {
    version: 1,
    height: 0,
    value: constants.MAX_MONEY,
    script: new bcoin.script([]),
    coinbase: false,
    hash: constants.NULL_HASH,
    index: 0
  },
  script: new bcoin.script([]),
  witness: new bcoin.witness([]),
  sequence: 0xffffffff
};

describe('HTTP', function() {
  var request = bcoin.http.request;
  var w, addr, hash;

  this.timeout(15000);

  var node = new bcoin.fullnode({
    network: 'regtest',
    apiKey: 'foo',
    walletAuth: true,
    db: 'memory'
  });

  var wallet = new bcoin.http.Wallet({
    network: 'regtest',
    apiKey: 'foo'
  });

  node.on('error', function() {});

  it('should open node', cob(function* () {
    constants.tx.COINBASE_MATURITY = 0;
    yield node.open();
  }));

  it('should create wallet', cob(function* () {
    var info = yield wallet.create({ id: 'test' });
    assert.equal(info.id, 'test');
  }));

  it('should get info', cob(function* () {
    var info = yield wallet.client.getInfo();
    assert.equal(info.network, node.network.type);
    assert.equal(info.version, constants.USER_VERSION);
    assert.equal(info.agent, constants.USER_AGENT);
    assert.equal(info.height, 0);
  }));

  it('should get wallet info', cob(function* () {
    var info = yield wallet.getInfo();
    assert.equal(info.id, 'test');
    addr = info.account.receiveAddress;
    assert.equal(typeof addr, 'string');
  }));

  it('should fill with funds', cob(function* () {
    var balance, receive, details;

    // Coinbase
    var t1 = bcoin.mtx()
      .addOutput(addr, 50460)
      .addOutput(addr, 50460)
      .addOutput(addr, 50460)
      .addOutput(addr, 50460);

    t1.addInput(dummyInput);
    t1 = t1.toTX();

    wallet.once('balance', function(b) {
      balance = b;
    });

    wallet.once('address', function(r) {
      receive = r[0];
    });

    wallet.once('tx', function(d) {
      details = d;
    });

    yield node.walletdb.addTX(t1);
    yield co.timeout(300);

    assert(receive);
    assert.equal(receive.id, 'test');
    assert.equal(receive.type, 'pubkeyhash');
    assert.equal(receive.branch, 0);
    assert(balance);
    assert.equal(Amount.value(balance.confirmed), 0);
    assert.equal(Amount.value(balance.unconfirmed), 201840);
    assert(details);
    assert.equal(details.hash, t1.rhash);
  }));

  it('should get balance', cob(function* () {
    var balance = yield wallet.getBalance();
    assert.equal(Amount.value(balance.confirmed), 0);
    assert.equal(Amount.value(balance.unconfirmed), 201840);
  }));

  it('should send a tx', cob(function* () {
    var value = 0;
    var options, tx;

    options = {
      rate: 10000,
      outputs: [{
        value: 10000,
        address: addr
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

  it('should get a tx', cob(function* () {
    var tx = yield wallet.getTX(hash);
    assert(tx);
    assert.equal(tx.hash, hash);
  }));

  it('should generate new api key', cob(function* () {
    var t = wallet.token.toString('hex');
    var token = yield wallet.retoken(null);
    assert(token.length === 64);
    assert.notEqual(token, t);
  }));

  it('should get balance', cob(function* () {
    var balance = yield wallet.getBalance();
    assert.equal(Amount.value(balance.unconfirmed), 199570);
  }));

  it('should execute an rpc call', cob(function* () {
    var info = yield wallet.client.rpc.call('getblockchaininfo', []);
    assert.equal(info.blocks, 0);
  }));

  it('should cleanup', cob(function* () {
    constants.tx.COINBASE_MATURITY = 100;
    yield wallet.close();
    yield node.close();
  }));
});

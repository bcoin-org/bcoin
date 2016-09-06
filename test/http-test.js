'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var network = bcoin.networks;
var utils = bcoin.utils;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var scriptTypes = constants.scriptTypes;

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

  var wallet = new bcoin.http.wallet({
    network: 'regtest',
    apiKey: 'foo'
  });

  node.on('error', function() {});

  it('should open node', function(cb) {
    constants.tx.COINBASE_MATURITY = 0;
    node.open(cb);
  });

  it('should create wallet', function(cb) {
    wallet.create({ id: 'test' }, function(err, wallet) {
      assert.ifError(err);
      assert.equal(wallet.id, 'test');
      cb();
    });
  });

  it('should get info', function(cb) {
    wallet.client.getInfo(function(err, info) {
      assert.ifError(err);
      assert.equal(info.network, node.network.type);
      assert.equal(info.version, constants.USER_VERSION);
      assert.equal(info.agent, constants.USER_AGENT);
      assert.equal(info.height, 0);
      cb();
    });
  });

  it('should get wallet info', function(cb) {
    wallet.getInfo(function(err, wallet) {
      assert.ifError(err);
      assert.equal(wallet.id, 'test');
      addr = wallet.account.receiveAddress;
      assert.equal(typeof addr, 'string');
      cb();
    });
  });

  it('should fill with funds', function(cb) {
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

    node.walletdb.addTX(t1, function(err) {
      assert.ifError(err);
      setTimeout(function() {
        assert(receive);
        assert.equal(receive.id, 'test');
        assert.equal(receive.type, 'pubkeyhash');
        assert.equal(receive.change, 0);
        assert(balance);
        assert.equal(utils.satoshi(balance.confirmed), 0);
        assert.equal(utils.satoshi(balance.unconfirmed), 201840);
        assert.equal(utils.satoshi(balance.total), 201840);
        assert(details);
        assert.equal(details.hash, t1.rhash);
        cb();
      }, 300);
    });
  });

  it('should get balance', function(cb) {
    wallet.getBalance(function(err, balance) {
      assert.ifError(err);
      assert.equal(utils.satoshi(balance.confirmed), 0);
      assert.equal(utils.satoshi(balance.unconfirmed), 201840);
      assert.equal(utils.satoshi(balance.total), 201840);
      cb();
    });
  });

  it('should send a tx', function(cb) {
    var options = {
      rate: 10000,
      outputs: [{
        value: 10000,
        address: addr
      }]
    };

    wallet.send(options, function(err, tx) {
      assert.ifError(err);
      assert(tx);
      assert.equal(tx.inputs.length, 1);
      assert.equal(tx.outputs.length, 2);
      assert.equal(utils.satoshi(tx.outputs[0].value) + utils.satoshi(tx.outputs[1].value), 48190);
      hash = tx.hash;
      cb();
    });
  });

  it('should get a tx', function(cb) {
    wallet.getTX(hash, function(err, tx) {
      assert.ifError(err);
      assert(tx);
      assert.equal(tx.hash, hash);
      cb();
    });
  });

  it('should generate new api key', function(cb) {
    var t = wallet.token.toString('hex');
    wallet.retoken(null, function(err, token) {
      assert.ifError(err);
      assert(token.length === 64);
      assert.notEqual(token, t);
      cb();
    });
  });

  it('should get balance', function(cb) {
    wallet.getBalance(function(err, balance) {
      assert.ifError(err);
      assert.equal(utils.satoshi(balance.total), 199570);
      cb();
    });
  });

  it('should cleanup', function(cb) {
    constants.tx.COINBASE_MATURITY = 100;
    wallet.close();
    node.close(cb);
  });
});

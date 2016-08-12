'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var bench = require('./bench');

var dummyInput = {
  prevout: {
    hash: constants.NULL_HASH,
    index: 0
  },
  coin: {
    version: 1,
    height: 0,
    value: 50460 * 4,
    script: new bcoin.script([]),
    coinbase: false,
    hash: constants.NULL_HASH,
    index: 0
  },
  script: new bcoin.script([]),
  witness: new bcoin.witness([]),
  sequence: 0xffffffff
};

var walletdb = new bcoin.walletdb({
  name: 'wallet-test',
  // location: __dirname + '/../walletdb-bench',
  // db: 'leveldb'
  db: 'memory'
});
var wallet;
var addrs = [];

function runBench(callback) {
  utils.serial([
    function(next) {
      walletdb.create(function(err, w) {
        assert.ifError(err);
        wallet = w;
        next();
      });
    },
    function(next) {
      var end = bench('accounts');
      utils.forRange(0, 1000, function(i, next) {
        wallet.createAccount({}, function(err, account) {
          assert.ifError(err);
          addrs.push(account.receiveAddress.getAddress());
          next();
        });
      }, function(err) {
        assert.ifError(err);
        end(1000);
        next();
      });
    },
    function(next) {
      var end = bench('addrs');
      utils.forRange(0, 1000, function(i, next) {
        utils.forRange(0, 10, function(j, next) {
          wallet.createReceive(i, function(err, addr) {
            assert.ifError(err);
            addrs.push(addr);
            next();
          });
        }, next);
      }, function(err) {
        assert.ifError(err);
        end(1000 * 10);
        next();
      });
    },
    function(next) {
      var nonce = new bn(0);
      var end;
      utils.forRange(0, 10000, function(i, next) {
        var t1 = bcoin.mtx()
          .addOutput(addrs[(i + 0) % addrs.length], 50460)
          .addOutput(addrs[(i + 1) % addrs.length], 50460)
          .addOutput(addrs[(i + 2) % addrs.length], 50460)
          .addOutput(addrs[(i + 3) % addrs.length], 50460);

        t1.addInput(dummyInput);
        nonce.addn(1);
        t1.inputs[0].script.set(0, nonce);
        t1.inputs[0].script.compile();

        walletdb.addTX(t1.toTX(), function(err) {
          assert.ifError(err);
          next();
        });
      }, function(err) {
        assert.ifError(err);
        end(10000);
        next();
      });
      end = bench('tx');
    },
    function(next) {
      var end = bench('balance');
      wallet.getBalance(function(err, balance) {
        assert.ifError(err);
        end(1);
        next();
      });
    },
    function(next) {
      var end = bench('coins');
      wallet.getCoins(function(err) {
        assert.ifError(err);
        end(1);
        next();
      });
    },
    function(next) {
      var end = bench('create');
      var options = {
        rate: 10000,
        outputs: [{
          value: 50460,
          address: addrs[0]
        }]
      };
      wallet.createTX(options, function(err) {
        assert.ifError(err);
        end(1);
        next();
      });
    }
  ], function(err) {
    assert.ifError(err);
    callback();
  });
}

walletdb.open(function(err) {
  assert.ifError(err);
  runBench(function(err) {
    assert.ifError(err);
    process.exit(0);
  });
});

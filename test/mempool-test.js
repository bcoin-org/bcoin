var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = require('assert');
var opcodes = constants.opcodes;

describe('Mempool', function() {
  this.timeout(5000);

  var chain = new bcoin.chain({
    name: 'mp-chain',
    db: 'memory'
  });

  var mempool = new bcoin.mempool({
    chain: chain,
    name: 'mempool-test',
    db: 'memory'
  });

  mempool.on('error', function() {});

  it('should open mempool', function(cb) {
    mempool.open(cb);
  });

  it('should handle incoming orphans and TXs', function(cb) {
    var w = new bcoin.wallet();

    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([w.publicKey, opcodes.OP_CHECKSIG]);
    var dummyInput = {
      prevout: {
        hash: constants.ONE_HASH.toString('hex'),
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: new bn(70000),
        script: prev,
        coinbase: false,
        hash: constants.ONE_HASH.toString('hex'),
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    t1.inputs[0].script = new bcoin.script([t1.createSignature(0, prev, w.privateKey, 'all', 0)]),

    // balance: 51000
    w.sign(t1);
    var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                       .addOutput(w, 20000)
                       .addOutput(w, 20000);
    // balance: 49000
    w.sign(t2);
    var t3 = bcoin.mtx().addInput(t1, 1) // 10000
                       .addInput(t2, 0) // 20000
                       .addOutput(w, 23000);
    // balance: 47000
    w.sign(t3);
    var t4 = bcoin.mtx().addInput(t2, 1) // 24000
                       .addInput(t3, 0) // 23000
                       .addOutput(w, 11000)
                       .addOutput(w, 11000);
    // balance: 22000
    w.sign(t4);
    var f1 = bcoin.mtx().addInput(t4, 1) // 11000
                       .addOutput(new bcoin.wallet(), 9000);
    // balance: 11000
    w.sign(f1);
    var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                         .addOutput(w, 6000); // 6000 instead of 500
    // Script inputs but do not sign
    w.scriptInputs(fake);
    // Fake signature
    fake.inputs[0].script.code[0] = new Buffer([0,0,0,0,0,0,0,0,0]);
    // balance: 11000
    [t2, t3, t4, f1, fake].forEach(function(tx) {
      tx.inputs.forEach(function(input) {
        delete input.coin;
      });
    });

    // Just for debugging
    t1.hint = 't1';
    t2.hint = 't2';
    t3.hint = 't3';
    t4.hint = 't4';
    f1.hint = 'f1';
    fake.hint = 'fake';

    mempool.addTX(fake, function(err) {
      assert.ifError(err);
      mempool.addTX(t4, function(err) {
        assert.ifError(err);
        mempool.getBalance(function(err, balance) {
          assert.ifError(err);
          assert.equal(balance.total.toString(10), '0');
          mempool.addTX(t1, function(err) {
            assert.ifError(err);
            mempool.getBalance(function(err, balance) {
              assert.ifError(err);
              assert.equal(balance.total.toString(10), '60000');
              mempool.addTX(t2, function(err) {
                assert.ifError(err);
                mempool.getBalance(function(err, balance) {
                  assert.ifError(err);
                  assert.equal(balance.total.toString(10), '50000');
                  mempool.addTX(t3, function(err) {
                    assert.ifError(err);
                    mempool.getBalance(function(err, balance) {
                      assert.ifError(err);
                      assert.equal(balance.total.toString(10), '22000');
                      mempool.addTX(f1, function(err) {
                        assert.ifError(err);
                        mempool.getBalance(function(err, balance) {
                          assert.ifError(err);
                          assert.equal(balance.total.toString(10), '20000');
                          mempool.getHistory(function(err, txs) {
                            assert(txs.some(function(tx) {
                              return tx.hash('hex') === f1.hash('hex');
                            }));

                            cb();
                          });
                        });
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  it('should destroy mempool', function(cb) {
    mempool.close(cb);
  });
});

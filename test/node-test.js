var bn = require('bn.js');
var bcoin = require('../');
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = utils.assert;
var opcodes = constants.opcodes;

describe('Wallet', function() {
  process.env.BCOIN_DB = 'memdown';
  var node = new bcoin.fullnode();
  node.on('error', function() {});

  it('should open node', function(cb) {
    node.open(cb);
  });

  it('should have wallet', function(cb) {
    delete process.env.BCOIN_DB;
    node.getWallet('primary', function(err, wallet) {
      if (err)
        return cb(err);

      node.wallet = wallet;

      cb();
    });
  });

  it('should have TX pool and be serializable', function(cb) {
    var w = node.wallet;

    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([w.publicKey, opcodes.OP_CHECKSIG]);
    var dummyInput = {
      prevout: {
        hash: constants.oneHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: new bn(70000),
        script: prev,
        coinbase: false,
        hash: constants.oneHash,
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

    var peer = { sendReject: function() {} };

    node.mempool.addTX(fake, peer, function(err) {
      assert.noError(err);
      node.mempool.addTX(t4, peer, function(err) {
        assert.noError(err);
        node.mempool.getBalance(function(err, balance) {
          assert.noError(err);
          assert.equal(balance.toString(10), '0');
          node.mempool.addTX(t1, peer, function(err) {
            assert.noError(err);
            node.mempool.getBalance(function(err, balance) {
              assert.noError(err);
              assert.equal(balance.toString(10), '60000');
              node.mempool.addTX(t2, peer, function(err) {
                assert.noError(err);
                node.mempool.getBalance(function(err, balance) {
                  assert.noError(err);
                  assert.equal(balance.toString(10), '50000');
                  node.mempool.addTX(t3, peer, function(err) {
                    assert.noError(err);
                    node.mempool.getBalance(function(err, balance) {
                      assert.noError(err);
                      assert.equal(balance.toString(10), '22000');
                      node.mempool.addTX(f1, peer, function(err) {
                        assert.noError(err);
                        node.mempool.getBalance(function(err, balance) {
                          assert.noError(err);
                          assert.equal(balance.toString(10), '20000');
                          node.mempool.getAll(function(err, txs) {
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

  it('should destroy pool', function(cb) {
    node.close(cb);
  });
});

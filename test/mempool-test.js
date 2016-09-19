'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var utils = bcoin.utils;
var crypto = require('../lib/crypto/crypto');
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

  var walletdb = new bcoin.walletdb({
    name: 'mempool-wallet-test',
    db: 'memory',
    verify: true
  });

  var w, cached;

  mempool.on('error', function() {});

  it('should open mempool', function(cb) {
    mempool.open(function(err) {
      assert.ifError(err);
      chain.state.flags |= constants.flags.VERIFY_WITNESS;
      cb();
    });
  });

  it('should open walletdb', function(cb) {
    walletdb.open(cb);
  });

  it('should open wallet', function(cb) {
    walletdb.create({}, function(err, wallet) {
      assert.ifError(err);
      w = wallet;
      cb();
    });
  });

  it('should handle incoming orphans and TXs', function(cb) {
    var kp = bcoin.keyring.generate();
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    var dummyInput = {
      prevout: {
        hash: constants.ONE_HASH.toString('hex'),
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: constants.ONE_HASH.toString('hex'),
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    t1.inputs[0].script = new bcoin.script([t1.signature(0, prev, kp.privateKey, 'all', 0)]),

    // balance: 51000
    w.sign(t1, function(err, total) {
      assert.ifError(err);
      t1 = t1.toTX();
      var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                         .addOutput(w, 20000)
                         .addOutput(w, 20000);
      // balance: 49000
      w.sign(t2, function(err, total) {
        assert.ifError(err);
        t2 = t2.toTX();
        var t3 = bcoin.mtx().addInput(t1, 1) // 10000
                           .addInput(t2, 0) // 20000
                           .addOutput(w, 23000);
        // balance: 47000
        w.sign(t3, function(err, total) {
          assert.ifError(err);
          t3 = t3.toTX();
          var t4 = bcoin.mtx().addInput(t2, 1) // 24000
                             .addInput(t3, 0) // 23000
                             .addOutput(w, 11000)
                             .addOutput(w, 11000);
          // balance: 22000
          w.sign(t4, function(err, total) {
            assert.ifError(err);
            t4 = t4.toTX();
            var f1 = bcoin.mtx().addInput(t4, 1) // 11000
                               .addOutput(bcoin.address.fromData(new Buffer([])).toBase58(), 9000);
            // balance: 11000
            w.sign(f1, function(err, total) {
              assert.ifError(err);
              f1 = f1.toTX();
              var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                                   .addOutput(w, 6000); // 6000 instead of 500
              // Script inputs but do not sign
              w.template(fake, function(err) {
                assert.ifError(err);
                // Fake signature
                fake.inputs[0].script.set(0, new Buffer([0,0,0,0,0,0,0,0,0]));
                fake.inputs[0].script.compile();
                fake = fake.toTX();
                // balance: 11000
                [t2, t3, t4, f1, fake].forEach(function(tx) {
                  tx.inputs.forEach(function(input) {
                    delete input.coin;
                  });
                });

                mempool.addTX(fake, function(err) {
                  assert.ifError(err);
                  mempool.addTX(t4, function(err) {
                    assert.ifError(err);
                    var balance = mempool.getBalance();
                    assert.equal(balance, 0);
                    mempool.addTX(t1, function(err) {
                      assert.ifError(err);
                      var balance = mempool.getBalance();
                      assert.equal(balance, 60000);
                      mempool.addTX(t2, function(err) {
                        assert.ifError(err);
                        var balance = mempool.getBalance();
                        assert.equal(balance, 50000);
                        mempool.addTX(t3, function(err) {
                          assert.ifError(err);
                          var balance = mempool.getBalance();
                          assert.equal(balance, 22000);
                          mempool.addTX(f1, function(err) {
                            assert.ifError(err);
                            var balance = mempool.getBalance();
                            assert.equal(balance, 20000);
                            var txs = mempool.getHistory();
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

  it('should handle locktime', function(cb) {
    var kp = bcoin.keyring.generate();
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    t1.setLocktime(200);
    chain.tip.height = 200;
    t1.inputs[0].script = new bcoin.script([t1.signature(0, prev, kp.privateKey, 'all', 0)]),
    t1 = t1.toTX();
    mempool.addTX(t1, function(err) {
      chain.tip.height = 0;
      assert.ifError(err);
      cb();
    });
  });

  it('should handle invalid locktime', function(cb) {
    var kp = bcoin.keyring.generate();
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    t1.setLocktime(200);
    chain.tip.height = 200 - 1;
    t1.inputs[0].script = new bcoin.script([t1.signature(0, prev, kp.privateKey, 'all', 0)]),
    t1 = t1.toTX();
    mempool.addTX(t1, function(err) {
      chain.tip.height = 0;
      assert(err);
      cb();
    });
  });

  it('should not cache a malleated wtx with mutated sig', function(cb) {
    var kp = bcoin.keyring.generate();
    kp.witness = true;
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([0, kp.keyHash]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    var prevs = bcoin.script.fromPubkeyhash(kp.keyHash);
    var sig = new bcoin.witness([t1.signature(0, prevs, kp.privateKey, 'all', 1), kp.publicKey]);
    var sig2 = new bcoin.witness([t1.signature(0, prevs, kp.privateKey, 'all', 1), kp.publicKey]);
    sig2.items[0][sig2.items[0].length - 1] = 0;
    t1.inputs[0].witness = sig2;
    var tx = t1.toTX();
    mempool.addTX(tx, function(err) {
      assert(err);
      assert(!mempool.hasReject(tx.hash()));
      cb();
    });
  });

  it('should not cache a malleated tx with unnecessary witness', function(cb) {
    var kp = bcoin.keyring.generate();
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    t1.inputs[0].script = new bcoin.script([t1.signature(0, prev, kp.privateKey, 'all', 0)]),
    t1.inputs[0].witness.push(new Buffer(0));
    var tx = t1.toTX();
    mempool.addTX(tx, function(err) {
      assert(err);
      assert(!mempool.hasReject(tx.hash()));
      cb();
    });
  });

  it('should not cache a malleated wtx with wit removed', function(cb) {
    var kp = bcoin.keyring.generate();
    kp.witness = true;
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([0, kp.keyHash]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    var tx = t1.toTX();
    mempool.addTX(tx, function(err) {
      assert(err);
      assert(err.malleated);
      assert(!mempool.hasReject(tx.hash()));
      cb();
    });
  });

  it('should cache non-malleated tx without sig', function(cb) {
    var kp = bcoin.keyring.generate();
    // Coinbase
    var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 10000); // 10000 instead of 1000
    var prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    var prevHash = crypto.randomBytes(32).toString('hex');
    var dummyInput = {
      prevout: {
        hash: prevHash,
        index: 0
      },
      coin: {
        version: 1,
        height: 0,
        value: 70000,
        script: prev,
        coinbase: false,
        hash: prevHash,
        index: 0
      },
      script: new bcoin.script([]),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    var tx = t1.toTX();
    mempool.addTX(tx, function(err) {
      assert(err);
      assert(!err.malleated);
      assert(mempool.hasReject(tx.hash()));
      cached = tx;
      cb();
    });
  });

  it('should clear reject cache', function(cb) {
    var t1 = bcoin.mtx().addOutput(w, 50000);
    var dummyInput = {
      prevout: {
        hash: constants.NULL_HASH,
        index: 0xffffffff
      },
      coin: null,
      script: new bcoin.script(),
      sequence: 0xffffffff
    };
    t1.addInput(dummyInput);
    var tx = t1.toTX();
    var block = new bcoin.block();
    block.txs.push(tx);
    assert(mempool.hasReject(cached.hash()));
    mempool.addBlock(block, function(err) {
      assert(!err);
      assert(!mempool.hasReject(cached.hash()));
      cb();
    });
  });

  it('should destroy mempool', function(cb) {
    mempool.close(cb);
  });
});

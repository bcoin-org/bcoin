var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = require('assert');

var KEY1 = 'xprv9s21ZrQH143K3Aj6xQBymM31Zb4BVc7wxqfUhMZrzewdDVCt'
  + 'qUP9iWfcHgJofs25xbaUpCps9GDXj83NiWvQCAkWQhVj5J4CorfnpKX94AZ';

KEY1 = { xprivkey: KEY1 };

var KEY2 = 'xprv9s21ZrQH143K3mqiSThzPtWAabQ22Pjp3uSNnZ53A5bQ4udp'
  + 'faKekc2m4AChLYH1XDzANhrSdxHYWUeTWjYJwFwWFyHkTMnMeAcW4JyRCZa';

KEY2 = { xprivkey: KEY2 };

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

assert.range = function range(value, lo, hi, message) {
  if (!(value >= lo && value <= hi)) {
    throw new assert.AssertionError({
      message: message,
      actual: value,
      expected: lo + ', ' + hi,
      operator: '>= && <=',
      stackStartFunction: range
    });
  }
};

describe('Wallet', function() {
  var wdb = new bcoin.walletdb({
    name: 'wallet-test',
    db: 'memory',
    verify: true
  });

  it('should open walletdb', function(cb) {
    constants.tx.COINBASE_MATURITY = 0;
    wdb.open(cb);
  });

  it('should generate new key and address', function() {
    var w = bcoin.wallet();
    w.init(function(err) {
      assert.ifError(err);
      var addr = w.getAddress();
      assert(addr);
      assert(bcoin.address.validate(addr));
    });
  });

  it('should validate existing address', function() {
    assert(bcoin.address.validate('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert(!bcoin.address.validate('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc'));
  });

  function p2pkh(witness, bullshitNesting, cb) {
    var flags = bcoin.protocol.constants.flags.STANDARD_VERIFY_FLAGS;

    if (witness)
      flags |= bcoin.protocol.constants.flags.VERIFY_WITNESS;

    wdb.create({ witness: witness }, function(err, w) {
      assert.ifError(err);

      if (witness)
        assert(bcoin.address.parseBase58(w.getAddress()).type === 'witnesspubkeyhash');
      else
        assert(bcoin.address.parseBase58(w.getAddress()).type === 'pubkeyhash');

      // Input transcation
      var src = bcoin.mtx({
        outputs: [{
          value: 5460 * 2,
          address: bullshitNesting
            ? w.getProgramAddress()
            : w.getAddress()
        }, {
          value: 5460 * 2,
          address: bcoin.address.fromData(new Buffer([])).toBase58()
        }]
      });

      src.addInput(dummyInput);

      var tx = bcoin.mtx()
        .addInput(src, 0)
        .addOutput(w.getAddress(), 5460);

      w.sign(tx, function(err) {
        assert.ifError(err);
        assert(tx.verify(null, true, flags));
        cb();
      });
    });
  }

  it('should sign/verify pubkeyhash tx', function(cb) {
    p2pkh(false, false, cb);
  });

  it('should sign/verify witnesspubkeyhash tx', function(cb) {
    p2pkh(true, false, cb);
  });

  it('should sign/verify witnesspubkeyhash tx with bullshit nesting', function(cb) {
    p2pkh(true, true, cb);
  });

  it('should multisign/verify TX', function() {
    var w = bcoin.wallet({
      derivation: 'bip44',
      type: 'multisig',
      m: 1,
      n: 2
    });
    w.init(function(err) {
      assert.ifError(err);
      var k2 = bcoin.hd.fromMnemonic().deriveAccount44(0).hdPublicKey;
      w.addKey(k2, function(err) {
        assert.ifError(err);
        // Input transcation
        var src = bcoin.mtx({
          outputs: [{
            value: 5460 * 2,
            m: 1,
            keys: [ w.getPublicKey(), k2.derive('m/0/0').publicKey ]
          }, {
            value: 5460 * 2,
            address: bcoin.address.fromData(new Buffer([])).toBase58()
          }]
        });
        src.addInput(dummyInput);

        var tx = bcoin.mtx()
          .addInput(src, 0)
          .addOutput(w.getAddress(), 5460);

        var maxSize = tx.maxSize();
        w.sign(tx, function(err) {
          assert.ifError(err);
          assert(tx.render().length <= maxSize);
          assert(tx.verify());
        });
      });
    });
  });

  var dw, di;
  it('should have TX pool and be serializable', function(cb) {
    wdb.create({}, function(err, w) {
      assert.ifError(err);
      wdb.create({}, function(err, f) {
        assert.ifError(err);
        dw = w;

        // Coinbase
        var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 1000);
        t1.addInput(dummyInput);
        // balance: 51000
        // w.sign(t1);
        w.sign(t1, function(err) {
          assert.ifError(err);
          var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                             .addOutput(w, 24000)
                             .addOutput(w, 24000);
          di = t2.inputs[0];
          // balance: 49000
          // w.sign(t2);
          w.sign(t2, function(err) {
            assert.ifError(err);
            var t3 = bcoin.mtx().addInput(t1, 1) // 1000
                               .addInput(t2, 0) // 24000
                               .addOutput(w, 23000);
            // balance: 47000
            // w.sign(t3);
            w.sign(t3, function(err) {
              assert.ifError(err);
              var t4 = bcoin.mtx().addInput(t2, 1) // 24000
                                 .addInput(t3, 0) // 23000
                                 .addOutput(w, 11000)
                                 .addOutput(w, 11000);
              // balance: 22000
              // w.sign(t4);
              w.sign(t4, function(err) {
                assert.ifError(err);
                var f1 = bcoin.mtx().addInput(t4, 1) // 11000
                                   .addOutput(f, 10000);
                // balance: 11000
                // w.sign(f1);
                w.sign(f1, function(err) {
                  assert.ifError(err);
                  var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                                       .addOutput(w, 500);
                  // Script inputs but do not sign
                  // w.scriptInputs(fake);
                  w.scriptInputs(fake, function(err) {
                    assert.ifError(err);
                    // Fake signature
                    fake.inputs[0].script.code[0] = new Buffer([0,0,0,0,0,0,0,0,0]);
                    // balance: 11000

                    // Just for debugging
                    t1.hint = 't1';
                    t2.hint = 't2';
                    t3.hint = 't3';
                    t4.hint = 't4';
                    f1.hint = 'f1';
                    fake.hint = 'fake';

                    // Fake TX should temporarly change output
                    wdb.addTX(fake, function(err) {
                      assert.ifError(err);
                      wdb.addTX(t4, function(err) {
                        assert.ifError(err);
                        w.getBalance(function(err, balance) {
                          assert.ifError(err);
                          assert.equal(balance.total, 22500);
                          wdb.addTX(t1, function(err) {
                            w.getBalance(function(err, balance) {
                              assert.ifError(err);
                              assert.equal(balance.total, 73000);
                              wdb.addTX(t2, function(err) {
                                assert.ifError(err);
                                w.getBalance(function(err, balance) {
                                  assert.ifError(err);
                                  assert.equal(balance.total, 47000);
                                  wdb.addTX(t3, function(err) {
                                    assert.ifError(err);
                                    w.getBalance(function(err, balance) {
                                      assert.ifError(err);
                                      assert.equal(balance.total, 22000);
                                      wdb.addTX(f1, function(err) {
                                        assert.ifError(err);
                                        w.getBalance(function(err, balance) {
                                          assert.ifError(err);
                                          assert.equal(balance.total, 11000);
                                          w.getHistory(function(err, txs) {
                                            assert(txs.some(function(tx) {
                                              return tx.hash('hex') === f1.hash('hex');
                                            }));

                                            //var w2 = bcoin.wallet.fromJSON(w.toJSON());
                                            // assert.equal(w2.getBalance(), 11000);
                                            // assert(w2.getHistory().some(function(tx) {
                                            //   return tx.hash('hex') === f1.hash('hex');
                                            // }));
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
                });
              });
            });
          });
        });
      });
    });
  });

  it('should cleanup spenders after double-spend', function(cb) {
    var t1 = bcoin.mtx().addOutput(dw, 5000);
    t1.addInput(di);
    wdb.addTX(t1, function(err) {
      assert.ifError(err);
      dw.getBalance(function(err, balance) {
        assert.ifError(err);
        assert.equal(balance.total, 11000);
        cb();
      });
    });
  });

  it('should fill tx with inputs', function(cb) {
    wdb.create({}, function(err, w1) {
      assert.ifError(err);
      wdb.create({}, function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        // Fake TX should temporarly change output
        wdb.addTX(t1, function(err) {
          assert.ifError(err);

          // Create new transaction
          var t2 = bcoin.mtx().addOutput(w2, 5460);
          w1.fill(t2, { rate: 10000, round: true }, function(err) {
            assert.ifError(err);
            w1.sign(t2, function(err) {
              assert.ifError(err);

              assert(t2.verify());

              assert.equal(t2.getInputValue(), 16380);
              // If change < dust and is added to outputs:
              // assert.equal(t2.getOutputValue(), 6380);
              // If change > dust and is added to fee:
              assert.equal(t2.getOutputValue(), 5460);
              assert.equal(t2.getFee(), 10920);

              // Create new transaction
              var t3 = bcoin.mtx().addOutput(w2, 15000);
              w1.fill(t3, { rate: 10000, round: true }, function(err) {
                assert(err);
                assert.equal(err.requiredFunds, 25000);
                cb();
              });
            });
          });
        });
      });
    });
  });

  it('should fill tx with inputs with accurate fee', function(cb) {
    wdb.create({ master: KEY1 }, function(err, w1) {
      assert.ifError(err);
      wdb.create({ master: KEY2 }, function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        // Fake TX should temporarly change output
        wdb.addTX(t1, function(err) {
          assert.ifError(err);

          // Create new transaction
          var t2 = bcoin.mtx().addOutput(w2, 5460);
          w1.fill(t2, { rate: 10000 }, function(err) {
            assert.ifError(err);
            w1.sign(t2, function(err) {
              assert.ifError(err);
              assert(t2.verify());

              assert.equal(t2.getInputValue(), 16380);

              // Should now have a change output:
              assert.equal(t2.getOutputValue(), 11130);

              assert.equal(t2.getFee(), 5250);

              assert.equal(t2.getCost(), 2084);
              assert.equal(t2.getBaseSize(), 521);
              assert.equal(t2.getSize(), 521);
              assert.equal(t2.getVirtualSize(), 521);

              var balance;
              w2.once('balance', function(b) {
                balance = b;
              });

              // Create new transaction
              wdb.addTX(t2, function(err) {
                assert.ifError(err);
                var t3 = bcoin.mtx().addOutput(w2, 15000);
                w1.fill(t3, { rate: 10000 }, function(err) {
                  assert(err);
                  assert(balance.total === 5460);
                  cb();
                });
              });
            });
          });
        });
      });
    });
  });

  it('should sign multiple inputs using different keys', function(cb) {
    wdb.create({}, function(err, w1) {
      assert.ifError(err);
      wdb.create({}, function(err, w2) {
        assert.ifError(err);
        wdb.create({}, function(err, to) {
          assert.ifError(err);

          // Coinbase
          var t1 = bcoin.mtx()
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(w1, 5460);

          t1.addInput(dummyInput);

          // Fake TX should temporarly change output
          // Coinbase
          var t2 = bcoin.mtx()
            .addOutput(w2, 5460)
            .addOutput(w2, 5460)
            .addOutput(w2, 5460)
            .addOutput(w2, 5460);

          t2.addInput(dummyInput);
          // Fake TX should temporarly change output

          wdb.addTX(t1, function(err) {
            assert.ifError(err);
            wdb.addTX(t2, function(err) {
              assert.ifError(err);

              // Create our tx with an output
              var tx = bcoin.mtx();
              tx.addOutput(to, 5460);

              var cost = tx.getOutputValue();
              var total = cost * constants.tx.MIN_FEE;

              w1.getCoins(function(err, coins1) {
                assert.ifError(err);
                w2.getCoins(function(err, coins2) {
                  assert.ifError(err);

                  // Add dummy output (for `left`) to calculate maximum TX size
                  tx.addOutput(w1, 0);

                  // Add our unspent inputs to sign
                  tx.addInput(coins1[0]);
                  tx.addInput(coins1[1]);
                  tx.addInput(coins2[0]);

                  var left = tx.getInputValue() - total;
                  if (left < constants.tx.DUST_THRESHOLD) {
                    tx.outputs[tx.outputs.length - 2].value += left;
                    left = 0;
                  }
                  if (left === 0)
                    tx.outputs.pop();
                  else
                    tx.outputs[tx.outputs.length - 1].value = left;

                  // Sign transaction
                  w1.sign(tx, function(err, total) {
                    assert.ifError(err);
                    assert.equal(total, 2);
                    w2.sign(tx, function(err, total) {
                      assert.ifError(err);
                      assert.equal(total, 1);

                      // Verify
                      assert.equal(tx.verify(), true);

                      // Sign transaction using `inputs` and `off` params.
                      tx.inputs.length = 0;
                      tx.addInput(coins1[1]);
                      tx.addInput(coins1[2]);
                      tx.addInput(coins2[1]);
                      w1.sign(tx, function(err, total) {
                        assert.ifError(err);
                        assert.equal(total, 2);
                        w2.sign(tx, function(err, total) {
                          assert.ifError(err);
                          assert.equal(total, 1);

                          // Verify
                          assert.equal(tx.verify(), true);

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

  function multisig(witness, bullshitNesting, cb) {
    var flags = bcoin.protocol.constants.flags.STANDARD_VERIFY_FLAGS;

    if (witness)
      flags |= bcoin.protocol.constants.flags.VERIFY_WITNESS;

    // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
    var options = {
      witness: witness,
      derivation: 'bip44',
      type: 'multisig',
      m: 2,
      n: 3
    };

    var w1, w2, w3, receive;

    utils.serial([
      function(next) {
        wdb.create(utils.merge({}, options), function(err, w1_) {
          assert.ifError(err);
          w1 = w1_;
          next();
        });
      },
      function(next) {
        wdb.create(utils.merge({}, options), function(err, w2_) {
          assert.ifError(err);
          w2 = w2_;
          next();
        });
      },
      function(next) {
        wdb.create(utils.merge({}, options), function(err, w3_) {
          assert.ifError(err);
          w3 = w3_;
          next();
        });
      },
      function(next) {
        wdb.create({}, function(err, receive_) {
          assert.ifError(err);
          receive = receive_;
          next();
        });
      }
    ], function(err) {
      assert.ifError(err);

      utils.serial([
        w1.addKey.bind(w1, w2.accountKey),
        w1.addKey.bind(w1, w3.accountKey),
        w2.addKey.bind(w2, w1.accountKey),
        w2.addKey.bind(w2, w3.accountKey),
        w3.addKey.bind(w3, w1.accountKey),
        w3.addKey.bind(w3, w2.accountKey)
      ], function(err) {
        assert.ifError(err);

        // w3 = bcoin.wallet.fromJSON(w3.toJSON());

        // Our p2sh address
        var addr = w1.getAddress();

        if (witness)
          assert(bcoin.address.parseBase58(addr).type === 'witnessscripthash');
        else
          assert(bcoin.address.parseBase58(addr).type === 'scripthash');

        assert.equal(w1.getAddress(), addr);
        assert.equal(w2.getAddress(), addr);
        assert.equal(w3.getAddress(), addr);

        var paddr = w1.getProgramAddress();
        assert.equal(w1.getProgramAddress(), paddr);
        assert.equal(w2.getProgramAddress(), paddr);
        assert.equal(w3.getProgramAddress(), paddr);

        // Add a shared unspent transaction to our wallets
        var utx = bcoin.mtx();
        if (bullshitNesting)
          utx.addOutput({ address: paddr, value: 5460 * 10 });
        else
          utx.addOutput({ address: addr, value: 5460 * 10 });

        utx.addInput(dummyInput);

        // Simulate a confirmation
        utx.ps = 0;
        utx.ts = 1;
        utx.height = 1;

        assert.equal(w1.receiveDepth, 1);

        wdb.addTX(utx, function(err) {
          assert.ifError(err);
          wdb.addTX(utx, function(err) {
            assert.ifError(err);
            wdb.addTX(utx, function(err) {
              assert.ifError(err);

              assert.equal(w1.receiveDepth, 2);
              assert.equal(w1.changeDepth, 1);

              assert(w1.getAddress() !== addr);
              addr = w1.getAddress();
              assert.equal(w1.getAddress(), addr);
              assert.equal(w2.getAddress(), addr);
              assert.equal(w3.getAddress(), addr);

              // Create a tx requiring 2 signatures
              var send = bcoin.mtx();
              send.addOutput({ address: receive.getAddress(), value: 5460 });
              assert(!send.verify(null, true, flags));
              w1.fill(send, { rate: 10000, round: true }, function(err) {
                assert.ifError(err);

                w1.sign(send, function(err) {
                  assert.ifError(err);

                  assert(!send.verify(null, true, flags));
                  w2.sign(send, function(err) {
                    assert.ifError(err);

                    assert(send.verify(null, true, flags));

                    assert.equal(w1.changeDepth, 1);
                    var change = w1.changeAddress.getAddress();
                    assert.equal(w1.changeAddress.getAddress(), change);
                    assert.equal(w2.changeAddress.getAddress(), change);
                    assert.equal(w3.changeAddress.getAddress(), change);

                    // Simulate a confirmation
                    send.ps = 0;
                    send.ts = 1;
                    send.height = 1;

                    wdb.addTX(send, function(err) {
                      assert.ifError(err);
                      wdb.addTX(send, function(err) {
                        assert.ifError(err);
                        wdb.addTX(send, function(err) {
                          assert.ifError(err);

                          assert.equal(w1.receiveDepth, 2);
                          assert.equal(w1.changeDepth, 2);

                          assert(w1.getAddress() === addr);
                          assert(w1.changeAddress.getAddress() !== change);
                          change = w1.changeAddress.getAddress();
                          assert.equal(w1.changeAddress.getAddress(), change);
                          assert.equal(w2.changeAddress.getAddress(), change);
                          assert.equal(w3.changeAddress.getAddress(), change);

                          if (witness)
                            send.inputs[0].witness.items[2] = new Buffer([]);
                          else
                            send.inputs[0].script.code[2] = 0;

                          assert(!send.verify(null, true, flags));
                          assert.equal(send.getFee(), 10000);

                          // w3 = bcoin.wallet.fromJSON(w3.toJSON());
                          // assert.equal(w3.receiveDepth, 2);
                          // assert.equal(w3.changeDepth, 2);
                          //assert.equal(w3.getAddress(), addr);
                          //assert.equal(w3.changeAddress.getAddress(), change);

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
  }

  it('should verify 2-of-3 scripthash tx', function(cb) {
    multisig(false, false, cb);
  });

  it('should verify 2-of-3 witnessscripthash tx', function(cb) {
    multisig(true, false, cb);
  });

  it('should verify 2-of-3 witnessscripthash tx with bullshit nesting', function(cb) {
    multisig(true, true, cb);
  });

  it('should cleanup', function(cb) {
    constants.tx.COINBASE_MATURITY = 100;
    cb();
  });
});

'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var utils = bcoin.utils;
var assert = require('assert');

var FAKE_SIG = new Buffer([0,0,0,0,0,0,0,0,0]);

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
  var walletdb = new bcoin.walletdb({
    name: 'wallet-test',
    db: 'memory',
    verify: true
  });

  it('should open walletdb', function(cb) {
    constants.tx.COINBASE_MATURITY = 0;
    walletdb.open(cb);
  });

  it('should generate new key and address', function() {
    walletdb.create(function(err, w) {
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

  it('should create and get wallet', function(cb) {
    walletdb.create(function(err, w1) {
      assert.ifError(err);
      w1.destroy();
      walletdb.get(w1.id, function(err, w1_) {
        assert.ifError(err);
        assert(w1 !== w1_);
        assert(w1.master !== w1_.master);
        assert.equal(w1.master.key.xprivkey, w1.master.key.xprivkey);
        assert(w1.account !== w1_.account);
        assert.equal(w1.account.accountKey.xpubkey, w1.account.accountKey.xpubkey);
        cb();
      });
    });
  });

  function p2pkh(witness, bullshitNesting, cb) {
    var flags = bcoin.protocol.constants.flags.STANDARD_VERIFY_FLAGS;

    if (witness)
      flags |= bcoin.protocol.constants.flags.VERIFY_WITNESS;

    walletdb.create({ witness: witness }, function(err, w) {
      assert.ifError(err);

      if (witness)
        assert(bcoin.address.fromBase58(w.getAddress()).type === 'witnesspubkeyhash');
      else
        assert(bcoin.address.fromBase58(w.getAddress()).type === 'pubkeyhash');

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
        assert(tx.verify(flags));
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
    walletdb.create({
      type: 'multisig',
      m: 1,
      n: 2
    }, function(err, w) {
      assert.ifError(err);
      var k2 = bcoin.hd.fromMnemonic().deriveAccount44(0).hdPublicKey;
      w.addKey(k2, function(err) {
        assert.ifError(err);
        var keys = [
          w.getPublicKey(),
          k2.derive('m/0/0').publicKey
        ];
        // Input transaction (bare 1-of-2 multisig)
        var src = bcoin.mtx({
          outputs: [{
            value: 5460 * 2,
            script: bcoin.script.fromMultisig(1, 2, keys)
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
          assert(tx.toRaw().length <= maxSize);
          assert(tx.verify());
        });
      });
    });
  });

  var dw, di;
  it('should have TX pool and be serializable', function(cb) {
    walletdb.create(function(err, w) {
      assert.ifError(err);
      walletdb.create(function(err, f) {
        assert.ifError(err);
        dw = w;

        // Coinbase
        var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 1000);
        t1.addInput(dummyInput);
        // balance: 51000
        w.sign(t1, function(err) {
          assert.ifError(err);
          var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                             .addOutput(w, 24000)
                             .addOutput(w, 24000);
          di = t2.inputs[0];
          // balance: 49000
          w.sign(t2, function(err) {
            assert.ifError(err);
            var t3 = bcoin.mtx().addInput(t1, 1) // 1000
                               .addInput(t2, 0) // 24000
                               .addOutput(w, 23000);
            // balance: 47000
            w.sign(t3, function(err) {
              assert.ifError(err);
              var t4 = bcoin.mtx().addInput(t2, 1) // 24000
                                 .addInput(t3, 0) // 23000
                                 .addOutput(w, 11000)
                                 .addOutput(w, 11000);
              // balance: 22000
              w.sign(t4, function(err) {
                assert.ifError(err);
                var f1 = bcoin.mtx().addInput(t4, 1) // 11000
                                   .addOutput(f, 10000);
                // balance: 11000
                w.sign(f1, function(err) {
                  assert.ifError(err);
                  var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                                       .addOutput(w, 500);
                  // Script inputs but do not sign
                  w.scriptInputs(fake, function(err) {
                    assert.ifError(err);
                    // Fake signature
                    fake.inputs[0].script.code[0] = bcoin.opcode.fromData(FAKE_SIG);
                    fake.inputs[0].script.compile();
                    // balance: 11000

                    // Fake TX should temporarly change output
                    walletdb.addTX(fake, function(err) {
                      assert.ifError(err);
                      walletdb.addTX(t4, function(err) {
                        assert.ifError(err);
                        w.getBalance(function(err, balance) {
                          assert.ifError(err);
                          assert.equal(balance.total, 22500);
                          walletdb.addTX(t1, function(err) {
                            w.getBalance(function(err, balance) {
                              assert.ifError(err);
                              assert.equal(balance.total, 73000);
                              walletdb.addTX(t2, function(err) {
                                assert.ifError(err);
                                w.getBalance(function(err, balance) {
                                  assert.ifError(err);
                                  assert.equal(balance.total, 47000);
                                  walletdb.addTX(t3, function(err) {
                                    assert.ifError(err);
                                    w.getBalance(function(err, balance) {
                                      assert.ifError(err);
                                      assert.equal(balance.total, 22000);
                                      walletdb.addTX(f1, function(err) {
                                        assert.ifError(err);
                                        w.getBalance(function(err, balance) {
                                          assert.ifError(err);
                                          assert.equal(balance.total, 11000);
                                          w.getHistory(function(err, txs) {
                                            assert(txs.some(function(tx) {
                                              return tx.hash('hex') === f1.hash('hex');
                                            }));
                                            f.getBalance(function(err, balance) {
                                              assert.ifError(err);
                                              assert.equal(balance.total, 10000);
                                              f.getHistory(function(err, txs) {
                                                assert.ifError(err);
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
    t1.addInput(di.coin);
    dw.getHistory(function(err, txs) {
      assert.ifError(err);
      assert.equal(txs.length, 5);
      var total = txs.reduce(function(t, tx) {
        return t + tx.getOutputValue();
      }, 0);
      assert.equal(total, 154000);
      dw.sign(t1, function(err) {
        assert.ifError(err);
        dw.getBalance(function(err, balance) {
          assert.ifError(err);
          assert.equal(balance.total, 11000);
          walletdb.addTX(t1, function(err) {
            assert.ifError(err);
            dw.getBalance(function(err, balance) {
              assert.ifError(err);
              assert.equal(balance.total, 6000);
              dw.getHistory(function(err, txs) {
                assert.ifError(err);
                assert.equal(txs.length, 2);
                var total = txs.reduce(function(t, tx) {
                  return t + tx.getOutputValue();
                }, 0);
                assert.equal(total, 56000);
                cb();
              });
            });
          });
        });
      });
    });
  });

  it('should fill tx with inputs', function(cb) {
    walletdb.create(function(err, w1) {
      assert.ifError(err);
      walletdb.create(function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        walletdb.addTX(t1, function(err) {
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
    walletdb.create({ master: KEY1 }, function(err, w1) {
      assert.ifError(err);
      walletdb.create({ master: KEY2 }, function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        walletdb.addTX(t1, function(err) {
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
              walletdb.addTX(t2, function(err) {
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
    walletdb.create(function(err, w1) {
      assert.ifError(err);
      walletdb.create(function(err, w2) {
        assert.ifError(err);
        walletdb.create(function(err, to) {
          assert.ifError(err);

          // Coinbase
          var t1 = bcoin.mtx()
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(w1, 5460);

          t1.addInput(dummyInput);

          // Coinbase
          var t2 = bcoin.mtx()
            .addOutput(w2, 5460)
            .addOutput(w2, 5460)
            .addOutput(w2, 5460)
            .addOutput(w2, 5460);

          t2.addInput(dummyInput);

          walletdb.addTX(t1, function(err) {
            assert.ifError(err);
            walletdb.addTX(t2, function(err) {
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
      type: 'multisig',
      m: 2,
      n: 3
    };

    var w1, w2, w3, receive;

    utils.serial([
      function(next) {
        walletdb.create(options, function(err, w1_) {
          assert.ifError(err);
          w1 = w1_;
          next();
        });
      },
      function(next) {
        walletdb.create(options, function(err, w2_) {
          assert.ifError(err);
          w2 = w2_;
          next();
        });
      },
      function(next) {
        walletdb.create(options, function(err, w3_) {
          assert.ifError(err);
          w3 = w3_;
          next();
        });
      },
      function(next) {
        walletdb.create(function(err, receive_) {
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
          assert(bcoin.address.fromBase58(addr).type === 'witnessscripthash');
        else
          assert(bcoin.address.fromBase58(addr).type === 'scripthash');

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

        walletdb.addTX(utx, function(err) {
          assert.ifError(err);
          walletdb.addTX(utx, function(err) {
            assert.ifError(err);
            walletdb.addTX(utx, function(err) {
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
              assert(!send.verify(flags));
              w1.fill(send, { rate: 10000, round: true }, function(err) {
                assert.ifError(err);

                w1.sign(send, function(err) {
                  assert.ifError(err);

                  assert(!send.verify(flags));
                  w2.sign(send, function(err) {
                    assert.ifError(err);

                    assert(send.verify(flags));

                    assert.equal(w1.changeDepth, 1);
                    var change = w1.changeAddress.getAddress();
                    assert.equal(w1.changeAddress.getAddress(), change);
                    assert.equal(w2.changeAddress.getAddress(), change);
                    assert.equal(w3.changeAddress.getAddress(), change);

                    // Simulate a confirmation
                    send.ps = 0;
                    send.ts = 1;
                    send.height = 1;

                    walletdb.addTX(send, function(err) {
                      assert.ifError(err);
                      walletdb.addTX(send, function(err) {
                        assert.ifError(err);
                        walletdb.addTX(send, function(err) {
                          assert.ifError(err);

                          assert.equal(w1.receiveDepth, 2);
                          assert.equal(w1.changeDepth, 2);

                          assert(w1.getAddress() === addr);
                          assert(w1.changeAddress.getAddress() !== change);
                          change = w1.changeAddress.getAddress();
                          assert.equal(w1.changeAddress.getAddress(), change);
                          assert.equal(w2.changeAddress.getAddress(), change);
                          assert.equal(w3.changeAddress.getAddress(), change);

                          if (witness) {
                            send.inputs[0].witness.items[2] = new Buffer([]);
                          } else {
                            send.inputs[0].script.code[2] = new bcoin.opcode(0);
                            send.inputs[0].script.compile();
                          }

                          assert(!send.verify(flags));
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

  it('should fill tx with account 1', function(cb) {
    walletdb.create({}, function(err, w1) {
      assert.ifError(err);
      walletdb.create({}, function(err, w2) {
        assert.ifError(err);
        w1.createAccount({ name: 'foo' }, function(err, account) {
          assert.ifError(err);
          assert.equal(account.name, 'foo');
          assert.equal(account.accountIndex, 1);
          w1.getAccount('foo', function(err, account) {
            assert.ifError(err);
            assert.equal(account.name, 'foo');
            assert.equal(account.accountIndex, 1);

            // Coinbase
            var t1 = bcoin.mtx()
              .addOutput(account.receiveAddress, 5460)
              .addOutput(account.receiveAddress, 5460)
              .addOutput(account.receiveAddress, 5460)
              .addOutput(account.receiveAddress, 5460);

            t1.addInput(dummyInput);

            walletdb.addTX(t1, function(err) {
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
                    w1.getAccounts(function(err, accounts) {
                      assert.ifError(err);
                      assert.deepEqual(accounts, ['default', 'foo']);
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

  it('should fail to fill tx with account 1', function(cb) {
    walletdb.create({}, function(err, w1) {
      assert.ifError(err);
      w1.createAccount({ name: 'foo' }, function(err, acc) {
        assert.ifError(err);
        assert.equal(acc.name, 'foo');
        assert.equal(acc.accountIndex, 1);
        w1.getAccount('foo', function(err, account) {
          assert.ifError(err);
          assert.equal(account.name, 'foo');
          assert.equal(account.accountIndex, 1);
          assert(account !== w1.account);
          assert(account !== acc);
          assert(account.accountKey.xpubkey === acc.accountKey.xpubkey);
          assert(w1.account.accountIndex === 0);
          assert(account.receiveAddress.getAddress() !== w1.account.receiveAddress.getAddress());
          assert(w1.getAddress() === w1.account.receiveAddress.getAddress());

          // Coinbase
          var t1 = bcoin.mtx()
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(w1, 5460)
            .addOutput(account.receiveAddress, 5460);

          t1.addInput(dummyInput);

          walletdb.addTX(t1, function(err) {
            assert.ifError(err);

            // Should fill from `foo` and fail
            var t2 = bcoin.mtx().addOutput(w1, 5460);
            w1.fill(t2, { rate: 10000, round: true, account: 'foo' }, function(err) {
              assert(err);
              // Should fill from whole wallet and succeed
              var t2 = bcoin.mtx().addOutput(w1, 5460);
              w1.fill(t2, { rate: 10000, round: true }, function(err) {
                assert.ifError(err);

                // Coinbase
                var t1 = bcoin.mtx()
                  .addOutput(account.receiveAddress, 5460)
                  .addOutput(account.receiveAddress, 5460)
                  .addOutput(account.receiveAddress, 5460);

                t1.addInput(dummyInput);

                walletdb.addTX(t1, function(err) {
                  assert.ifError(err);
                  var t2 = bcoin.mtx().addOutput(w1, 5460);
                  // Should fill from `foo` and succeed
                  w1.fill(t2, { rate: 10000, round: true, account: 'foo' }, function(err) {
                    assert.ifError(err);
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

  it('should fill tx with inputs when encrypted', function(cb) {
    walletdb.create({ passphrase: 'foo' }, function(err, w1) {
      assert.ifError(err);
      w1.master.destroy();

      // Coinbase
      var t1 = bcoin.mtx()
        .addOutput(w1, 5460)
        .addOutput(w1, 5460)
        .addOutput(w1, 5460)
        .addOutput(w1, 5460);

      t1.addInput(dummyInput);

      walletdb.addTX(t1, function(err) {
        assert.ifError(err);

        // Create new transaction
        var t2 = bcoin.mtx().addOutput(w1, 5460);
        w1.fill(t2, { rate: 10000, round: true }, function(err) {
          assert.ifError(err);
          // Should fail
          w1.sign(t2, 'bar', function(err) {
            assert(err);
            assert(!t2.verify());
            // Should succeed
            w1.sign(t2, 'foo', function(err) {
              assert.ifError(err);
              assert(t2.verify());
              cb();
            });
          });
        });
      });
    });
  });

  it('should fill tx with inputs with subtract fee', function(cb) {
    walletdb.create(function(err, w1) {
      assert.ifError(err);
      walletdb.create(function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        walletdb.addTX(t1, function(err) {
          assert.ifError(err);

          // Create new transaction
          var t2 = bcoin.mtx().addOutput(w2, 21840);
          w1.fill(t2, { rate: 10000, round: true, subtractFee: true }, function(err) {
            assert.ifError(err);
            w1.sign(t2, function(err) {
              assert.ifError(err);

              assert(t2.verify());

              assert.equal(t2.getInputValue(), 5460 * 4);
              assert.equal(t2.getOutputValue(), 21840 - 10000);
              assert.equal(t2.getFee(), 10000);

              cb();
            });
          });
        });
      });
    });
  });

  it('should fill tx with inputs with subtract fee with create tx', function(cb) {
    walletdb.create(function(err, w1) {
      assert.ifError(err);
      walletdb.create(function(err, w2) {
        assert.ifError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        walletdb.addTX(t1, function(err) {
          assert.ifError(err);

          var options = {
            subtractFee: true,
            rate: 10000,
            round: true,
            outputs: [{ address: w2.getAddress(), value: 21840 }]
          };

          // Create new transaction
          w1.createTX(options, function(err, t2) {
            assert.ifError(err);
            w1.sign(t2, function(err) {
              assert.ifError(err);

              assert(t2.verify());

              assert.equal(t2.getInputValue(), 5460 * 4);
              assert.equal(t2.getOutputValue(), 21840 - 10000);
              assert.equal(t2.getFee(), 10000);

              cb();
            });
          });
        });
      });
    });
  });

  it('should cleanup', function(cb) {
    constants.tx.COINBASE_MATURITY = 100;
    cb();
  });
});

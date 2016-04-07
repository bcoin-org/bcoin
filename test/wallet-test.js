var bn = require('bn.js');
var bcoin = require('../')({ db: 'memory' });
var constants = bcoin.protocol.constants;
var utils = bcoin.utils;
var assert = utils.assert;

var dummyInput = {
  prevout: {
    hash: constants.zeroHash,
    index: 0
  },
  coin: {
    version: 1,
    height: 0,
    value: constants.maxMoney.clone(),
    script: new bcoin.script([]),
    coinbase: false,
    hash: constants.zeroHash,
    index: 0
  },
  script: new bcoin.script([]),
  witness: new bcoin.script.witness([]),
  sequence: 0xffffffff
};

describe('Wallet', function() {
  var wdb = new bcoin.walletdb({ verify: true });

  it('should open walletdb', function(cb) {
    wdb.open(cb);
  });

  it('should generate new key and address', function() {
    var w = bcoin.wallet();
    var addr = w.getAddress();
    assert(addr);
    assert(bcoin.address.validate(addr));
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
      assert.noError(err);

      if (witness)
        assert(bcoin.address.parse(w.getAddress()).type === 'witnesspubkeyhash');
      else
        assert(bcoin.address.parse(w.getAddress()).type === 'pubkeyhash');

      // Input transcation
      var src = bcoin.mtx({
        outputs: [{
          value: 5460 * 2,
          address: bullshitNesting
            ? w.getProgramAddress()
            : w.getAddress()
        }, {
          value: 5460 * 2,
          address: bcoin.address.compileData(new Buffer([]))
        }]
      });

      src.addInput(dummyInput);
      assert(w.ownOutput(src));
      assert(w.ownOutput(src.outputs[0]));
      assert(!w.ownOutput(src.outputs[1]));

      var tx = bcoin.mtx()
        .addInput(src, 0)
        .addOutput(w.getAddress(), 5460);

      w.sign(tx);
      assert(tx.verify(null, true, flags));

      cb();
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
    var k2 = bcoin.hd.fromSeed().deriveAccount44(0).hdPublicKey;
    w.addKey(k2);

    // Input transcation
    var src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        m: 1,
        keys: [ w.getPublicKey(), k2.derive('m/0/0').publicKey ]
      }, {
        value: 5460 * 2,
        address: bcoin.address.compileData(new Buffer([]))
      }]
    });
    src.addInput(dummyInput);
    assert(w.ownOutput(src));
    assert(w.ownOutput(src.outputs[0]));
    assert(!w.ownOutput(src.outputs[1]));

    var tx = bcoin.mtx()
      .addInput(src, 0)
      .addOutput(w.getAddress(), 5460);

    var maxSize = tx.maxSize();
    w.sign(tx);
    assert(tx.render().length <= maxSize);
    assert(tx.verify());
  });

  var dw, di;
  it('should have TX pool and be serializable', function(cb) {
    wdb.create({}, function(err, w) {
      assert.noError(err);
      wdb.create({}, function(err, f) {
        assert.noError(err);
        dw = w;

        // Coinbase
        var t1 = bcoin.mtx().addOutput(w, 50000).addOutput(w, 1000);
        t1.addInput(dummyInput);
        // balance: 51000
        w.sign(t1);
        var t2 = bcoin.mtx().addInput(t1, 0) // 50000
                           .addOutput(w, 24000)
                           .addOutput(w, 24000);
        di = t2.inputs[0];
        // balance: 49000
        w.sign(t2);
        var t3 = bcoin.mtx().addInput(t1, 1) // 1000
                           .addInput(t2, 0) // 24000
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
                           .addOutput(f, 10000);
        // balance: 11000
        w.sign(f1);
        var fake = bcoin.mtx().addInput(t1, 1) // 1000 (already redeemed)
                             .addOutput(w, 500);
        // Script inputs but do not sign
        w.scriptInputs(fake);
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
          assert.noError(err);
          wdb.addTX(t4, function(err) {
            assert.noError(err);
            w.getBalance(function(err, balance) {
              assert.noError(err);
              assert.equal(balance.unconfirmed.toString(10), '22500');
              wdb.addTX(t1, function(err) {
                w.getBalance(function(err, balance) {
                  assert.noError(err);
                  assert.equal(balance.unconfirmed.toString(10), '73000');
                  wdb.addTX(t2, function(err) {
                    assert.noError(err);
                    w.getBalance(function(err, balance) {
                      assert.noError(err);
                      assert.equal(balance.unconfirmed.toString(10), '47000');
                      wdb.addTX(t3, function(err) {
                        assert.noError(err);
                        w.getBalance(function(err, balance) {
                          assert.noError(err);
                          assert.equal(balance.unconfirmed.toString(10), '22000');
                          wdb.addTX(f1, function(err) {
                            assert.noError(err);
                            w.getBalance(function(err, balance) {
                              assert.noError(err);
                              assert.equal(balance.unconfirmed.toString(10), '11000');
                              w.getAll(function(err, txs) {
                                assert(txs.some(function(tx) {
                                  return tx.hash('hex') === f1.hash('hex');
                                }));

                                var w2 = bcoin.wallet.fromJSON(w.toJSON());
                                // assert.equal(w2.getBalance().toString(10), '11000');
                                // assert(w2.getAll().some(function(tx) {
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

  it('should cleanup spenders after double-spend', function(cb) {
    var t1 = bcoin.mtx().addOutput(dw, 5000);
    t1.addInput(di);
    wdb.addTX(t1, function(err) {
      assert.noError(err);
      dw.getBalance(function(err, balance) {
        assert.noError(err);
        assert.equal(balance.unconfirmed.toString(10), '11000');
        cb();
      });
    });
  });

  it('should fill tx with inputs', function(cb) {
    wdb.create({}, function(err, w1) {
      assert.noError(err);
      wdb.create({}, function(err, w2) {
        assert.noError(err);

        // Coinbase
        var t1 = bcoin.mtx()
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460)
          .addOutput(w1, 5460);

        t1.addInput(dummyInput);

        // Fake TX should temporarly change output
        wdb.addTX(t1, function(err) {
          assert.noError(err);

          // Create new transaction
          var t2 = bcoin.mtx().addOutput(w2, 5460);
          w1.fill(t2, function(err) {
            assert.noError(err);
            w1.sign(t2);
            assert(t2.verify());

            assert.equal(t2.getInputValue().toString(10), 16380);
            // If change < dust and is added to outputs:
            // assert.equal(t2.getOutputValue().toString(10), 6380);
            // If change < dust and is added to fee:
            assert.equal(t2.getOutputValue().toString(10), 5460);

            // Create new transaction
            var t3 = bcoin.mtx().addOutput(w2, 15000);
            w1.fill(t3, function(err) {
              assert(err);
              assert.equal(err.requiredFunds.toString(10), 25000);
              cb();
            });
          });
        });
      });
    });
  });

  it('should sign multiple inputs using different keys', function(cb) {
    wdb.create({}, function(err, w1) {
      assert.noError(err);
      wdb.create({}, function(err, w2) {
        assert.noError(err);
        wdb.create({}, function(err, to) {
          assert.noError(err);

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
            assert.noError(err);
            wdb.addTX(t2, function(err) {
              assert.noError(err);

              // Create our tx with an output
              var tx = bcoin.mtx();
              tx.addOutput(to, 5460);

              var cost = tx.getOutputValue();
              var total = cost.add(new bn(constants.tx.minFee));

              w1.getCoins(function(err, coins1) {
                assert.noError(err);
                w2.getCoins(function(err, coins2) {
                  assert.noError(err);

                  // Add dummy output (for `left`) to calculate maximum TX size
                  tx.addOutput(w1, new bn(0));

                  // Add our unspent inputs to sign
                  tx.addInput(coins1[0]);
                  tx.addInput(coins1[1]);
                  tx.addInput(coins2[0]);

                  var left = tx.getInputValue().sub(total);
                  if (left.cmpn(constants.tx.dustThreshold) < 0) {
                    tx.outputs[tx.outputs.length - 2].value.iadd(left);
                    left = new bn(0);
                  }
                  if (left.cmpn(0) === 0)
                    tx.outputs.pop();
                  else
                    tx.outputs[tx.outputs.length - 1].value = left;

                  // Sign transaction
                  assert.equal(w1.sign(tx), 2);
                  assert.equal(w2.sign(tx), 1);

                  // Verify
                  assert.equal(tx.verify(), true);

                  // Sign transaction using `inputs` and `off` params.
                  tx.inputs.length = 0;
                  tx.addInput(coins1[1]);
                  tx.addInput(coins1[2]);
                  tx.addInput(coins2[1]);
                  assert.equal(w1.sign(tx), 2);
                  assert.equal(w2.sign(tx), 1);

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

    wdb.create(utils.merge({}, options), function(err, w1) {
      assert.noError(err);
      wdb.create(utils.merge({}, options), function(err, w2) {
        assert.noError(err);
        wdb.create(utils.merge({}, options), function(err, w3) {
          assert.noError(err);
          wdb.create({}, function(err, receive) {
            assert.noError(err);

            w1.addKey(w2);
            w1.addKey(w3);
            w2.addKey(w1);
            w2.addKey(w3);
            w3.addKey(w1);
            w3.addKey(w2);

            // w3 = bcoin.wallet.fromJSON(w3.toJSON());

            // Our p2sh address
            var addr = w1.getAddress();

            if (witness)
              assert(bcoin.address.parse(addr).type === 'witnessscripthash');
            else
              assert(bcoin.address.parse(addr).type === 'scripthash');

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

            assert(w1.ownOutput(utx.outputs[0]));

            // Simulate a confirmation
            utx.ps = 0;
            utx.ts = 1;
            utx.height = 1;

            assert.equal(w1.receiveDepth, 1);

            wdb.addTX(utx, function(err) {
              assert.noError(err);
              wdb.addTX(utx, function(err) {
                assert.noError(err);
                wdb.addTX(utx, function(err) {
                  assert.noError(err);

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
                  w1.fill(send, { m: w1.m, n: w1.n }, function(err) {
                    assert.noError(err);

                    w1.sign(send);

                    assert(!send.verify(null, true, flags));
                    w2.sign(send);

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
                      assert.noError(err);
                      wdb.addTX(send, function(err) {
                        assert.noError(err);
                        wdb.addTX(send, function(err) {
                          assert.noError(err);

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
                          assert.equal(send.getFee().toNumber(), 10000);

                          w3 = bcoin.wallet.fromJSON(w3.toJSON());
                          assert.equal(w3.receiveDepth, 2);
                          assert.equal(w3.changeDepth, 2);
                          assert.equal(w3.getAddress(), addr);
                          assert.equal(w3.changeAddress.getAddress(), change);

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

  it('should have gratuitous dump', function(cb) {
    bcoin.walletdb().dump(function(err, records) {
      assert.noError(err);
      console.log(records);
      setTimeout(cb, 200);
    });
  });
});

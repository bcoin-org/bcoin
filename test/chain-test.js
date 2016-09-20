'use strict';

var bn = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var utils = bcoin.utils;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var opcodes = constants.opcodes;

describe('Chain', function() {
  var chain, wallet, node, miner, walletdb;
  var competingTip, oldTip, tip1, tip2, cb1, cb2;

  this.timeout(5000);

  function c(p, cb) {
    var called = false;
    p.then(function(result) {
      called = true;
      cb(null, result);
    }).catch(function(err) {
      if (called) {
        utils.nextTick(function() {
          throw err;
        });
        return;
      }
      cb(err);
    });
  }

  node = new bcoin.fullnode({ db: 'memory' });
  chain = node.chain;
  walletdb = node.walletdb;
  miner = node.miner;
  node.on('error', function() {});

  function mineBlock(tip, tx, callback) {
    c(miner.createBlock(tip), function(err, attempt) {
      assert.ifError(err);
      if (tx) {
        var redeemer = bcoin.mtx();
        redeemer.addOutput({
          address: wallet.receiveAddress.getAddress(),
          value: utils.satoshi('25.0')
        });
        redeemer.addOutput({
          address: wallet.changeAddress.getAddress(),
          value: utils.satoshi('5.0')
        });
        redeemer.addInput(tx, 0);
        redeemer.setLocktime(chain.height);
        return c(wallet.sign(redeemer), function(err) {
          assert.ifError(err);
          attempt.addTX(redeemer.toTX());
          callback(null, attempt.mineSync());
        });
      }
      callback(null, attempt.mineSync());
    });
  }

  function deleteCoins(tx) {
    if (tx.txs) {
      deleteCoins(tx.txs);
      return;
    }
    if (Array.isArray(tx)) {
      tx.forEach(deleteCoins);
      return;
    }
    tx.inputs.forEach(function(input) {
      input.coin = null;
    });
  }

  it('should open chain and miner', function(cb) {
    miner.mempool = null;
    constants.tx.COINBASE_MATURITY = 0;
    c(node.open(), cb);
  });

  it('should open walletdb', function(cb) {
    c(walletdb.create({}), function(err, w) {
      assert.ifError(err);
      wallet = w;
      miner.address = wallet.getAddress();
      cb();
    });
  });

  it('should mine a block', function(cb) {
    c(miner.mineBlock(), function(err, block) {
      assert.ifError(err);
      assert(block);
      cb();
    });
  });

  it('should mine competing chains', function(cb) {
    utils.forRangeSerial(0, 10, function(i, next) {
      mineBlock(tip1, cb1, function(err, block1) {
        assert.ifError(err);
        cb1 = block1.txs[0];
        mineBlock(tip2, cb2, function(err, block2) {
          assert.ifError(err);
          cb2 = block2.txs[0];
          deleteCoins(block1);
          c(chain.add(block1), function(err) {
            assert.ifError(err);
            deleteCoins(block2);
            c(chain.add(block2), function(err) {
              assert.ifError(err);
              assert(chain.tip.hash === block1.hash('hex'));
              competingTip = block2.hash('hex');
              c(chain.db.get(block1.hash('hex')), function(err, entry1) {
                assert.ifError(err);
                c(chain.db.get(block2.hash('hex')), function(err, entry2) {
                  assert.ifError(err);
                  assert(entry1);
                  assert(entry2);
                  tip1 = entry1;
                  tip2 = entry2;
                  c(chain.db.isMainChain(block2.hash('hex')), function(err, result) {
                    assert.ifError(err);
                    assert(!result);
                    next();
                  });
                });
              });
            });
          });
        });
      });
    }, cb);
  });

  it('should handle a reorg', function(cb) {
    assert.equal(walletdb.height, chain.height);
    assert.equal(chain.height, 10);
    oldTip = chain.tip;
    c(chain.db.get(competingTip), function(err, entry) {
      assert.ifError(err);
      assert(entry);
      assert(chain.height === entry.height);
      c(miner.mineBlock(entry), function(err, block) {
        assert.ifError(err);
        assert(block);
        var forked = false;
        chain.once('reorganize', function() {
          forked = true;
        });
        deleteCoins(block);
        c(chain.add(block), function(err) {
          assert.ifError(err);
          assert(forked);
          assert(chain.tip.hash === block.hash('hex'));
          assert(chain.tip.chainwork.cmp(oldTip.chainwork) > 0);
          cb();
        });
      });
    });
  });

  it('should check main chain', function(cb) {
    c(chain.db.isMainChain(oldTip), function(err, result) {
      assert.ifError(err);
      assert(!result);
      cb();
    });
  });

  it('should mine a block after a reorg', function(cb) {
    mineBlock(null, cb2, function(err, block) {
      assert.ifError(err);
      deleteCoins(block);
      c(chain.add(block), function(err) {
        assert.ifError(err);
        c(chain.db.get(block.hash('hex')), function(err, entry) {
          assert.ifError(err);
          assert(entry);
          assert(chain.tip.hash === entry.hash);
          c(chain.db.isMainChain(entry.hash), function(err, result) {
            assert.ifError(err);
            assert(result);
            cb();
          });
        });
      });
    });
  });

  it('should fail to mine a block with coins on an alternate chain', function(cb) {
    mineBlock(null, cb1, function(err, block) {
      assert.ifError(err);
      deleteCoins(block);
      c(chain.add(block), function(err) {
        assert(err);
        cb();
      });
    });
  });

  it('should get coin', function(cb) {
    mineBlock(null, null, function(err, block) {
      assert.ifError(err);
      c(chain.add(block), function(err) {
        assert.ifError(err);
        mineBlock(null, block.txs[0], function(err, block) {
          assert.ifError(err);
          c(chain.add(block), function(err) {
            assert.ifError(err);
            var tx = block.txs[1];
            var output = bcoin.coin.fromTX(tx, 1);
            c(chain.db.getCoin(tx.hash('hex'), 1), function(err, coin) {
              assert.ifError(err);
              assert.deepEqual(coin.toRaw(), output.toRaw());
              cb();
            });
          });
        });
      });
    });
  });

  it('should get balance', function(cb) {
    setTimeout(function() {
      c(wallet.getBalance(), function(err, balance) {
        assert.ifError(err);
        // assert.equal(balance.unconfirmed, 23000000000);
        // assert.equal(balance.confirmed, 97000000000);
        // assert.equal(balance.total, 120000000000);
        // assert.equal(wallet.account.receiveDepth, 8);
        // assert.equal(wallet.account.changeDepth, 7);
        assert.equal(walletdb.height, chain.height);
        assert.equal(walletdb.tip, chain.tip.hash);
        c(wallet.getHistory(), function(err, txs) {
          assert.ifError(err);
          assert.equal(txs.length, 44);
          cb();
        });
      });
    }, 100);
  });

  it('should rescan for transactions', function(cb) {
    var total = 0;
    c(walletdb.getAddressHashes(), function(err, hashes) {
      assert.ifError(err);
      c(chain.db.scan(null, hashes, function(block, txs) {
        total += txs.length;
        return Promise.resolve(null);
      }), function(err) {
        assert.ifError(err);
        assert.equal(total, 25);
        cb();
      });
    });
  });

  it('should cleanup', function(cb) {
    constants.tx.COINBASE_MATURITY = 100;
    c(node.close(), cb);
  });
});

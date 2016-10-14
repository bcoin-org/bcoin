'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var utils = bcoin.utils;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var opcodes = constants.opcodes;
var co = require('../lib/utils/co');
var cob = co.cob;

describe('Chain', function() {
  var chain, wallet, node, miner, walletdb;
  var tip1, tip2, cb1, cb2;

  this.timeout(5000);

  node = new bcoin.fullnode({ db: 'memory' });
  chain = node.chain;
  walletdb = node.walletdb;
  miner = node.miner;
  node.on('error', function() {});

  var mineBlock = co(function* mineBlock(tip, tx) {
    var attempt = yield miner.createBlock(tip);
    var redeemer;

    if (!tx)
      return yield attempt.mineAsync();

    redeemer = bcoin.mtx();

    redeemer.addOutput({
      address: wallet.receive.getAddress(),
      value: 25 * 1e8
    });

    redeemer.addOutput({
      address: wallet.change.getAddress(),
      value: 5 * 1e8
    });

    redeemer.addInput(tx, 0);

    redeemer.setLocktime(chain.height);

    yield wallet.sign(redeemer);

    attempt.addTX(redeemer.toTX());

    return yield attempt.mineAsync();
  });

  function deleteCoins(tx) {
    var i;

    if (tx.txs) {
      deleteCoins(tx.txs);
      return;
    }

    if (Array.isArray(tx)) {
      for (i = 0; i < tx.length; i++)
        deleteCoins(tx[i]);
      return;
    }

    for (i = 0; i < tx.inputs.length; i++)
      tx.inputs[i].coin = null;
  }

  it('should open chain and miner', cob(function* () {
    miner.mempool = null;
    constants.tx.COINBASE_MATURITY = 0;
    yield node.open();
  }));

  it('should open walletdb', cob(function* () {
    wallet = yield walletdb.create();
    miner.address = wallet.getAddress();
  }));

  it('should mine a block', cob(function* () {
    var block = yield miner.mineBlock();
    assert(block);
  }));

  it('should mine competing chains', cob(function* () {
    var i, block1, block2;

    for (i = 0; i < 10; i++) {
      block1 = yield mineBlock(tip1, cb1);
      cb1 = block1.txs[0];

      block2 = yield mineBlock(tip2, cb2);
      cb2 = block2.txs[0];

      deleteCoins(block1);
      yield chain.add(block1);

      deleteCoins(block2);
      yield chain.add(block2);

      assert(chain.tip.hash === block1.hash('hex'));

      tip1 = yield chain.db.get(block1.hash('hex'));
      tip2 = yield chain.db.get(block2.hash('hex'));

      assert(tip1);
      assert(tip2);

      assert(!(yield tip2.isMainChain()));
    }
  }));

  it('should have correct balance', cob(function* () {
    var balance;

    yield co.timeout(100);

    balance = yield wallet.getBalance();
    assert.equal(balance.unconfirmed, 0);
    assert.equal(balance.confirmed, 500 * 1e8);
    assert.equal(balance.total, 500 * 1e8);
  }));

  it('should handle a reorg', cob(function* () {
    var entry, block, forked;

    assert.equal(walletdb.height, chain.height);
    assert.equal(chain.height, 10);

    entry = yield chain.db.get(tip2.hash);
    assert(entry);
    assert(chain.height === entry.height);

    block = yield miner.mineBlock(entry);
    assert(block);

    forked = false;
    chain.once('reorganize', function() {
      forked = true;
    });

    deleteCoins(block);

    yield chain.add(block);

    assert(forked);
    assert(chain.tip.hash === block.hash('hex'));
    assert(chain.tip.chainwork.cmp(tip1.chainwork) > 0);
  }));

  it('should have correct balance', cob(function* () {
    var balance;

    yield co.timeout(100);

    balance = yield wallet.getBalance();
    assert.equal(balance.unconfirmed, 500 * 1e8);
    assert.equal(balance.confirmed, 550 * 1e8);
    assert.equal(balance.total, 1050 * 1e8);
  }));

  it('should check main chain', cob(function* () {
    var result = yield tip1.isMainChain();
    assert(!result);
  }));

  it('should mine a block after a reorg', cob(function* () {
    var block, entry, result;

    block = yield mineBlock(null, cb2);
    deleteCoins(block);
    yield chain.add(block);

    entry = yield chain.db.get(block.hash('hex'));
    assert(entry);
    assert(chain.tip.hash === entry.hash);

    result = yield entry.isMainChain();
    assert(result);
  }));

  it('should fail to mine a block with coins on an alternate chain', cob(function* () {
    var block = yield mineBlock(null, cb1);
    var err;

    deleteCoins(block);

    try {
      yield chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.reason, 'bad-txns-inputs-missingorspent');
  }));

  it('should get coin', cob(function* () {
    var block, tx, output, coin;

    block = yield mineBlock();
    yield chain.add(block);
    block = yield mineBlock(null, block.txs[0]);
    yield chain.add(block);

    tx = block.txs[1];
    output = bcoin.coin.fromTX(tx, 1);

    coin = yield chain.db.getCoin(tx.hash('hex'), 1);

    assert.deepEqual(coin.toRaw(), output.toRaw());
  }));

  it('should get balance', cob(function* () {
    var balance, txs;

    yield co.timeout(100);

    balance = yield wallet.getBalance();
    assert.equal(balance.unconfirmed, 500 * 1e8);
    assert.equal(balance.confirmed, 700 * 1e8);
    assert.equal(balance.total, 1200 * 1e8);

    assert(wallet.account.receiveDepth >= 8);
    assert(wallet.account.changeDepth >= 7);

    assert.equal(walletdb.height, chain.height);
    assert.equal(walletdb.tip, chain.tip.hash);

    txs = yield wallet.getHistory();
    assert.equal(txs.length, 44);
  }));

  it('should rescan for transactions', cob(function* () {
    var total = 0;
    var hashes = yield walletdb.getHashes();

    yield chain.db.scan(null, hashes, function(block, txs) {
      total += txs.length;
      return Promise.resolve();
    });

    assert.equal(total, 25);
  }));

  it('should cleanup', cob(function* () {
    constants.tx.COINBASE_MATURITY = 100;
    yield node.close();
  }));
});

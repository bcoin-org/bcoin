'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('regtest');
var constants = bcoin.constants;
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var opcodes = constants.opcodes;
var co = require('../lib/utils/co');
var cob = co.cob;
// var Client = require('../lib/wallet/client');

describe('Chain', function() {
  var chain, wallet, node, miner, walletdb;
  var tip1, tip2, cb1, cb2, mineBlock;

  this.timeout(5000);

  node = new bcoin.fullnode({ db: 'memory', apiKey: 'foo' });
  // node.walletdb.client = new Client({ apiKey: 'foo', network: 'regtest' });
  chain = node.chain;
  walletdb = node.walletdb;
  walletdb.options.resolution = false;
  miner = node.miner;
  node.on('error', function() {});

  mineBlock = co(function* mineBlock(tip, tx) {
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

  it('should open chain and miner', cob(function* () {
    miner.mempool = null;
    constants.tx.COINBASE_MATURITY = 0;
    yield node.open();
  }));

  it('should open walletdb', cob(function* () {
    wallet = yield walletdb.create();
    miner.addresses.length = 0;
    miner.addAddress(wallet.getAddress());
  }));

  it('should mine a block', cob(function* () {
    var block = yield miner.mineBlock();
    assert(block);
    yield chain.add(block);
  }));

  it('should mine competing chains', cob(function* () {
    var i, block1, block2;

    for (i = 0; i < 10; i++) {
      block1 = yield mineBlock(tip1, cb1);
      cb1 = block1.txs[0];

      block2 = yield mineBlock(tip2, cb2);
      cb2 = block2.txs[0];

      yield chain.add(block1);

      yield chain.add(block2);

      assert(chain.tip.hash === block1.hash('hex'));

      tip1 = yield chain.db.getEntry(block1.hash('hex'));
      tip2 = yield chain.db.getEntry(block2.hash('hex'));

      assert(tip1);
      assert(tip2);

      assert(!(yield tip2.isMainChain()));
    }
  }));

  it('should have correct balance', cob(function* () {
    var balance;

    yield co.timeout(100);

    balance = yield wallet.getBalance();
    assert.equal(balance.unconfirmed, 550 * 1e8);
    assert.equal(balance.confirmed, 550 * 1e8);
  }));

  it('should handle a reorg', cob(function* () {
    var entry, block, forked;

    assert.equal(walletdb.state.height, chain.height);
    assert.equal(chain.height, 11);

    entry = yield chain.db.getEntry(tip2.hash);
    assert(entry);
    assert(chain.height === entry.height);

    block = yield miner.mineBlock(entry);
    assert(block);

    forked = false;
    chain.once('reorganize', function() {
      forked = true;
    });

    yield chain.add(block);

    assert(forked);
    assert(chain.tip.hash === block.hash('hex'));
    assert(chain.tip.chainwork.cmp(tip1.chainwork) > 0);
  }));

  it('should have correct balance', cob(function* () {
    var balance;

    yield co.timeout(100);

    balance = yield wallet.getBalance();
    assert.equal(balance.unconfirmed, 1100 * 1e8);
    assert.equal(balance.confirmed, 600 * 1e8);
  }));

  it('should check main chain', cob(function* () {
    var result = yield tip1.isMainChain();
    assert(!result);
  }));

  it('should mine a block after a reorg', cob(function* () {
    var block = yield mineBlock(null, cb2);
    var entry, result;

    yield chain.add(block);

    entry = yield chain.db.getEntry(block.hash('hex'));
    assert(entry);
    assert(chain.tip.hash === entry.hash);

    result = yield entry.isMainChain();
    assert(result);
  }));

  it('should prevent double spend on new chain', cob(function* () {
    var block = yield mineBlock(null, cb2);
    var tip = chain.tip;
    var err;

    try {
      yield chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.reason, 'bad-txns-inputs-missingorspent');
    assert(chain.tip === tip);
  }));

  it('should fail to mine a block with coins on an alternate chain', cob(function* () {
    var block = yield mineBlock(null, cb1);
    var tip = chain.tip;
    var err;

    try {
      yield chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.reason, 'bad-txns-inputs-missingorspent');
    assert(chain.tip === tip);
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
    assert.equal(balance.unconfirmed, 1250 * 1e8);
    assert.equal(balance.confirmed, 750 * 1e8);

    assert(wallet.account.receiveDepth >= 7);
    assert(wallet.account.changeDepth >= 6);

    assert.equal(walletdb.state.height, chain.height);

    txs = yield wallet.getHistory();
    assert.equal(txs.length, 45);
  }));

  it('should get tips and remove chains', cob(function* () {
    var tips = yield chain.db.getTips();

    assert.notEqual(tips.indexOf(chain.tip.hash), -1);
    assert.equal(tips.length, 2);

    yield chain.db.removeChains();

    tips = yield chain.db.getTips();

    assert.notEqual(tips.indexOf(chain.tip.hash), -1);
    assert.equal(tips.length, 1);
  }));

  it('should rescan for transactions', cob(function* () {
    var total = 0;

    yield chain.db.scan(0, walletdb.filter, function(block, txs) {
      total += txs.length;
      return Promise.resolve();
    });

    assert.equal(total, 26);
  }));

  it('should activate csv', cob(function* () {
    var deployments = chain.network.deployments;
    var i, block, prev, state, cache;

    prev = yield chain.tip.getPrevious();
    state = yield chain.getState(prev, deployments.csv);
    assert(state === 0);

    for (i = 0; i < 417; i++) {
      block = yield miner.mineBlock();
      yield chain.add(block);
      switch (chain.height) {
        case 144:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert(state === 1);
          break;
        case 288:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert(state === 2);
          break;
        case 432:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert(state === 3);
          break;
      }
    }

    assert(chain.height === 432);
    assert(chain.state.hasCSV());

    cache = yield chain.db.getStateCache();
    assert.deepEqual(cache, chain.db.stateCache);
    assert.equal(chain.db.stateCache.updates.length, 0);
    assert(yield chain.db.verifyDeployments());
  }));

  var mineCSV = co(function* mineCSV(tx) {
    var attempt = yield miner.createBlock();
    var redeemer;

    redeemer = bcoin.mtx();

    redeemer.addOutput({
      script: [
        bcoin.script.array(new BN(1)),
        constants.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    redeemer.addInput(tx, 0);

    redeemer.setLocktime(chain.height);

    yield wallet.sign(redeemer);

    attempt.addTX(redeemer.toTX());

    return yield attempt.mineAsync();
  });

  it('should test csv', cob(function* () {
    var tx = (yield chain.db.getBlock(chain.height)).txs[0];
    var block = yield mineCSV(tx);
    var csv, attempt, redeemer;

    yield chain.add(block);

    csv = block.txs[1];

    redeemer = bcoin.mtx();

    redeemer.addOutput({
      script: [
        bcoin.script.array(new BN(2)),
        constants.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    redeemer.addInput(csv, 0);
    redeemer.setSequence(0, 1, false);

    attempt = yield miner.createBlock();

    attempt.addTX(redeemer.toTX());

    block = yield attempt.mineAsync();

    yield chain.add(block);
  }));

  it('should fail csv with bad sequence', cob(function* () {
    var csv = (yield chain.db.getBlock(chain.height)).txs[1];
    var block, attempt, redeemer, err;

    redeemer = bcoin.mtx();

    redeemer.addOutput({
      script: [
        bcoin.script.array(new BN(1)),
        constants.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    redeemer.addInput(csv, 0);
    redeemer.setSequence(0, 1, false);

    attempt = yield miner.createBlock();

    attempt.addTX(redeemer.toTX());

    block = yield attempt.mineAsync();

    try {
      yield chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.reason, 'mandatory-script-verify-flag-failed');
  }));

  it('should mine a block', cob(function* () {
    var block = yield miner.mineBlock();
    assert(block);
    yield chain.add(block);
  }));

  it('should fail csv lock checks', cob(function* () {
    var tx = (yield chain.db.getBlock(chain.height)).txs[0];
    var block = yield mineCSV(tx);
    var csv, attempt, redeemer, err;

    yield chain.add(block);

    csv = block.txs[1];

    redeemer = bcoin.mtx();

    redeemer.addOutput({
      script: [
        bcoin.script.array(new BN(2)),
        constants.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    redeemer.addInput(csv, 0);
    redeemer.setSequence(0, 2, false);

    attempt = yield miner.createBlock();

    attempt.addTX(redeemer.toTX());

    block = yield attempt.mineAsync();

    try {
      yield chain.add(block);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.reason, 'bad-txns-nonfinal');
  }));

  it('should rescan for transactions', cob(function* () {
    yield walletdb.rescan(0);
    assert.equal(wallet.state.confirmed, 1289250000000);
  }));

  it('should cleanup', cob(function* () {
    constants.tx.COINBASE_MATURITY = 100;
    yield node.close();
  }));
});

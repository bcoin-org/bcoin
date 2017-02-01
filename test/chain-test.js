'use strict';

var assert = require('assert');
var BN = require('bn.js');
var consensus = require('../lib/protocol/consensus');
var encoding = require('../lib/utils/encoding');
var co = require('../lib/utils/co');
var Coin = require('../lib/primitives/coin');
var Script = require('../lib/script/script');
var Chain = require('../lib/blockchain/chain');
var Miner = require('../lib/mining/miner');
var MTX = require('../lib/primitives/mtx');
var MemWallet = require('./util/memwallet');
var Network = require('../lib/protocol/network');
var Output = require('../lib/primitives/output');
var util = require('../lib/utils/util');
var opcodes = Script.opcodes;

describe('Chain', function() {
  var network = Network.get('regtest');
  var chain = new Chain({ db: 'memory', network: network });
  var miner = new Miner({ chain: chain, version: 4 });
  var wallet = new MemWallet({ network: network });
  var wwallet = new MemWallet({ network: network, witness: true });
  var tip1, tip2, addBlock, mineCSV;

  this.timeout(45000);

  addBlock = co(function* addBlock(attempt) {
    var block = yield attempt.mineAsync();
    try {
      yield chain.add(block);
    } catch (e) {
      assert(e.type === 'VerifyError');
      return e.reason;
    }
    return 'OK';
  });

  mineCSV = co(function* mineCSV(tx) {
    var attempt = yield miner.createBlock();
    var rtx;

    rtx = new MTX();

    rtx.addOutput({
      script: [
        Script.array(new BN(1)),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10000
    });

    rtx.addTX(tx, 0);

    rtx.setLocktime(chain.height);

    wallet.sign(rtx);

    attempt.addTX(rtx.toTX(), rtx.view);

    return yield attempt.mineAsync();
  });

  chain.on('connect', function(entry, block) {
    wallet.addBlock(entry, block.txs);
  });

  chain.on('disconnect', function(entry, block) {
    wallet.removeBlock(entry, block.txs);
  });

  it('should open chain and miner', co(function* () {
    yield chain.open();
    yield miner.open();
  }));

  it('should add addrs to miner', co(function* () {
    miner.addresses.length = 0;
    miner.addAddress(wallet.getReceive());
  }));

  it('should mine 200 blocks', co(function* () {
    var i, block;

    for (i = 0; i < 200; i++) {
      block = yield miner.mineBlock();
      assert(block);
      yield chain.add(block);
    }

    assert.equal(chain.height, 200);
  }));

  it('should mine competing chains', co(function* () {
    var i, mtx, at1, at2, blk1, blk2, hash1, hash2;

    for (i = 0; i < 10; i++) {
      at1 = yield miner.createBlock(tip1);
      at2 = yield miner.createBlock(tip2);

      mtx = yield wallet.create({
        outputs: [{
          address: wallet.getAddress(),
          value: 10 * 1e8
        }]
      });

      at1.addTX(mtx.toTX(), mtx.view);
      at2.addTX(mtx.toTX(), mtx.view);

      blk1 = yield at1.mineAsync();
      blk2 = yield at2.mineAsync();

      hash1 = blk1.hash('hex');
      hash2 = blk2.hash('hex');

      yield chain.add(blk1);
      yield chain.add(blk2);

      assert(chain.tip.hash === hash1);

      tip1 = yield chain.db.getEntry(hash1);
      tip2 = yield chain.db.getEntry(hash2);

      assert(tip1);
      assert(tip2);

      assert(!(yield tip2.isMainChain()));
    }
  }));

  it('should have correct chain value', function() {
    assert.equal(chain.db.state.value, 897500000000);
    assert.equal(chain.db.state.coin, 220);
    assert.equal(chain.db.state.tx, 221);
  });

  it('should have correct wallet balance', co(function* () {
    assert.equal(wallet.balance, 897500000000);
  }));

  it('should handle a reorg', co(function* () {
    var forked = false;
    var entry, block;

    assert.equal(chain.height, 210);

    entry = yield chain.db.getEntry(tip2.hash);
    assert(entry);
    assert(chain.height === entry.height);

    block = yield miner.mineBlock(entry);
    assert(block);

    chain.once('reorganize', function() {
      forked = true;
    });

    yield chain.add(block);

    assert(forked);
    assert(chain.tip.hash === block.hash('hex'));
    assert(chain.tip.chainwork.cmp(tip1.chainwork) > 0);
  }));

  it('should have correct chain value', function() {
    assert.equal(chain.db.state.value, 900000000000);
    assert.equal(chain.db.state.coin, 221);
    assert.equal(chain.db.state.tx, 222);
  });

  it('should have correct wallet balance', co(function* () {
    assert.equal(wallet.balance, 900000000000);
  }));

  it('should check main chain', co(function* () {
    var result = yield tip1.isMainChain();
    assert(!result);
  }));

  it('should mine a block after a reorg', co(function* () {
    var block = yield miner.mineBlock();
    var hash, entry, result;

    yield chain.add(block);

    hash = block.hash('hex');
    entry = yield chain.db.getEntry(hash);

    assert(entry);
    assert(chain.tip.hash === entry.hash);

    result = yield entry.isMainChain();
    assert(result);
  }));

  it('should prevent double spend on new chain', co(function* () {
    var attempt = yield miner.createBlock();
    var mtx, block;

    mtx = yield wallet.create({
      outputs: [{
        address: wallet.getAddress(),
        value: 10 * 1e8
      }]
    });

    attempt.addTX(mtx.toTX(), mtx.view);

    block = yield attempt.mineAsync();

    yield chain.add(block);

    attempt = yield miner.createBlock();

    assert(mtx.outputs.length > 1);
    mtx.outputs.pop();

    attempt.addTX(mtx.toTX(), mtx.view);

    assert.equal(yield addBlock(attempt), 'bad-txns-inputs-missingorspent');
  }));

  it('should fail to connect coins on an alternate chain', co(function* () {
    var block = yield chain.db.getBlock(tip1.hash);
    var cb = block.txs[0];
    var mtx = new MTX();
    var attempt;

    mtx.addTX(cb, 0);
    mtx.addOutput(wallet.getAddress(), 10 * 1e8);

    wallet.sign(mtx);

    attempt = yield miner.createBlock();
    attempt.addTX(mtx.toTX(), mtx.view);

    assert.equal(yield addBlock(attempt), 'bad-txns-inputs-missingorspent');
  }));

  it('should have correct chain value', function() {
    assert.equal(chain.db.state.value, 905000000000);
    assert.equal(chain.db.state.coin, 224);
    assert.equal(chain.db.state.tx, 225);
  });

  it('should get coin', co(function* () {
    var mtx, attempt, block, tx, output, coin;

    mtx = yield wallet.send({
      outputs: [
        {
          address: wallet.getAddress(),
          value: 1e8
        },
        {
          address: wallet.getAddress(),
          value: 1e8
        },
        {
          address: wallet.getAddress(),
          value: 1e8
        }
      ]
    });

    attempt = yield miner.createBlock();
    attempt.addTX(mtx.toTX(), mtx.view);

    block = yield attempt.mineAsync();
    yield chain.add(block);

    tx = block.txs[1];
    output = Coin.fromTX(tx, 2, chain.height);

    coin = yield chain.db.getCoin(tx.hash('hex'), 2);

    assert.deepEqual(coin.toRaw(), output.toRaw());
  }));

  it('should have correct wallet balance', co(function* () {
    assert.equal(wallet.balance, 907500000000);
    assert.equal(wallet.receiveDepth, 15);
    assert.equal(wallet.changeDepth, 14);
    assert.equal(wallet.txs, 226);
  }));

  it('should get tips and remove chains', co(function* () {
    var tips = yield chain.db.getTips();

    assert.notEqual(tips.indexOf(chain.tip.hash), -1);
    assert.equal(tips.length, 2);

    yield chain.db.removeChains();

    tips = yield chain.db.getTips();

    assert.notEqual(tips.indexOf(chain.tip.hash), -1);
    assert.equal(tips.length, 1);
  }));

  it('should rescan for transactions', co(function* () {
    var total = 0;

    yield chain.db.scan(0, wallet.filter, function(block, txs) {
      total += txs.length;
      return Promise.resolve();
    });

    assert.equal(total, 226);
  }));

  it('should activate csv', co(function* () {
    var deployments = network.deployments;
    var i, block, prev, state, cache;

    miner.options.version = -1;

    assert.equal(chain.height, 214);

    prev = yield chain.tip.getPrevious();
    state = yield chain.getState(prev, deployments.csv);
    assert.equal(state, 1);

    for (i = 0; i < 417; i++) {
      block = yield miner.mineBlock();
      yield chain.add(block);
      switch (chain.height) {
        case 288:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert.equal(state, 1);
          break;
        case 432:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert.equal(state, 2);
          break;
        case 576:
          prev = yield chain.tip.getPrevious();
          state = yield chain.getState(prev, deployments.csv);
          assert.equal(state, 3);
          break;
      }
    }

    assert.equal(chain.height, 631);
    assert(chain.state.hasCSV());
    assert(chain.state.hasWitness());

    cache = yield chain.db.getStateCache();
    assert.deepEqual(cache, chain.db.stateCache);
    assert.equal(chain.db.stateCache.updates.length, 0);
    assert(yield chain.db.verifyDeployments());
  }));

  it('should have activated segwit', co(function* () {
    var deployments = network.deployments;
    var prev = yield chain.tip.getPrevious();
    var state = yield chain.getState(prev, deployments.segwit);
    assert.equal(state, 3);
  }));

  it('should test csv', co(function* () {
    var tx = (yield chain.db.getBlock(chain.height - 100)).txs[0];
    var block = yield mineCSV(tx);
    var csv, attempt, rtx;

    yield chain.add(block);

    csv = block.txs[1];

    rtx = new MTX();

    rtx.addOutput({
      script: [
        Script.array(new BN(2)),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10000
    });

    rtx.addTX(csv, 0);
    rtx.setSequence(0, 1, false);

    attempt = yield miner.createBlock();

    attempt.addTX(rtx.toTX(), rtx.view);

    block = yield attempt.mineAsync();

    yield chain.add(block);
  }));

  it('should fail csv with bad sequence', co(function* () {
    var csv = (yield chain.db.getBlock(chain.height - 100)).txs[0];
    var rtx = new MTX();
    var attempt;

    rtx.addOutput({
      script: [
        Script.array(new BN(1)),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 10 * 1e8
    });

    rtx.addTX(csv, 0);
    rtx.setSequence(0, 1, false);

    attempt = yield miner.createBlock();
    attempt.addTX(rtx.toTX(), rtx.view);

    assert(yield addBlock(attempt), 'mandatory-script-verify-flag-failed');
  }));

  it('should mine a block', co(function* () {
    var block = yield miner.mineBlock();
    assert(block);
    yield chain.add(block);
  }));

  it('should fail csv lock checks', co(function* () {
    var tx = (yield chain.db.getBlock(chain.height - 100)).txs[0];
    var block = yield mineCSV(tx);
    var csv, attempt, rtx;

    yield chain.add(block);

    csv = block.txs[1];

    rtx = new MTX();

    rtx.addOutput({
      script: [
        Script.array(new BN(2)),
        Script.opcodes.OP_CHECKSEQUENCEVERIFY
      ],
      value: 1 * 1e8
    });

    rtx.addTX(csv, 0);
    rtx.setSequence(0, 2, false);

    attempt = yield miner.createBlock();
    attempt.addTX(rtx.toTX(), rtx.view);

    assert.equal(yield addBlock(attempt), 'bad-txns-nonfinal');
  }));

  it('should have correct wallet balance', co(function* () {
    assert.equal(wallet.balance, 1412499980000);
  }));

  it('should fail to connect bad bits', co(function* () {
    var attempt = yield miner.createBlock();
    attempt.block.bits = 553713663;
    assert.equal(yield addBlock(attempt), 'bad-diffbits');
  }));

  it('should fail to connect bad MTP', co(function* () {
    var mtp = yield chain.tip.getMedianTimeAsync();
    var attempt = yield miner.createBlock();
    attempt.block.ts = mtp - 1;
    assert.equal(yield addBlock(attempt), 'time-too-old');
  }));

  it('should fail to connect bad time', co(function* () {
    var attempt = yield miner.createBlock();
    var now = network.now() + 3 * 60 * 60;
    attempt.block.ts = now;
    assert.equal(yield addBlock(attempt), 'time-too-new');
  }));

  it('should fail to connect bad locktime', co(function* () {
    var attempt = yield miner.createBlock();
    var tx = yield wallet.send({ locktime: 100000 });
    attempt.block.txs.push(tx.toTX());
    attempt.refresh();
    assert.equal(yield addBlock(attempt), 'bad-txns-nonfinal');
  }));

  it('should fail to connect bad cb height', co(function* () {
    var bip34height = network.block.bip34height;
    var attempt = yield miner.createBlock();
    var tx = attempt.block.txs[0];
    var input = tx.inputs[0];

    input.script.set(0, new BN(10));
    input.script.compile();
    attempt.refresh();

    try {
      network.block.bip34height = 0;
      assert.equal(yield addBlock(attempt), 'bad-cb-height');
    } finally {
      network.block.bip34height = bip34height;
    }
  }));

  it('should fail to connect bad witness nonce size', co(function* () {
    var attempt = yield miner.createBlock();
    var tx = attempt.block.txs[0];
    var input = tx.inputs[0];
    input.witness.set(0, new Buffer(33));
    input.witness.compile();
    assert.equal(yield addBlock(attempt), 'bad-witness-merkle-size');
  }));

  it('should fail to connect bad witness nonce', co(function* () {
    var attempt = yield miner.createBlock();
    var tx = attempt.block.txs[0];
    var input = tx.inputs[0];
    input.witness.set(0, encoding.ONE_HASH);
    input.witness.compile();
    assert.equal(yield addBlock(attempt), 'bad-witness-merkle-match');
  }));

  it('should fail to connect bad witness commitment', co(function* () {
    var attempt = yield miner.createBlock();
    var tx = attempt.block.txs[0];
    var output = tx.outputs[1];
    var commit;

    assert(output.script.isCommitment());

    commit = util.copy(output.script.get(1));
    commit.fill(0, 10);
    output.script.set(1, commit);
    output.script.compile();

    attempt.updateMerkle();
    assert.equal(yield addBlock(attempt), 'bad-witness-merkle-match');
  }));

  it('should fail to connect unexpected witness', co(function* () {
    var attempt = yield miner.createBlock();
    var tx = attempt.block.txs[0];
    var output = tx.outputs[1];
    assert(output.script.isCommitment());
    tx.outputs.pop();
    attempt.updateMerkle();
    assert.equal(yield addBlock(attempt), 'unexpected-witness');
  }));

  it('should add wit addrs to miner', co(function* () {
    miner.addresses.length = 0;
    miner.addAddress(wwallet.getReceive());
    assert.equal(wwallet.getReceive().getType(), 'witnesspubkeyhash');
  }));

  it('should mine 2000 witness blocks', co(function* () {
    var i, block;

    for (i = 0; i < 2001; i++) {
      block = yield miner.mineBlock();
      assert(block);
      yield chain.add(block);
    }

    assert.equal(chain.height, 2636);
  }));

  it('should mine a witness tx', co(function* () {
    var block = yield chain.db.getBlock(chain.height - 2000);
    var cb = block.txs[0];
    var mtx = new MTX();
    var attempt;

    mtx.addTX(cb, 0);
    mtx.addOutput(wwallet.getAddress(), 1000);

    wwallet.sign(mtx);

    attempt = yield miner.createBlock();
    attempt.addTX(mtx.toTX(), mtx.view);

    block = yield attempt.mineAsync();

    yield chain.add(block);
  }));

  it('should mine fail to connect too much weight', co(function* () {
    var start = chain.height - 2000;
    var end = chain.height - 200;
    var attempt = yield miner.createBlock();
    var mtx = new MTX();
    var i, j, block, cb;

    for (i = start; i <= end; i++) {
      block = yield chain.db.getBlock(i);
      cb = block.txs[0];

      mtx = new MTX();
      mtx.addTX(cb, 0);

      for (j = 0; j < 16; j++)
        mtx.addOutput(wwallet.getAddress(), 1);

      wwallet.sign(mtx);

      attempt.block.txs.push(mtx.toTX());
    }

    attempt.refresh();

    assert.equal(yield addBlock(attempt), 'bad-blk-weight');
  }));

  it('should mine fail to connect too much size', co(function* () {
    var start = chain.height - 2000;
    var end = chain.height - 200;
    var attempt = yield miner.createBlock();
    var mtx = new MTX();
    var i, j, block, cb;

    for (i = start; i <= end; i++) {
      block = yield chain.db.getBlock(i);
      cb = block.txs[0];

      mtx = new MTX();
      mtx.addTX(cb, 0);

      for (j = 0; j < 20; j++)
        mtx.addOutput(wwallet.getAddress(), 1);

      wwallet.sign(mtx);

      attempt.block.txs.push(mtx.toTX());
    }

    attempt.refresh();

    assert.equal(yield addBlock(attempt), 'bad-blk-length');
  }));

  it('should mine a big block', co(function* () {
    var start = chain.height - 2000;
    var end = chain.height - 200;
    var attempt = yield miner.createBlock();
    var mtx = new MTX();
    var i, j, block, cb;

    for (i = start; i <= end; i++) {
      block = yield chain.db.getBlock(i);
      cb = block.txs[0];

      mtx = new MTX();
      mtx.addTX(cb, 0);

      for (j = 0; j < 15; j++)
        mtx.addOutput(wwallet.getAddress(), 1);

      wwallet.sign(mtx);

      attempt.block.txs.push(mtx.toTX());
    }

    attempt.refresh();

    assert.equal(yield addBlock(attempt), 'OK');
  }));

  it('should fail to connect bad versions', co(function* () {
    var i, attempt;

    for (i = 0; i <= 3; i++) {
      attempt = yield miner.createBlock();
      attempt.block.version = i;
      assert.equal(yield addBlock(attempt), 'bad-version');
    }
  }));

  it('should fail to connect bad amount', co(function* () {
    var attempt = yield miner.createBlock();

    attempt.block.txs[0].outputs[0].value += 1;
    attempt.updateMerkle();
    assert.equal(yield addBlock(attempt), 'bad-cb-amount');
  }));

  it('should fail to connect premature cb spend', co(function* () {
    var attempt = yield miner.createBlock();
    var block = yield chain.db.getBlock(chain.height - 98);
    var cb = block.txs[0];
    var mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(wwallet.getAddress(), 1);

    wwallet.sign(mtx);

    attempt.addTX(mtx.toTX(), mtx.view);

    assert.equal(yield addBlock(attempt),
      'bad-txns-premature-spend-of-coinbase');
  }));

  it('should fail to connect vout belowout', co(function* () {
    var attempt = yield miner.createBlock();
    var block = yield chain.db.getBlock(chain.height - 99);
    var cb = block.txs[0];
    var mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(wwallet.getAddress(), 1e8);

    wwallet.sign(mtx);

    attempt.block.txs.push(mtx.toTX());
    attempt.refresh();

    assert.equal(yield addBlock(attempt),
      'bad-txns-in-belowout');
  }));

  it('should fail to connect outtotal toolarge', co(function* () {
    var attempt = yield miner.createBlock();
    var block = yield chain.db.getBlock(chain.height - 99);
    var cb = block.txs[0];
    var mtx = new MTX();

    mtx.addTX(cb, 0);
    mtx.addOutput(wwallet.getAddress(), Math.floor(consensus.MAX_MONEY / 2));
    mtx.addOutput(wwallet.getAddress(), Math.floor(consensus.MAX_MONEY / 2));
    mtx.addOutput(wwallet.getAddress(), Math.floor(consensus.MAX_MONEY / 2));

    wwallet.sign(mtx);

    attempt.block.txs.push(mtx.toTX());
    attempt.refresh();

    assert.equal(yield addBlock(attempt),
      'bad-txns-txouttotal-toolarge');
  }));

  it('should mine 111 multisig blocks', co(function* () {
    var i, j, script, attempt, cb, output, val, block;

    script = new Script();
    script.push(new BN(20));

    for (i = 0; i < 20; i++)
      script.push(encoding.ZERO_KEY);

    script.push(new BN(20));
    script.push(opcodes.OP_CHECKMULTISIG);
    script.compile();

    script = Script.fromScripthash(script.hash160());

    for (i = 0; i < 111; i++) {
      attempt = yield miner.createBlock();
      cb = attempt.block.txs[0];
      val = cb.outputs[0].value;

      cb.outputs[0].value = 0;

      for (j = 0; j < Math.min(100, val); j++) {
        output = new Output();
        output.script = script.clone();
        output.value = 1;

        cb.outputs.push(output);
      }

      attempt.updateMerkle();

      block = yield attempt.mineAsync();
      yield chain.add(block);
    }

    assert.equal(chain.height, 2749);
  }));

  it('should fail to connect too many sigops', co(function* () {
    var start = chain.height - 110;
    var end = chain.height - 100;
    var attempt = yield miner.createBlock();
    var i, j, mtx, script, block, cb;

    script = new Script();
    script.push(new BN(20));

    for (i = 0; i < 20; i++)
      script.push(encoding.ZERO_KEY);

    script.push(new BN(20));
    script.push(opcodes.OP_CHECKMULTISIG);
    script.compile();

    for (i = start; i <= end; i++) {
      block = yield chain.db.getBlock(i);
      cb = block.txs[0];

      if (cb.outputs.length === 2)
        continue;

      mtx = new MTX();

      for (j = 2; j < cb.outputs.length; j++) {
        mtx.addTX(cb, j);
        mtx.inputs[j - 2].script = new Script([script.toRaw()]);
      }

      mtx.addOutput(wwallet.getAddress(), 1);

      attempt.block.txs.push(mtx.toTX());
    }

    attempt.refresh();

    assert.equal(yield addBlock(attempt), 'bad-blk-sigops');
  }));

  it('should cleanup', co(function* () {
    yield miner.close();
    yield chain.close();
  }));
});

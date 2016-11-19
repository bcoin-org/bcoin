'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var util = bcoin.util;
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var opcodes = constants.opcodes;
var cob = require('../lib/utils/co').cob;

function dummy(prev, prevHash) {
  if (!prevHash)
    prevHash = constants.ONE_HASH.toString('hex');

  return {
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
    script: new bcoin.script(),
    sequence: 0xffffffff
  };
}

describe('Mempool', function() {
  var chain, mempool, walletdb;
  var wallet, cached;

  this.timeout(5000);

  chain = new bcoin.chain({
    name: 'mp-chain',
    db: 'memory'
  });

  mempool = new bcoin.mempool({
    chain: chain,
    name: 'mempool-test',
    db: 'memory'
  });

  walletdb = new bcoin.walletdb({
    name: 'mempool-wallet-test',
    db: 'memory',
    verify: true
  });

  it('should open mempool', cob(function* () {
    yield mempool.open();
    chain.state.flags |= constants.flags.VERIFY_WITNESS;
  }));

  it('should open walletdb', cob(function* () {
    yield walletdb.open();
  }));

  it('should open wallet', cob(function* () {
    wallet = yield walletdb.create();
  }));

  it('should handle incoming orphans and TXs', cob(function* () {
    var kp = bcoin.keyring.generate();
    var w = wallet;
    var t1, t2, t3, t4, f1, fake, prev, sig, balance, txs;

    t1 = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    t1.addInput(dummy(prev));
    sig = t1.signature(0, prev, kp.privateKey, 'all', 0);
    t1.inputs[0].script = new bcoin.script([sig]),

    // balance: 51000
    yield w.sign(t1);
    t1 = t1.toTX();

    t2 = bcoin.mtx()
      .addInput(t1, 0) // 50000
      .addOutput(w.getAddress(), 20000)
      .addOutput(w.getAddress(), 20000);

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();

    t3 = bcoin.mtx()
      .addInput(t1, 1) // 10000
      .addInput(t2, 0) // 20000
      .addOutput(w.getAddress(), 23000);

    // balance: 47000
    yield w.sign(t3);
    t3 = t3.toTX();

    t4 = bcoin.mtx()
      .addInput(t2, 1) // 24000
      .addInput(t3, 0) // 23000
      .addOutput(w.getAddress(), 11000)
      .addOutput(w.getAddress(), 11000);

    // balance: 22000
    yield w.sign(t4);
    t4 = t4.toTX();

    f1 = bcoin.mtx()
      .addInput(t4, 1) // 11000
      .addOutput(new bcoin.address(), 9000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    fake = bcoin.mtx()
      .addInput(t1, 1) // 1000 (already redeemed)
      .addOutput(w.getAddress(), 6000); // 6000 instead of 500

    // Script inputs but do not sign
    yield w.template(fake);

    // Fake signature
    fake.inputs[0].script.set(0, constants.ZERO_SIG);
    fake.inputs[0].script.compile();
    fake = fake.toTX();
    // balance: 11000

    [t2, t3, t4, f1, fake].forEach(function(tx) {
      tx.inputs.forEach(function(input) {
        input.coin = null;
      });
    });

    yield mempool.addTX(fake);
    yield mempool.addTX(t4);

    balance = mempool.getBalance();
    assert.equal(balance, 0);

    yield mempool.addTX(t1);

    balance = mempool.getBalance();
    assert.equal(balance, 60000);

    yield mempool.addTX(t2);

    balance = mempool.getBalance();
    assert.equal(balance, 50000);

    yield mempool.addTX(t3);

    balance = mempool.getBalance();
    assert.equal(balance, 22000);

    yield mempool.addTX(f1);

    balance = mempool.getBalance();
    assert.equal(balance, 20000);

    txs = mempool.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));
  }));

  it('should handle locktime', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, sig;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));
    tx.setLocktime(200);

    chain.tip.height = 200;

    sig = tx.signature(0, prev, kp.privateKey, 'all', 0);
    tx.inputs[0].script = new bcoin.script([sig]),

    tx = tx.toTX();

    yield mempool.addTX(tx);
    chain.tip.height = 0;
  }));

  it('should handle invalid locktime', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, sig, err;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));
    tx.setLocktime(200);
    chain.tip.height = 200 - 1;

    sig = tx.signature(0, prev, kp.privateKey, 'all', 0);
    tx.inputs[0].script = new bcoin.script([sig]),
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);

    chain.tip.height = 0;
  }));

  it('should not cache a malleated wtx with mutated sig', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, prevs, sig, tx, err;

    kp.witness = true;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([0, kp.keyHash]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));

    prevs = bcoin.script.fromPubkeyhash(kp.keyHash);

    sig = tx.signature(0, prevs, kp.privateKey, 'all', 1);
    sig[sig.length - 1] = 0;
    tx.inputs[0].witness = new bcoin.witness([sig, kp.publicKey]);
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should not cache a malleated tx with unnecessary witness', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, sig, tx, err;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));

    sig = tx.signature(0, prev, kp.privateKey, 'all', 0);
    tx.inputs[0].script = new bcoin.script([sig]);
    tx.inputs[0].witness.push(new Buffer(0));
    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should not cache a malleated wtx with wit removed', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, tx, err;

    kp.witness = true;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([0, kp.keyHash]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));

    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(err.malleated);
    assert(!mempool.hasReject(tx.hash()));
  }));

  it('should cache non-malleated tx without sig', cob(function* () {
    var w = wallet;
    var kp = bcoin.keyring.generate();
    var tx, prev, prevHash, tx, err;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 10000);

    prev = new bcoin.script([kp.publicKey, opcodes.OP_CHECKSIG]);
    prevHash = crypto.randomBytes(32).toString('hex');

    tx.addInput(dummy(prev, prevHash));

    tx = tx.toTX();

    try {
      yield mempool.addTX(tx);
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!err.malleated);
    assert(mempool.hasReject(tx.hash()));
    cached = tx;
  }));

  it('should clear reject cache', cob(function* () {
    var w = wallet;
    var tx, input, tx, block;

    tx = bcoin.mtx()
      .addOutput(w.getAddress(), 50000);

    input = {
      prevout: {
        hash: constants.NULL_HASH,
        index: 0xffffffff
      },
      coin: null,
      script: new bcoin.script(),
      sequence: 0xffffffff
    };

    tx.addInput(input);

    tx = tx.toTX();

    block = new bcoin.block();
    block.txs.push(tx);

    assert(mempool.hasReject(cached.hash()));
    yield mempool.addBlock(block);
    assert(!mempool.hasReject(cached.hash()));
  }));

  it('should destroy mempool', cob(function* () {
    yield mempool.close();
  }));
});

'use strict';

var BN = require('bn.js');
var bcoin = require('../').set('main');
var constants = bcoin.constants;
var network = bcoin.networks;
var util = bcoin.util;
var encoding = require('../lib/utils/encoding');
var crypto = require('../lib/crypto/crypto');
var assert = require('assert');
var scriptTypes = constants.scriptTypes;
var co = require('../lib/utils/co');
var cob = co.cob;

var KEY1 = 'xprv9s21ZrQH143K3Aj6xQBymM31Zb4BVc7wxqfUhMZrzewdDVCt'
  + 'qUP9iWfcHgJofs25xbaUpCps9GDXj83NiWvQCAkWQhVj5J4CorfnpKX94AZ';

var KEY2 = 'xprv9s21ZrQH143K3mqiSThzPtWAabQ22Pjp3uSNnZ53A5bQ4udp'
  + 'faKekc2m4AChLYH1XDzANhrSdxHYWUeTWjYJwFwWFyHkTMnMeAcW4JyRCZa';

var globalHeight = 1;
var globalTime = util.now();

function nextBlock(height) {
  var hash, prev;

  if (height == null)
    height = globalHeight++;

  hash = crypto.hash256(encoding.U32(height)).toString('hex');
  prev = crypto.hash256(encoding.U32(height - 1)).toString('hex');

  return {
    hash: hash,
    height: height,
    prevBlock: prev,
    ts: globalTime + height,
    merkleRoot: constants.NULL_HASH,
    nonce: 0,
    bits: 0
  };
}

function dummy(hash) {
  hash = hash || crypto.randomBytes(32).toString('hex');
  return {
    prevout: {
      hash: hash,
      index: 0
    },
    coin: {
      version: 1,
      height: 0,
      value: constants.MAX_MONEY,
      script: new bcoin.script(),
      coinbase: false,
      hash: hash,
      index: 0
    },
    script: new bcoin.script(),
    witness: new bcoin.witness(),
    sequence: 0xffffffff
  };
}

describe('Wallet', function() {
  var walletdb, wallet, ewallet, ekey, doubleSpendWallet, doubleSpend;

  walletdb = new bcoin.walletdb({
    name: 'wallet-test',
    db: 'memory',
    resolution: true,
    verify: true
  });

  this.timeout(5000);

  it('should open walletdb', cob(function* () {
    constants.tx.COINBASE_MATURITY = 0;
    yield walletdb.open();
  }));

  it('should generate new key and address', cob(function* () {
    var w = yield walletdb.create();
    var addr = w.getAddress('base58');
    assert(addr);
    assert(bcoin.address.validate(addr));
  }));

  it('should validate existing address', function() {
    assert(bcoin.address.validate('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert(!bcoin.address.validate('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc'));
  });

  it('should create and get wallet', cob(function* () {
    var w1, w2;

    w1 = yield walletdb.create();
    yield w1.destroy();

    w2 = yield walletdb.get(w1.id);

    assert(w1 !== w2);
    assert(w1.master !== w2.master);
    assert.equal(w1.master.key.xprivkey, w2.master.key.xprivkey);
    assert.equal(w1.account.accountKey.xpubkey, w2.account.accountKey.xpubkey);
  }));

  var p2pkh = co(function* p2pkh(witness, bullshitNesting) {
    var flags = bcoin.constants.flags.STANDARD_VERIFY_FLAGS;
    var w, addr, src, tx;

    if (witness)
      flags |= bcoin.constants.flags.VERIFY_WITNESS;

    w = yield walletdb.create({ witness: witness });

    addr = bcoin.address.fromBase58(w.getAddress('base58'));

    if (witness)
      assert.equal(addr.type, scriptTypes.WITNESSPUBKEYHASH);
    else
      assert.equal(addr.type, scriptTypes.PUBKEYHASH);

    src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        address: bullshitNesting
          ? w.getNestedAddress()
          : w.getAddress()
      }, {
        value: 5460 * 2,
        address: new bcoin.address()
      }]
    });

    src.addInput(dummy());

    tx = bcoin.mtx()
      .addInput(src, 0)
      .addOutput(w.getAddress(), 5460);

    yield w.sign(tx);

    assert(tx.verify(flags));
  });

  it('should sign/verify pubkeyhash tx', cob(function* () {
    yield p2pkh(false, false);
  }));

  it('should sign/verify witnesspubkeyhash tx', cob(function* () {
    yield p2pkh(true, false);
  }));

  it('should sign/verify witnesspubkeyhash tx with bullshit nesting', cob(function* () {
    yield p2pkh(true, true);
  }));

  it('should multisign/verify TX', cob(function* () {
    var w, k, keys, src, tx, maxSize;

    w = yield walletdb.create({
      type: 'multisig',
      m: 1,
      n: 2
    });

    k = bcoin.hd.fromMnemonic().deriveAccount44(0).hdPublicKey;

    yield w.addSharedKey(k);

    keys = [
      w.getPublicKey(),
      k.derive('m/0/0').publicKey
    ];

    // Input transaction (bare 1-of-2 multisig)
    src = bcoin.mtx({
      outputs: [{
        value: 5460 * 2,
        script: bcoin.script.fromMultisig(1, 2, keys)
      }, {
        value: 5460 * 2,
        address: new bcoin.address()
      }]
    });

    src.addInput(dummy());

    tx = bcoin.mtx()
      .addInput(src, 0)
      .addOutput(w.getAddress(), 5460);

    maxSize = tx.maxSize();

    yield w.sign(tx);

    assert(tx.toRaw().length <= maxSize);
    assert(tx.verify());
  }));

  it('should handle missed and invalid txs', cob(function* () {
    var w = yield walletdb.create();
    var f = yield walletdb.create();
    var t1, t2, t3, t4, f1, fake, balance, txs;

    doubleSpendWallet = w;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 1000);
    t1.addInput(dummy());
    t1.ts = util.now();

    // balance: 51000
    yield w.sign(t1);
    t1 = t1.toTX();

    t2 = bcoin.mtx()
      .addInput(t1, 0) // 50000
      .addOutput(w.getAddress(), 24000)
      .addOutput(w.getAddress(), 24000);

    doubleSpend = t2.inputs[0];

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();
    t3 = bcoin.mtx()
      .addInput(t1, 1) // 1000
      .addInput(t2, 0) // 24000
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
      .addOutput(f.getAddress(), 10000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    fake = bcoin.mtx()
      .addInput(t1, 1) // 1000 (already redeemed)
      .addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    yield w.template(fake);
    // Fake signature
    fake.inputs[0].script.set(0, constants.ZERO_SIG);
    fake.inputs[0].script.compile();
    // balance: 11000
    fake = fake.toTX();

    // Fake TX should temporarly change output
    yield walletdb.addTX(fake);

    yield walletdb.addTX(t4);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 22500);
    assert.equal(balance.unconfirmed, 0);

    yield walletdb.addTX(t1);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 73000);
    assert.equal(balance.unconfirmed, 51000);

    yield walletdb.addTX(t2);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 47000);
    assert.equal(balance.unconfirmed, 49000);

    yield walletdb.addTX(t3);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    yield walletdb.addTX(f1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    txs = yield w.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));

    balance = yield f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = yield f.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));
  }));

  it('should cleanup spenders after double-spend', cob(function* () {
    var w = doubleSpendWallet;
    var tx, txs, total, balance;

    tx = bcoin.mtx().addOutput(w.getAddress(), 5000);
    tx.addInput(doubleSpend.coin);

    txs = yield w.getHistory();
    assert.equal(txs.length, 5);
    total = txs.reduce(function(t, tx) {
      return t + tx.getOutputValue();
    }, 0);

    assert.equal(total, 154000);

    yield w.sign(tx);
    tx = tx.toTX();

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    yield walletdb.addTX(tx);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 6000);

    txs = yield w.getHistory();
    assert.equal(txs.length, 2);

    total = txs.reduce(function(t, tx) {
      return t + tx.getOutputValue();
    }, 0);
    assert.equal(total, 56000);
  }));

  it('should handle missed txs without resolution', cob(function* () {
    var walletdb, w, f, t1, t2, t3, t4, f1, fake, balance, txs;

    walletdb = new bcoin.walletdb({
      name: 'wallet-test',
      db: 'memory',
      resolution: false,
      verify: false
    });

    yield walletdb.open();

    w = yield walletdb.create();
    f = yield walletdb.create();

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w.getAddress(), 50000)
      .addOutput(w.getAddress(), 1000);
    t1.addInput(dummy());

    // balance: 51000
    yield w.sign(t1);
    t1 = t1.toTX();

    t2 = bcoin.mtx()
      .addInput(t1, 0) // 50000
      .addOutput(w.getAddress(), 24000)
      .addOutput(w.getAddress(), 24000);

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();
    t3 = bcoin.mtx()
      .addInput(t1, 1) // 1000
      .addInput(t2, 0) // 24000
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
      .addOutput(f.getAddress(), 10000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    // fake = bcoin.mtx()
    //   .addInput(t1, 1) // 1000 (already redeemed)
    //   .addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    // yield w.template(fake);
    // Fake signature
    // fake.inputs[0].script.set(0, constants.ZERO_SIG);
    // fake.inputs[0].script.compile();
    // balance: 11000
    // fake = fake.toTX();

    // Fake TX should temporarly change output
    // yield walletdb.addTX(fake);

    yield walletdb.addTX(t4);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    yield walletdb.addTX(t1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 73000);

    yield walletdb.addTX(t2);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 71000);
    assert.equal(balance.unconfirmed, 47000);

    yield walletdb.addTX(t3);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 69000);
    assert.equal(balance.unconfirmed, 22000);

    yield walletdb.addTX(f1);

    balance = yield w.getBalance();
    //assert.equal(balance.unconfirmed, 58000);
    assert.equal(balance.unconfirmed, 11000);

    txs = yield w.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));

    balance = yield f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = yield f.getHistory();
    assert(txs.some(function(tx) {
      return tx.hash('hex') === f1.hash('hex');
    }));

    yield walletdb.addTX(t2);

    yield walletdb.addTX(t3);

    yield walletdb.addTX(t4);

    yield walletdb.addTX(f1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    balance = yield f.getBalance();
    assert.equal(balance.unconfirmed, 10000);
  }));

  it('should fill tx with inputs', cob(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var t1, t2, t3, err;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = bcoin.mtx().addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000, round: true });
    yield w1.sign(t2);
    t2 = t2.toTX();

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 16380);
    assert.equal(t2.getOutputValue(), 5460);
    assert.equal(t2.getFee(), 10920);

    // Create new transaction
    t3 = bcoin.mtx().addOutput(w2.getAddress(), 15000);

    try {
      yield w1.fund(t3, { rate: 10000, round: true });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.requiredFunds, 25000);
  }));

  it('should fill tx with inputs with accurate fee', cob(function* () {
    var w1 = yield walletdb.create({ master: KEY1 });
    var w2 = yield walletdb.create({ master: KEY2 });
    var t1, t2, t3, balance, err;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460);

    t1.addInput(dummy(constants.NULL_HASH));
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = bcoin.mtx().addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000 });

    yield w1.sign(t2);
    t2 = t2.toTX();
    assert(t2.verify());

    assert.equal(t2.getInputValue(), 16380);

    // Should now have a change output:
    assert.equal(t2.getOutputValue(), 11130);

    assert.equal(t2.getFee(), 5250);

    assert.equal(t2.getWeight(), 2084);
    assert.equal(t2.getBaseSize(), 521);
    assert.equal(t2.getSize(), 521);
    assert.equal(t2.getVirtualSize(), 521);

    w2.once('balance', function(b) {
      balance = b;
    });

    yield walletdb.addTX(t2);

    // Create new transaction
    t3 = bcoin.mtx().addOutput(w2.getAddress(), 15000);

    try {
      yield w1.fund(t3, { rate: 10000 });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(balance);
    assert(balance.unconfirmed === 5460);
  }));

  it('should sign multiple inputs using different keys', cob(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var to = yield walletdb.create();
    var t1, t2, tx, cost, total, coins1, coins2, left;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    // Coinbase
    t2 = bcoin.mtx()
      .addOutput(w2.getAddress(), 5460)
      .addOutput(w2.getAddress(), 5460)
      .addOutput(w2.getAddress(), 5460)
      .addOutput(w2.getAddress(), 5460);

    t2.addInput(dummy());
    t2 = t2.toTX();

    yield walletdb.addTX(t1);
    yield walletdb.addTX(t2);

    // Create our tx with an output
    tx = bcoin.mtx();
    tx.addOutput(to.getAddress(), 5460);

    cost = tx.getOutputValue();
    total = cost * constants.tx.MIN_FEE;

    coins1 = yield w1.getCoins();
    coins2 = yield w2.getCoins();

    // Add dummy output (for `left`) to calculate maximum TX size
    tx.addOutput(w1.getAddress(), 0);

    // Add our unspent inputs to sign
    tx.addInput(coins1[0]);
    tx.addInput(coins1[1]);
    tx.addInput(coins2[0]);

    left = tx.getInputValue() - total;
    if (left < constants.tx.DUST_THRESHOLD) {
      tx.outputs[tx.outputs.length - 2].value += left;
      left = 0;
    }
    if (left === 0)
      tx.outputs.pop();
    else
      tx.outputs[tx.outputs.length - 1].value = left;

    // Sign transaction
    total = yield w1.sign(tx);
    assert.equal(total, 2);

    total = yield w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);

    // Sign transaction using `inputs` and `off` params.
    tx.inputs.length = 0;
    tx.addInput(coins1[1]);
    tx.addInput(coins1[2]);
    tx.addInput(coins2[1]);

    total = yield w1.sign(tx);
    assert.equal(total, 2);

    total = yield w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);
  }));

  var multisig = co(function* multisig(witness, bullshitNesting, cb) {
    var flags = bcoin.constants.flags.STANDARD_VERIFY_FLAGS;
    var options, w1, w2, w3, receive, b58, addr, paddr, utx, send, change;

    var rec = bullshitNesting ? 'nested' : 'receive';
    var depth = bullshitNesting ? 'nestedDepth' : 'receiveDepth';

    if (witness)
      flags |= bcoin.constants.flags.VERIFY_WITNESS;

    // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
    options = {
      witness: witness,
      type: 'multisig',
      m: 2,
      n: 3
    };

    w1 = yield walletdb.create(options);
    w2 = yield walletdb.create(options);
    w3 = yield walletdb.create(options);
    receive = yield walletdb.create();

    yield w1.addSharedKey(w2.accountKey);
    yield w1.addSharedKey(w3.accountKey);
    yield w2.addSharedKey(w1.accountKey);
    yield w2.addSharedKey(w3.accountKey);
    yield w3.addSharedKey(w1.accountKey);
    yield w3.addSharedKey(w2.accountKey);

    // Our p2sh address
    b58 = w1[rec].getAddress('base58');
    addr = bcoin.address.fromBase58(b58);

    if (witness) {
      if (bullshitNesting)
        assert.equal(addr.type, scriptTypes.SCRIPTHASH);
      else
        assert.equal(addr.type, scriptTypes.WITNESSSCRIPTHASH);
    } else {
      assert.equal(addr.type, scriptTypes.SCRIPTHASH);
    }

    assert.equal(w1[rec].getAddress('base58'), b58);
    assert.equal(w2[rec].getAddress('base58'), b58);
    assert.equal(w3[rec].getAddress('base58'), b58);

    paddr = w1.getNestedAddress('base58');
    assert.equal(w1.getNestedAddress('base58'), paddr);
    assert.equal(w2.getNestedAddress('base58'), paddr);
    assert.equal(w3.getNestedAddress('base58'), paddr);

    // Add a shared unspent transaction to our wallets
    utx = bcoin.mtx();
    if (bullshitNesting)
      utx.addOutput({ address: paddr, value: 5460 * 10 });
    else
      utx.addOutput({ address: addr, value: 5460 * 10 });

    utx.addInput(dummy());
    utx = utx.toTX();

    // Simulate a confirmation
    var block = nextBlock();
    utx.height = block.height;
    utx.block = block.hash;
    utx.ts = block.ts;
    utx.index = 0;

    assert.equal(w1[depth], 1);

    yield walletdb.addBlock(block, [utx]);

    assert.equal(w1[depth], 2);

    assert.equal(w1.changeDepth, 1);

    assert(w1[rec].getAddress('base58') !== b58);
    b58 = w1[rec].getAddress('base58');
    assert.equal(w1[rec].getAddress('base58'), b58);
    assert.equal(w2[rec].getAddress('base58'), b58);
    assert.equal(w3[rec].getAddress('base58'), b58);

    // Create a tx requiring 2 signatures
    send = bcoin.mtx();
    send.addOutput({ address: receive.getAddress(), value: 5460 });
    assert(!send.verify(flags));
    yield w1.fund(send, { rate: 10000, round: true });

    yield w1.sign(send);

    assert(!send.verify(flags));

    yield w2.sign(send);

    send = send.toTX();
    assert(send.verify(flags));

    assert.equal(w1.changeDepth, 1);

    change = w1.change.getAddress('base58');
    assert.equal(w1.change.getAddress('base58'), change);
    assert.equal(w2.change.getAddress('base58'), change);
    assert.equal(w3.change.getAddress('base58'), change);

    // Simulate a confirmation
    var block = nextBlock();
    send.height = block.height;
    send.block = block.hash;
    send.ts = block.ts;
    send.index = 0;

    yield walletdb.addBlock(block, [send]);

    assert.equal(w1[depth], 2);
    assert.equal(w1.changeDepth, 2);

    assert(w1[rec].getAddress('base58') === b58);
    assert(w1.change.getAddress('base58') !== change);
    change = w1.change.getAddress('base58');
    assert.equal(w1.change.getAddress('base58'), change);
    assert.equal(w2.change.getAddress('base58'), change);
    assert.equal(w3.change.getAddress('base58'), change);

    if (witness) {
      send.inputs[0].witness.set(2, 0);
    } else {
      send.inputs[0].script.set(2, 0);
      send.inputs[0].script.compile();
    }

    assert(!send.verify(flags));
    assert.equal(send.getFee(), 10000);
  });

  it('should verify 2-of-3 scripthash tx', cob(function* () {
    yield multisig(false, false);
  }));

  it('should verify 2-of-3 witnessscripthash tx', cob(function* () {
    yield multisig(true, false);
  }));

  it('should verify 2-of-3 witnessscripthash tx with bullshit nesting', cob(function* () {
    yield multisig(true, true);
  }));

  it('should fill tx with account 1', cob(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var account, accounts, rec, t1, t2, t3, err;

    account = yield w1.createAccount({ name: 'foo' });
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);

    account = yield w1.getAccount('foo');
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);
    rec = account.receive;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(rec.getAddress(), 5460)
      .addOutput(rec.getAddress(), 5460)
      .addOutput(rec.getAddress(), 5460)
      .addOutput(rec.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = bcoin.mtx().addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000, round: true });
    yield w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 16380);
    assert.equal(t2.getOutputValue(), 5460);
    assert.equal(t2.getFee(), 10920);

    // Create new transaction
    t3 = bcoin.mtx().addOutput(w2.getAddress(), 15000);

    try {
      yield w1.fund(t3, { rate: 10000, round: true });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.requiredFunds, 25000);

    accounts = yield w1.getAccounts();
    assert.deepEqual(accounts, ['default', 'foo']);
  }));

  it('should fail to fill tx with account 1', cob(function* () {
    var w = yield walletdb.create();
    var acc, account, t1, t2, err;

    wallet = w;

    acc = yield w.createAccount({ name: 'foo' });
    assert.equal(acc.name, 'foo');
    assert.equal(acc.accountIndex, 1);

    account = yield w.getAccount('foo');
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);
    assert(account.accountKey.xpubkey === acc.accountKey.xpubkey);
    assert(w.account.accountIndex === 0);

    assert.notEqual(
      account.receive.getAddress('base58'),
      w.account.receive.getAddress('base58'));

    assert.equal(w.getAddress('base58'),
      w.account.receive.getAddress('base58'));

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w.getAddress(), 5460)
      .addOutput(w.getAddress(), 5460)
      .addOutput(w.getAddress(), 5460)
      .addOutput(account.receive.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Should fill from `foo` and fail
    t2 = bcoin.mtx().addOutput(w.getAddress(), 5460);
    try {
      yield w.fund(t2, { rate: 10000, round: true, account: 'foo' });
    } catch (e) {
      err = e;
    }
    assert(err);

    // Should fill from whole wallet and succeed
    t2 = bcoin.mtx().addOutput(w.getAddress(), 5460);
    yield w.fund(t2, { rate: 10000, round: true });

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(account.receive.getAddress(), 5460)
      .addOutput(account.receive.getAddress(), 5460)
      .addOutput(account.receive.getAddress(), 5460);

    t1.ps = 0xdeadbeef;
    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    t2 = bcoin.mtx().addOutput(w.getAddress(), 5460);
    // Should fill from `foo` and succeed
    yield w.fund(t2, { rate: 10000, round: true, account: 'foo' });
  }));

  it('should create two accounts multiple encryption', cob(function* () {
    var w = yield walletdb.create({ id: 'foobar', passphrase: 'foo' });
    yield w.destroy();
    var w = yield walletdb.get('foobar');
    var account = yield w.createAccount({ name: 'foo1' }, 'foo');
    assert(account);
    yield w.lock();
  }));

  it('should fill tx with inputs when encrypted', cob(function* () {
    var w = yield walletdb.create({ passphrase: 'foo' });
    var t1, t2, err;

    w.master.stop();
    w.master.key = null;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w.getAddress(), 5460)
      .addOutput(w.getAddress(), 5460)
      .addOutput(w.getAddress(), 5460)
      .addOutput(w.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = bcoin.mtx().addOutput(w.getAddress(), 5460);
    yield w.fund(t2, { rate: 10000, round: true });

    // Should fail
    try {
      yield w.sign(t2, 'bar');
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!t2.verify());

    // Should succeed
    yield w.sign(t2, 'foo');
    assert(t2.verify());
  }));

  it('should fill tx with inputs with subtract fee', cob(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var t1, t2;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = bcoin.mtx().addOutput(w2.getAddress(), 21840);
    yield w1.fund(t2, { rate: 10000, round: true, subtractFee: true });
    yield w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 5460 * 4);
    assert.equal(t2.getOutputValue(), 21840 - 10000);
    assert.equal(t2.getFee(), 10000);
  }));

  it('should fill tx with inputs with subtract fee with create tx', cob(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var options, t1, t2;

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460)
      .addOutput(w1.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    options = {
      subtractFee: true,
      rate: 10000,
      round: true,
      outputs: [{ address: w2.getAddress(), value: 21840 }]
    };

    // Create new transaction
    t2 = yield w1.createTX(options);
    yield w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 5460 * 4);
    assert.equal(t2.getOutputValue(), 21840 - 10000);
    assert.equal(t2.getFee(), 10000);
  }));

  it('should get range of txs', cob(function* () {
    var w = wallet;
    var txs = yield w.getRange({ start: 0xdeadbeef - 1000 });
    assert.equal(txs.length, 1);
  }));

  it('should get range of txs from account', cob(function* () {
    var w = wallet;
    var txs = yield w.getRange('foo', { start: 0xdeadbeef - 1000 });
    assert.equal(txs.length, 1);
  }));

  it('should not get range of txs from non-existent account', cob(function* () {
    var w = wallet;
    var txs, err;

    try {
      txs = yield w.getRange('bad', { start: 0xdeadbeef - 1000 });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.message, 'Account not found.');
  }));

  it('should get account balance', cob(function* () {
    var w = wallet;
    var balance = yield w.getBalance('foo');
    assert.equal(balance.unconfirmed, 21840);
  }));

  it('should import privkey', cob(function* () {
    var key = bcoin.keyring.generate();
    var w = yield walletdb.create({ passphrase: 'test' });
    var options, k, t1, t2, tx;

    yield w.importKey('default', key, 'test');

    k = yield w.getKey(key.getHash('hex'));

    assert.equal(k.getHash('hex'), key.getHash('hex'));

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(key.getAddress(), 5460)
      .addOutput(key.getAddress(), 5460)
      .addOutput(key.getAddress(), 5460)
      .addOutput(key.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    tx = yield w.getTX(t1.hash('hex'));
    assert(tx);
    assert.equal(t1.hash('hex'), tx.hash('hex'));

    options = {
      rate: 10000,
      round: true,
      outputs: [{ address: w.getAddress(), value: 7000 }]
    };

    // Create new transaction
    t2 = yield w.createTX(options);
    yield w.sign(t2);
    assert(t2.verify());
    assert(t2.inputs[0].prevout.hash === tx.hash('hex'));

    ewallet = w;
    ekey = key;
  }));

  it('should import pubkey', cob(function* () {
    var priv = bcoin.keyring.generate();
    var key = new bcoin.keyring(priv.publicKey);
    var w = yield walletdb.create({ watchOnly: true });
    var options, k, t1, t2, tx;

    yield w.importKey('default', key);

    k = yield w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = yield w.getKey(key.getHash('hex'));
    assert(k);
  }));

  it('should import address', cob(function* () {
    var key = bcoin.keyring.generate();
    var w = yield walletdb.create({ watchOnly: true });
    var options, k, t1, t2, tx;

    yield w.importAddress('default', key.getAddress());

    k = yield w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = yield w.getKey(key.getHash('hex'));
    assert(!k);
  }));

  it('should get details', cob(function* () {
    var w = wallet;
    var txs = yield w.getRange('foo', { start: 0xdeadbeef - 1000 });
    var details = yield w.toDetails(txs);
    assert.equal(details[0].toJSON().outputs[0].path.name, 'foo');
  }));

  it('should rename wallet', cob(function* () {
    var w = wallet;
    yield wallet.rename('test');
    var txs = yield w.getRange('foo', { start: 0xdeadbeef - 1000 });
    var details = yield w.toDetails(txs);
    assert.equal(details[0].toJSON().id, 'test');
  }));

  it('should handle changed passphrase with encrypted imports', cob(function* () {
    var w = ewallet;
    var addr = ekey.getAddress();
    var path, d1, d2, k;

    assert(w.master.encrypted);

    path = yield w.getPath(addr);
    assert(path);
    assert(path.data && path.encrypted);
    d1 = path.data;

    yield w.decrypt('test');

    path = yield w.getPath(addr);
    assert(path);
    assert(path.data && !path.encrypted);

    k = yield w.getKey(addr);
    assert(k);

    yield w.encrypt('foo');

    path = yield w.getPath(addr);
    assert(path);
    assert(path.data && path.encrypted);
    d2 = path.data;

    assert(!util.equal(d1, d2));

    k = yield w.getKey(addr);
    assert(!k);

    yield w.unlock('foo');
    k = yield w.getKey(addr);
    assert(k);
    assert.equal(k.getHash('hex'), addr.getHash('hex'));
  }));

  it('should recover from a missed tx', cob(function* () {
    var walletdb, alice, addr, bob, t1, t2, t3;

    walletdb = new bcoin.walletdb({
      name: 'wallet-test',
      db: 'memory',
      resolution: false,
      verify: false
    });

    yield walletdb.open();

    alice = yield walletdb.create({ master: KEY1 });
    bob = yield walletdb.create({ master: KEY1 });
    addr = alice.getAddress();

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(addr, 50000);
    t1.addInput(dummy());

    yield alice.sign(t1);
    t1 = t1.toTX();

    yield alice.add(t1);
    yield bob.add(t1);

    // Bob misses this tx!
    t2 = bcoin.mtx()
      .addInput(t1, 0)
      .addOutput(addr, 24000)
      .addOutput(addr, 24000);

    yield alice.sign(t2);
    t2 = t2.toTX();

    yield alice.add(t2);

    assert.notEqual(
      (yield alice.getBalance()).unconfirmed,
      (yield bob.getBalance()).unconfirmed);

    // Bob sees this one.
    t3 = bcoin.mtx()
      .addInput(t2, 0)
      .addInput(t2, 1)
      .addOutput(addr, 30000);

    yield alice.sign(t3);
    t3 = t3.toTX();

    assert.equal((yield bob.getBalance()).unconfirmed, 50000);

    yield alice.add(t3);
    yield bob.add(t3);

    assert.equal((yield alice.getBalance()).unconfirmed, 30000);

    // Bob sees t2 on the chain.
    yield bob.add(t2);

    // Bob sees t3 on the chain.
    yield bob.add(t3);

    assert.equal((yield bob.getBalance()).unconfirmed, 30000);
  }));

  it('should recover from a missed tx and double spend', cob(function* () {
    var walletdb, alice, addr, bob, t1, t2, t3, t2a;

    walletdb = new bcoin.walletdb({
      name: 'wallet-test',
      db: 'memory',
      resolution: false,
      verify: false
    });

    yield walletdb.open();

    alice = yield walletdb.create({ master: KEY1 });
    bob = yield walletdb.create({ master: KEY1 });
    addr = alice.getAddress();

    // Coinbase
    t1 = bcoin.mtx()
      .addOutput(addr, 50000);
    t1.addInput(dummy());

    yield alice.sign(t1);
    t1 = t1.toTX();

    yield alice.add(t1);
    yield bob.add(t1);

    // Bob misses this tx!
    t2 = bcoin.mtx()
      .addInput(t1, 0)
      .addOutput(addr, 24000)
      .addOutput(addr, 24000);

    yield alice.sign(t2);
    t2 = t2.toTX();

    yield alice.add(t2);

    assert.notEqual(
      (yield alice.getBalance()).unconfirmed,
      (yield bob.getBalance()).unconfirmed);

    // Bob doublespends.
    t2a = bcoin.mtx()
      .addInput(t1, 0)
      .addOutput(addr, 10000)
      .addOutput(addr, 10000);

    yield bob.sign(t2a);
    t2a = t2a.toTX();

    yield bob.add(t2a);

    // Bob sees this one.
    t3 = bcoin.mtx()
      .addInput(t2, 0)
      .addInput(t2, 1)
      .addOutput(addr, 30000);

    yield alice.sign(t3);
    t3 = t3.toTX();

    assert.equal((yield bob.getBalance()).unconfirmed, 20000);

    yield alice.add(t3);
    yield bob.add(t3);

    assert.equal((yield alice.getBalance()).unconfirmed, 30000);

    // Bob sees t2 on the chain.
    yield bob.add(t2);

    // Bob sees t3 on the chain.
    yield bob.add(t3);

    assert.equal((yield bob.getBalance()).unconfirmed, 30000);
  }));

  it('should cleanup', cob(function* () {
    var records = yield walletdb.dump();
    constants.tx.COINBASE_MATURITY = 100;
  }));
});

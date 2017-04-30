'use strict';

var assert = require('assert');
var consensus = require('../lib/protocol/consensus');
var util = require('../lib/utils/util');
var encoding = require('../lib/utils/encoding');
var crypto = require('../lib/crypto/crypto');
var co = require('../lib/utils/co');
var WalletDB = require('../lib/wallet/walletdb');
var Address = require('../lib/primitives/address');
var MTX = require('../lib/primitives/mtx');
var Coin = require('../lib/primitives/coin');
var KeyRing = require('../lib/primitives/keyring');
var Address = require('../lib/primitives/address');
var Input = require('../lib/primitives/input');
var Outpoint = require('../lib/primitives/outpoint');
var Script = require('../lib/script/script');
var HD = require('../lib/hd');
var scriptTypes = Script.types;

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
    merkleRoot: encoding.NULL_HASH,
    nonce: 0,
    bits: 0
  };
}

function dummy(hash) {
  if (!hash)
    hash = crypto.randomBytes(32).toString('hex');

  return Input.fromOutpoint(new Outpoint(hash, 0));
}

describe('Wallet', function() {
  var walletdb, wallet, ewallet, ekey;
  var doubleSpendWallet, doubleSpend;
  var testP2PKH, testMultisig;

  walletdb = new WalletDB({
    name: 'wallet-test',
    db: 'memory',
    verify: true
  });

  this.timeout(5000);

  it('should open walletdb', co(function* () {
    consensus.COINBASE_MATURITY = 0;
    yield walletdb.open();
  }));

  it('should generate new key and address', co(function* () {
    var w = yield walletdb.create();
    var addr = w.getAddress('string');
    assert(addr);
    assert(Address.fromString(addr));
  }));

  it('should validate existing address', function() {
    assert(Address.fromString('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', function() {
    assert.throws(function() {
      Address.fromString('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc');
    });
  });

  it('should create and get wallet', co(function* () {
    var w1, w2;

    w1 = yield walletdb.create();
    yield w1.destroy();

    w2 = yield walletdb.get(w1.id);

    assert(w1 !== w2);
    assert(w1.master !== w2.master);
    assert.equal(w1.master.key.toBase58(), w2.master.key.toBase58());
    assert.equal(
      w1.account.accountKey.toBase58(),
      w2.account.accountKey.toBase58());
  }));

  testP2PKH = co(function* testP2PKH(witness, bullshitNesting) {
    var flags = Script.flags.STANDARD_VERIFY_FLAGS;
    var w, addr, src, tx;

    w = yield walletdb.create({ witness: witness });

    addr = Address.fromString(w.getAddress('string'));

    if (witness)
      assert.equal(addr.type, scriptTypes.WITNESSPUBKEYHASH);
    else
      assert.equal(addr.type, scriptTypes.PUBKEYHASH);

    src = new MTX();
    src.addInput(dummy());
    src.addOutput(bullshitNesting ? w.getNested() : w.getAddress(), 5460 * 2);
    src.addOutput(new Address(), 2 * 5460);
    src = src.toTX();

    tx = new MTX();
    tx.addTX(src, 0);
    tx.addOutput(w.getAddress(), 5460);

    yield w.sign(tx);

    assert(tx.verify(flags));
  });

  it('should sign/verify pubkeyhash tx', co(function* () {
    yield testP2PKH(false, false);
  }));

  it('should sign/verify witnesspubkeyhash tx', co(function* () {
    yield testP2PKH(true, false);
  }));

  it('should sign/verify witnesspubkeyhash tx with bullshit nesting', co(function* () {
    yield testP2PKH(true, true);
  }));

  it('should multisign/verify TX', co(function* () {
    var w, k, script, src, tx, maxSize;

    w = yield walletdb.create({
      type: 'multisig',
      m: 1,
      n: 2
    });

    k = HD.generate().deriveAccount44(0).toPublic();

    yield w.addSharedKey(k);

    script = Script.fromMultisig(1, 2, [
      w.account.receive.getPublicKey(),
      k.derive('m/0/0').publicKey
    ]);

    // Input transaction (bare 1-of-2 multisig)
    src = new MTX();
    src.addInput(dummy());
    src.addOutput(script, 5460 * 2);
    src.addOutput(new Address(), 5460 * 2);
    src = src.toTX();

    tx = new MTX();
    tx.addTX(src, 0)
    tx.addOutput(w.getAddress(), 5460);

    maxSize = yield tx.estimateSize();

    yield w.sign(tx);

    assert(tx.toRaw().length <= maxSize);
    assert(tx.verify());
  }));

  it('should handle missed and invalid txs', co(function* () {
    var w = yield walletdb.create();
    var f = yield walletdb.create();
    var t1, t2, t3, t4, f1, fake, balance, txs;

    // Coinbase
    // balance: 51000
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 1000);
    t1 = t1.toTX();

    t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 24000);
    t2.addOutput(w.getAddress(), 24000);

    // Save for later.
    doubleSpendWallet = w;
    doubleSpend = Coin.fromTX(t1, 0, -1);

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();
    t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    yield w.sign(t3);
    t3 = t3.toTX();
    t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    yield w.sign(t4);
    t4 = t4.toTX();
    f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(f.getAddress(), 10000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    fake = new MTX();
    fake.addTX(t1, 1); // 1000 (already redeemed)
    fake.addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    yield w.template(fake);
    // Fake signature
    fake.inputs[0].script.set(0, encoding.ZERO_SIG);
    fake.inputs[0].script.compile();
    // balance: 11000
    fake = fake.toTX();

    // Fake TX should temporarily change output.
    yield walletdb.addTX(fake);

    yield walletdb.addTX(t4);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 22500);

    yield walletdb.addTX(t1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 72500);

    yield walletdb.addTX(t2);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 46500);

    yield walletdb.addTX(t3);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    yield walletdb.addTX(f1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    txs = yield w.getHistory();
    assert(txs.some(function(wtx) {
      return wtx.hash === f1.hash('hex');
    }));

    balance = yield f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = yield f.getHistory();
    assert(txs.some(function(wtx) {
      return wtx.tx.hash('hex') === f1.hash('hex');
    }));
  }));

  it('should cleanup spenders after double-spend', co(function* () {
    var w = doubleSpendWallet;
    var tx, txs, total, balance;

    tx = new MTX();
    tx.addCoin(doubleSpend);
    tx.addOutput(w.getAddress(), 5000);

    txs = yield w.getHistory();
    assert.equal(txs.length, 5);
    total = txs.reduce(function(t, wtx) {
      return t + wtx.tx.getOutputValue();
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

    total = txs.reduce(function(t, wtx) {
      return t + wtx.tx.getOutputValue();
    }, 0);
    assert.equal(total, 56000);
  }));

  it('should handle missed txs without resolution', co(function* () {
    var walletdb, w, f, t1, t2, t3, t4, f1, balance, txs;

    walletdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    yield walletdb.open();

    w = yield walletdb.create();
    f = yield walletdb.create();

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 1000);

    // balance: 51000
    // yield w.sign(t1);
    t1 = t1.toTX();

    t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 24000);
    t2.addOutput(w.getAddress(), 24000);

    // balance: 49000
    yield w.sign(t2);
    t2 = t2.toTX();
    t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    yield w.sign(t3);
    t3 = t3.toTX();
    t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    yield w.sign(t4);
    t4 = t4.toTX();
    f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(f.getAddress(), 10000);

    // balance: 11000
    yield w.sign(f1);
    f1 = f1.toTX();

    // fake = new MTX();
    // fake.addTX(t1, 1); // 1000 (already redeemed)
    // fake.addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    // yield w.template(fake);
    // Fake signature
    // fake.inputs[0].script.set(0, encoding.ZERO_SIG);
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
    assert.equal(balance.unconfirmed, 47000);

    yield walletdb.addTX(t3);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    yield walletdb.addTX(f1);

    balance = yield w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    txs = yield w.getHistory();
    assert(txs.some(function(wtx) {
      return wtx.tx.hash('hex') === f1.hash('hex');
    }));

    balance = yield f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = yield f.getHistory();
    assert(txs.some(function(wtx) {
      return wtx.tx.hash('hex') === f1.hash('hex');
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

  it('should fill tx with inputs', co(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var view, t1, t2, t3, err;

    // Coinbase
    t1 = new MTX()
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);

    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000, round: true });
    yield w1.sign(t2);
    view = t2.view;
    t2 = t2.toTX();

    assert(t2.verify(view));

    assert.equal(t2.getInputValue(view), 16380);
    assert.equal(t2.getOutputValue(), 6380);
    assert.equal(t2.getFee(view), 10000);

    // Create new transaction
    t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

    try {
      yield w1.fund(t3, { rate: 10000, round: true });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.requiredFunds, 25000);
  }));

  it('should fill tx with inputs with accurate fee', co(function* () {
    var w1 = yield walletdb.create({ master: KEY1 });
    var w2 = yield walletdb.create({ master: KEY2 });
    var view, t1, t2, t3, balance, err;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy(encoding.NULL_HASH));
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000 });

    yield w1.sign(t2);
    view = t2.view;
    t2 = t2.toTX();
    assert(t2.verify(view));

    assert.equal(t2.getInputValue(view), 16380);

    // Should now have a change output:
    assert.equal(t2.getOutputValue(), 11130);

    assert.equal(t2.getFee(view), 5250);

    assert.equal(t2.getWeight(), 2084);
    assert.equal(t2.getBaseSize(), 521);
    assert.equal(t2.getSize(), 521);
    assert.equal(t2.getVirtualSize(), 521);

    w2.once('balance', function(b) {
      balance = b;
    });

    yield walletdb.addTX(t2);

    // Create new transaction
    t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

    try {
      yield w1.fund(t3, { rate: 10000 });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(balance);
    assert(balance.unconfirmed === 5460);
  }));

  it('should sign multiple inputs using different keys', co(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var to = yield walletdb.create();
    var t1, t2, tx, cost, total, coins1, coins2;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    // Coinbase
    t2 = new MTX();
    t2.addInput(dummy());
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2 = t2.toTX();

    yield walletdb.addTX(t1);
    yield walletdb.addTX(t2);

    // Create our tx with an output
    tx = new MTX();
    tx.addOutput(to.getAddress(), 5460);

    cost = tx.getOutputValue();
    total = cost * 10000;

    coins1 = yield w1.getCoins();
    coins2 = yield w2.getCoins();

    // Add our unspent inputs to sign
    tx.addCoin(coins1[0]);
    tx.addCoin(coins1[1]);
    tx.addCoin(coins2[0]);

    // Sign transaction
    total = yield w1.sign(tx);
    assert.equal(total, 2);

    total = yield w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);

    tx.inputs.length = 0;
    tx.addCoin(coins1[1]);
    tx.addCoin(coins1[2]);
    tx.addCoin(coins2[1]);

    total = yield w1.sign(tx);
    assert.equal(total, 2);

    total = yield w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);
  }));

  testMultisig = co(function* testMultisig(witness, bullshitNesting, cb) {
    var flags = Script.flags.STANDARD_VERIFY_FLAGS;
    var rec = bullshitNesting ? 'nested' : 'receive';
    var depth = bullshitNesting ? 'nestedDepth' : 'receiveDepth';
    var options, w1, w2, w3, receive, b58;
    var addr, paddr, utx, send, change;
    var view, block;

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

    yield w1.addSharedKey(w2.account.accountKey);
    yield w1.addSharedKey(w3.account.accountKey);
    yield w2.addSharedKey(w1.account.accountKey);
    yield w2.addSharedKey(w3.account.accountKey);
    yield w3.addSharedKey(w1.account.accountKey);
    yield w3.addSharedKey(w2.account.accountKey);

    // Our p2sh address
    b58 = w1.account[rec].getAddress('string');
    addr = Address.fromString(b58);

    if (witness) {
      if (bullshitNesting)
        assert.equal(addr.type, scriptTypes.SCRIPTHASH);
      else
        assert.equal(addr.type, scriptTypes.WITNESSSCRIPTHASH);
    } else {
      assert.equal(addr.type, scriptTypes.SCRIPTHASH);
    }

    assert.equal(w1.account[rec].getAddress('string'), b58);
    assert.equal(w2.account[rec].getAddress('string'), b58);
    assert.equal(w3.account[rec].getAddress('string'), b58);

    paddr = w1.getNested();

    if (witness) {
      assert(paddr);
      assert.equal(w1.getNested('string'), paddr.toString());
      assert.equal(w2.getNested('string'), paddr.toString());
      assert.equal(w3.getNested('string'), paddr.toString());
    }

    // Add a shared unspent transaction to our wallets
    utx = new MTX();
    utx.addInput(dummy());
    utx.addOutput(bullshitNesting ? paddr : addr, 5460 * 10);
    utx = utx.toTX();

    // Simulate a confirmation
    block = nextBlock();

    assert.equal(w1.account[depth], 1);

    yield walletdb.addBlock(block, [utx]);

    assert.equal(w1.account[depth], 2);

    assert.equal(w1.account.changeDepth, 1);

    assert(w1.account[rec].getAddress('string') !== b58);
    b58 = w1.account[rec].getAddress('string');
    assert.equal(w1.account[rec].getAddress('string'), b58);
    assert.equal(w2.account[rec].getAddress('string'), b58);
    assert.equal(w3.account[rec].getAddress('string'), b58);

    // Create a tx requiring 2 signatures
    send = new MTX();
    send.addOutput(receive.getAddress(), 5460);
    assert(!send.verify(flags));
    yield w1.fund(send, { rate: 10000, round: true });

    yield w1.sign(send);

    assert(!send.verify(flags));

    yield w2.sign(send);

    view = send.view;
    send = send.toTX();
    assert(send.verify(view, flags));

    assert.equal(w1.account.changeDepth, 1);

    change = w1.account.change.getAddress('string');
    assert.equal(w1.account.change.getAddress('string'), change);
    assert.equal(w2.account.change.getAddress('string'), change);
    assert.equal(w3.account.change.getAddress('string'), change);

    // Simulate a confirmation
    block = nextBlock();

    yield walletdb.addBlock(block, [send]);

    assert.equal(w1.account[depth], 2);
    assert.equal(w1.account.changeDepth, 2);

    assert(w1.account[rec].getAddress('string') === b58);
    assert(w1.account.change.getAddress('string') !== change);
    change = w1.account.change.getAddress('string');
    assert.equal(w1.account.change.getAddress('string'), change);
    assert.equal(w2.account.change.getAddress('string'), change);
    assert.equal(w3.account.change.getAddress('string'), change);

    if (witness) {
      send.inputs[0].witness.set(2, 0);
      send.inputs[0].witness.compile();
    } else {
      send.inputs[0].script.set(2, 0);
      send.inputs[0].script.compile();
    }

    assert(!send.verify(view, flags));
    assert.equal(send.getFee(view), 10000);
  });

  it('should verify 2-of-3 scripthash tx', co(function* () {
    yield testMultisig(false, false);
  }));

  it('should verify 2-of-3 witnessscripthash tx', co(function* () {
    yield testMultisig(true, false);
  }));

  it('should verify 2-of-3 witnessscripthash tx with bullshit nesting', co(function* () {
    yield testMultisig(true, true);
  }));

  it('should fill tx with account 1', co(function* () {
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
    t1 = new MTX();
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    yield w1.fund(t2, { rate: 10000, round: true });
    yield w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 16380);
    assert.equal(t2.getOutputValue(), 6380);
    assert.equal(t2.getFee(), 10000);

    // Create new transaction
    t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

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

  it('should fail to fill tx with account 1', co(function* () {
    var w = yield walletdb.create();
    var acc, account, t1, t2, err;

    wallet = w;

    acc = yield w.createAccount({ name: 'foo' });
    assert.equal(acc.name, 'foo');
    assert.equal(acc.accountIndex, 1);

    account = yield w.getAccount('foo');
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);
    assert(account.accountKey.toBase58() === acc.accountKey.toBase58());
    assert(w.account.accountIndex === 0);

    assert.notEqual(
      account.receive.getAddress('string'),
      w.account.receive.getAddress('string'));

    assert.equal(w.getAddress('string'),
      w.account.receive.getAddress('string'));

    // Coinbase
    t1 = new MTX();
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Should fill from `foo` and fail
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    try {
      yield w.fund(t2, { rate: 10000, round: true, account: 'foo' });
    } catch (e) {
      err = e;
    }
    assert(err);

    // Should fill from whole wallet and succeed
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    yield w.fund(t2, { rate: 10000, round: true });

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(account.receive.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Should fill from `foo` and succeed
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    yield w.fund(t2, { rate: 10000, round: true, account: 'foo' });
  }));

  it('should create two accounts (multiple encryption)', co(function* () {
    var w = yield walletdb.create({ id: 'foobar', passphrase: 'foo' });
    var account;

    yield w.destroy();

    w = yield walletdb.get('foobar');

    account = yield w.createAccount({ name: 'foo1' }, 'foo');
    assert(account);

    yield w.lock();
  }));

  it('should fill tx with inputs when encrypted', co(function* () {
    var w = yield walletdb.create({ passphrase: 'foo' });
    var t1, t2, err;

    w.master.stop();
    w.master.key = null;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
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

  it('should fill tx with inputs with subtract fee (1)', co(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var t1, t2;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Create new transaction
    t2 = new MTX();
    t2.addOutput(w2.getAddress(), 21840);
    yield w1.fund(t2, { rate: 10000, round: true, subtractFee: true });
    yield w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 5460 * 4);
    assert.equal(t2.getOutputValue(), 21840 - 10000);
    assert.equal(t2.getFee(), 10000);
  }));

  it('should fill tx with inputs with subtract fee (2)', co(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var options, t1, t2;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
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

  it('should fill tx with smart coin selection', co(function* () {
    var w1 = yield walletdb.create();
    var w2 = yield walletdb.create();
    var found = false;
    var total = 0;
    var i, options, t1, t2, t3, block, coins, coin;

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    // Coinbase
    t2 = new MTX();
    t2.addInput(dummy());
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2 = t2.toTX();

    block = nextBlock();

    yield walletdb.addBlock(block, [t2]);

    coins = yield w1.getSmartCoins();
    assert.equal(coins.length, 4);

    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      assert.equal(coin.height, block.height);
    }

    // Create a change output for ourselves.
    yield w1.send({
      subtractFee: true,
      rate: 1000,
      depth: 1,
      outputs: [{ address: w2.getAddress(), value: 1461 }]
    });

    coins = yield w1.getSmartCoins();
    assert.equal(coins.length, 4);

    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      if (coin.height === -1) {
        assert(!found);
        assert(coin.value < 5460);
        found = true;
      } else {
        assert.equal(coin.height, block.height);
      }
      total += coin.value;
    }

    assert(found);

    // Use smart selection
    options = {
      subtractFee: true,
      smart: true,
      rate: 10000,
      outputs: [{ address: w2.getAddress(), value: total }]
    };

    t3 = yield w1.createTX(options);
    assert.equal(t3.inputs.length, 4);

    found = false;
    for (i = 0; i < t3.inputs.length; i++) {
      coin = t3.view.getCoin(t3.inputs[i]);
      if (coin.height === -1) {
        assert(!found);
        assert(coin.value < 5460);
        found = true;
      } else {
        assert.equal(coin.height, block.height);
      }
    }

    assert(found);

    yield w1.sign(t3);

    assert(t3.verify());
  }));

  it('should get range of txs', co(function* () {
    var w = wallet;
    var txs = yield w.getRange({ start: util.now() - 1000 });
    assert.equal(txs.length, 2);
  }));

  it('should get range of txs from account', co(function* () {
    var w = wallet;
    var txs = yield w.getRange('foo', { start: util.now() - 1000 });
    assert.equal(txs.length, 2);
  }));

  it('should not get range of txs from non-existent account', co(function* () {
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

  it('should get account balance', co(function* () {
    var w = wallet;
    var balance = yield w.getBalance('foo');
    assert.equal(balance.unconfirmed, 21840);
  }));

  it('should import privkey', co(function* () {
    var key = KeyRing.generate();
    var w = yield walletdb.create({ passphrase: 'test' });
    var options, k, t1, t2, wtx;

    yield w.importKey('default', key, 'test');

    k = yield w.getKey(key.getHash('hex'));

    assert.equal(k.getHash('hex'), key.getHash('hex'));

    // Coinbase
    t1 = new MTX();
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    yield walletdb.addTX(t1);

    wtx = yield w.getTX(t1.hash('hex'));
    assert(wtx);
    assert.equal(t1.hash('hex'), wtx.hash);

    options = {
      rate: 10000,
      round: true,
      outputs: [{ address: w.getAddress(), value: 7000 }]
    };

    // Create new transaction
    t2 = yield w.createTX(options);
    yield w.sign(t2);
    assert(t2.verify());
    assert(t2.inputs[0].prevout.hash === wtx.hash);

    ewallet = w;
    ekey = key;
  }));

  it('should import pubkey', co(function* () {
    var priv = KeyRing.generate();
    var key = new KeyRing(priv.publicKey);
    var w = yield walletdb.create({ watchOnly: true });
    var k;

    yield w.importKey('default', key);

    k = yield w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = yield w.getKey(key.getHash('hex'));
    assert(k);
  }));

  it('should import address', co(function* () {
    var key = KeyRing.generate();
    var w = yield walletdb.create({ watchOnly: true });
    var k;

    yield w.importAddress('default', key.getAddress());

    k = yield w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = yield w.getKey(key.getHash('hex'));
    assert(!k);
  }));

  it('should get details', co(function* () {
    var w = wallet;
    var txs = yield w.getRange('foo', { start: util.now() - 1000 });
    var details = yield w.toDetails(txs);
    assert(details.some(function(tx) {
      return tx.toJSON().outputs[0].path.name === 'foo';
    }));
  }));

  it('should rename wallet', co(function* () {
    var w = wallet;
    yield wallet.rename('test');
    var txs = yield w.getRange('foo', { start: util.now() - 1000 });
    var details = yield w.toDetails(txs);
    assert.equal(details[0].toJSON().id, 'test');
  }));

  it('should change passphrase with encrypted imports', co(function* () {
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

  it('should recover from a missed tx', co(function* () {
    var walletdb, alice, addr, bob, t1, t2, t3;

    walletdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    yield walletdb.open();

    alice = yield walletdb.create({ master: KEY1 });
    bob = yield walletdb.create({ master: KEY1 });
    addr = alice.getAddress();

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(addr, 50000);
    t1 = t1.toTX();

    yield alice.add(t1);
    yield bob.add(t1);

    // Bob misses this tx!
    t2 = new MTX();
    t2.addTX(t1, 0);
    t2.addOutput(addr, 24000);
    t2.addOutput(addr, 24000);

    yield alice.sign(t2);
    t2 = t2.toTX();

    yield alice.add(t2);

    assert.notEqual(
      (yield alice.getBalance()).unconfirmed,
      (yield bob.getBalance()).unconfirmed);

    // Bob sees this one.
    t3 = new MTX();
    t3.addTX(t2, 0);
    t3.addTX(t2, 1);
    t3.addOutput(addr, 30000);

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

  it('should recover from a missed tx and double spend', co(function* () {
    var walletdb, alice, addr, bob, t1, t2, t3, t2a;

    walletdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    yield walletdb.open();

    alice = yield walletdb.create({ master: KEY1 });
    bob = yield walletdb.create({ master: KEY1 });
    addr = alice.getAddress();

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(addr, 50000);
    t1 = t1.toTX();

    yield alice.add(t1);
    yield bob.add(t1);

    // Bob misses this tx!
    t2 = new MTX();
    t2.addTX(t1, 0);
    t2.addOutput(addr, 24000);
    t2.addOutput(addr, 24000);

    yield alice.sign(t2);
    t2 = t2.toTX();

    yield alice.add(t2);

    assert.notEqual(
      (yield alice.getBalance()).unconfirmed,
      (yield bob.getBalance()).unconfirmed);

    // Bob doublespends.
    t2a = new MTX();
    t2a.addTX(t1, 0);
    t2a.addOutput(addr, 10000);
    t2a.addOutput(addr, 10000);

    yield bob.sign(t2a);
    t2a = t2a.toTX();

    yield bob.add(t2a);

    // Bob sees this one.
    t3 = new MTX();
    t3.addTX(t2, 0);
    t3.addTX(t2, 1);
    t3.addOutput(addr, 30000);

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

  it('should cleanup', function() {
    consensus.COINBASE_MATURITY = 100;
  });
});

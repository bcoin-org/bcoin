/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('assert');
const consensus = require('../lib/protocol/consensus');
const util = require('../lib/utils/util');
const encoding = require('../lib/utils/encoding');
const digest = require('../lib/crypto/digest');
const random = require('../lib/crypto/random');
const WalletDB = require('../lib/wallet/walletdb');
const Address = require('../lib/primitives/address');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const HD = require('../lib/hd');

const KEY1 = 'xprv9s21ZrQH143K3Aj6xQBymM31Zb4BVc7wxqfUhMZrzewdDVCt'
  + 'qUP9iWfcHgJofs25xbaUpCps9GDXj83NiWvQCAkWQhVj5J4CorfnpKX94AZ';

const KEY2 = 'xprv9s21ZrQH143K3mqiSThzPtWAabQ22Pjp3uSNnZ53A5bQ4udp'
  + 'faKekc2m4AChLYH1XDzANhrSdxHYWUeTWjYJwFwWFyHkTMnMeAcW4JyRCZa';

let globalHeight = 1;
const globalTime = util.now();

function nextBlock(height) {
  if (height == null)
    height = globalHeight++;

  const hash = digest.hash256(encoding.U32(height)).toString('hex');
  const prev = digest.hash256(encoding.U32(height - 1)).toString('hex');

  return {
    hash: hash,
    height: height,
    prevBlock: prev,
    time: globalTime + height,
    merkleRoot: encoding.NULL_HASH,
    nonce: 0,
    bits: 0
  };
}

function dummy(hash) {
  if (!hash)
    hash = random.randomBytes(32).toString('hex');

  return Input.fromOutpoint(new Outpoint(hash, 0));
}

describe('Wallet', function() {
  let wallet, ewallet, ekey;
  let doubleSpendWallet, doubleSpend;

  const wdb = new WalletDB({
    name: 'wallet-test',
    db: 'memory',
    verify: true
  });

  this.timeout(5000);

  it('should open walletdb', async () => {
    consensus.COINBASE_MATURITY = 0;
    await wdb.open();
  });

  it('should generate new key and address', async () => {
    const w = await wdb.create();
    const addr = w.getAddress('string');
    assert(addr);
    assert(Address.fromString(addr));
  });

  it('should validate existing address', () => {
    assert(Address.fromString('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc'));
  });

  it('should fail to validate invalid address', () => {
    assert.throws(() => {
      Address.fromString('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc');
    });
  });

  it('should create and get wallet', async () => {
    const w1 = await wdb.create();
    await w1.destroy();

    const w2 = await wdb.get(w1.id);

    assert(w1 !== w2);
    assert(w1.master !== w2.master);
    assert.equal(w1.master.key.toBase58(), w2.master.key.toBase58());
    assert.equal(
      w1.account.accountKey.toBase58(),
      w2.account.accountKey.toBase58());
  });

  async function testP2PKH(witness, bullshitNesting) {
    const flags = Script.flags.STANDARD_VERIFY_FLAGS;

    const w = await wdb.create({ witness: witness });

    const addr = Address.fromString(w.getAddress('string'));

    if (witness)
      assert.equal(addr.type, Address.types.WITNESS);
    else
      assert.equal(addr.type, Address.types.PUBKEYHASH);

    let src = new MTX();
    src.addInput(dummy());
    src.addOutput(bullshitNesting ? w.getNested() : w.getAddress(), 5460 * 2);
    src.addOutput(new Address(), 2 * 5460);
    src = src.toTX();

    const tx = new MTX();
    tx.addTX(src, 0);
    tx.addOutput(w.getAddress(), 5460);

    await w.sign(tx);

    assert(tx.verify(flags));
  }

  it('should sign/verify p2pkh tx', async () => {
    await testP2PKH(false, false);
  });

  it('should sign/verify p2wpkh tx', async () => {
    await testP2PKH(true, false);
  });

  it('should sign/verify p2wpkh tx w/ nested bullshit', async () => {
    await testP2PKH(true, true);
  });

  it('should multisign/verify TX', async () => {
    const w = await wdb.create({
      type: 'multisig',
      m: 1,
      n: 2
    });

    const k = HD.generate().deriveBIP44(0).toPublic();

    await w.addSharedKey(k);

    const script = Script.fromMultisig(1, 2, [
      w.account.receive.getPublicKey(),
      k.derivePath('m/0/0').publicKey
    ]);

    // Input transaction (bare 1-of-2 multisig)
    let src = new MTX();
    src.addInput(dummy());
    src.addOutput(script, 5460 * 2);
    src.addOutput(new Address(), 5460 * 2);
    src = src.toTX();

    const tx = new MTX();
    tx.addTX(src, 0);
    tx.addOutput(w.getAddress(), 5460);

    const maxSize = await tx.estimateSize();

    await w.sign(tx);

    assert(tx.toRaw().length <= maxSize);
    assert(tx.verify());
  });

  it('should handle missed and invalid txs', async () => {
    const w = await wdb.create();
    const f = await wdb.create();

    // Coinbase
    // balance: 51000
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 1000);
    t1 = t1.toTX();

    let t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 24000);
    t2.addOutput(w.getAddress(), 24000);

    // Save for later.
    doubleSpendWallet = w;
    doubleSpend = Coin.fromTX(t1, 0, -1);

    // balance: 49000
    await w.sign(t2);
    t2 = t2.toTX();
    let t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    await w.sign(t3);
    t3 = t3.toTX();
    let t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    await w.sign(t4);
    t4 = t4.toTX();
    let f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(f.getAddress(), 10000);

    // balance: 11000
    await w.sign(f1);
    f1 = f1.toTX();

    let fake = new MTX();
    fake.addTX(t1, 1); // 1000 (already redeemed)
    fake.addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    await w.template(fake);
    // Fake signature
    fake.inputs[0].script.set(0, encoding.ZERO_SIG);
    fake.inputs[0].script.compile();
    // balance: 11000
    fake = fake.toTX();

    // Fake TX should temporarily change output.
    await wdb.addTX(fake);

    await wdb.addTX(t4);

    let balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 22500);

    await wdb.addTX(t1);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 72500);

    await wdb.addTX(t2);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 46500);

    await wdb.addTX(t3);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    await wdb.addTX(f1);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    let txs = await w.getHistory();
    assert(txs.some((wtx) => {
      return wtx.hash === f1.hash('hex');
    }));

    balance = await f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = await f.getHistory();
    assert(txs.some((wtx) => {
      return wtx.tx.hash('hex') === f1.hash('hex');
    }));
  });

  it('should cleanup spenders after double-spend', async () => {
    const w = doubleSpendWallet;

    let tx = new MTX();
    tx.addCoin(doubleSpend);
    tx.addOutput(w.getAddress(), 5000);

    let txs = await w.getHistory();
    assert.equal(txs.length, 5);
    let total = txs.reduce((t, wtx) => {
      return t + wtx.tx.getOutputValue();
    }, 0);

    assert.equal(total, 154000);

    await w.sign(tx);
    tx = tx.toTX();

    let balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    await wdb.addTX(tx);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 6000);

    txs = await w.getHistory();
    assert.equal(txs.length, 2);

    total = txs.reduce((t, wtx) => {
      return t + wtx.tx.getOutputValue();
    }, 0);
    assert.equal(total, 56000);
  });

  it('should handle missed txs without resolution', async () => {
    const wdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    await wdb.open();

    const w = await wdb.create();
    const f = await wdb.create();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 50000);
    t1.addOutput(w.getAddress(), 1000);

    // balance: 51000
    // await w.sign(t1);
    t1 = t1.toTX();

    let t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(w.getAddress(), 24000);
    t2.addOutput(w.getAddress(), 24000);

    // balance: 49000
    await w.sign(t2);
    t2 = t2.toTX();
    let t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(w.getAddress(), 23000);

    // balance: 47000
    await w.sign(t3);
    t3 = t3.toTX();
    let t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(w.getAddress(), 11000);
    t4.addOutput(w.getAddress(), 11000);

    // balance: 22000
    await w.sign(t4);
    t4 = t4.toTX();
    let f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(f.getAddress(), 10000);

    // balance: 11000
    await w.sign(f1);
    f1 = f1.toTX();

    // fake = new MTX();
    // fake.addTX(t1, 1); // 1000 (already redeemed)
    // fake.addOutput(w.getAddress(), 500);

    // Script inputs but do not sign
    // await w.template(fake);
    // Fake signature
    // fake.inputs[0].script.set(0, encoding.ZERO_SIG);
    // fake.inputs[0].script.compile();
    // balance: 11000
    // fake = fake.toTX();

    // Fake TX should temporarly change output
    // await wdb.addTX(fake);

    await wdb.addTX(t4);

    let balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    await wdb.addTX(t1);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 73000);

    await wdb.addTX(t2);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 47000);

    await wdb.addTX(t3);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 22000);

    await wdb.addTX(f1);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    let txs = await w.getHistory();
    assert(txs.some((wtx) => {
      return wtx.tx.hash('hex') === f1.hash('hex');
    }));

    balance = await f.getBalance();
    assert.equal(balance.unconfirmed, 10000);

    txs = await f.getHistory();
    assert(txs.some((wtx) => {
      return wtx.tx.hash('hex') === f1.hash('hex');
    }));

    await wdb.addTX(t2);

    await wdb.addTX(t3);

    await wdb.addTX(t4);

    await wdb.addTX(f1);

    balance = await w.getBalance();
    assert.equal(balance.unconfirmed, 11000);

    balance = await f.getBalance();
    assert.equal(balance.unconfirmed, 10000);
  });

  it('should fill tx with inputs', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);

    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Create new transaction
    let t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    await w1.fund(t2, { rate: 10000, round: true });
    await w1.sign(t2);
    const view = t2.view;
    t2 = t2.toTX();

    assert(t2.verify(view));

    assert.equal(t2.getInputValue(view), 16380);
    assert.equal(t2.getOutputValue(), 6380);
    assert.equal(t2.getFee(view), 10000);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

    let err;
    try {
      await w1.fund(t3, { rate: 10000, round: true });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.requiredFunds, 25000);
  });

  it('should fill tx with inputs with accurate fee', async () => {
    const w1 = await wdb.create({ master: KEY1 });
    const w2 = await wdb.create({ master: KEY2 });
    let balance;

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy(encoding.NULL_HASH));
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Create new transaction
    let t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    await w1.fund(t2, { rate: 10000 });

    await w1.sign(t2);
    const view = t2.view;
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

    w2.once('balance', (b) => {
      balance = b;
    });

    await wdb.addTX(t2);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

    let err;
    try {
      await w1.fund(t3, { rate: 10000 });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(balance);
    assert(balance.unconfirmed === 5460);
  });

  it('should sign multiple inputs using different keys', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();
    const to = await wdb.create();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    // Coinbase
    let t2 = new MTX();
    t2.addInput(dummy());
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2.addOutput(w2.getAddress(), 5460);
    t2 = t2.toTX();

    await wdb.addTX(t1);
    await wdb.addTX(t2);

    // Create our tx with an output
    const tx = new MTX();
    tx.addOutput(to.getAddress(), 5460);

    const cost = tx.getOutputValue();
    let total = cost * 10000;

    const coins1 = await w1.getCoins();
    const coins2 = await w2.getCoins();

    // Add our unspent inputs to sign
    tx.addCoin(coins1[0]);
    tx.addCoin(coins1[1]);
    tx.addCoin(coins2[0]);

    // Sign transaction
    total = await w1.sign(tx);
    assert.equal(total, 2);

    total = await w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);

    tx.inputs.length = 0;
    tx.addCoin(coins1[1]);
    tx.addCoin(coins1[2]);
    tx.addCoin(coins2[1]);

    total = await w1.sign(tx);
    assert.equal(total, 2);

    total = await w2.sign(tx);
    assert.equal(total, 1);

    // Verify
    assert.equal(tx.verify(), true);
  });

  async function testMultisig(witness, bullshitNesting, cb) {
    const flags = Script.flags.STANDARD_VERIFY_FLAGS;
    const rec = bullshitNesting ? 'nested' : 'receive';
    const depth = bullshitNesting ? 'nestedDepth' : 'receiveDepth';

    // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
    const options = {
      witness: witness,
      type: 'multisig',
      m: 2,
      n: 3
    };

    const w1 = await wdb.create(options);
    const w2 = await wdb.create(options);
    const w3 = await wdb.create(options);
    const receive = await wdb.create();

    await w1.addSharedKey(w2.account.accountKey);
    await w1.addSharedKey(w3.account.accountKey);
    await w2.addSharedKey(w1.account.accountKey);
    await w2.addSharedKey(w3.account.accountKey);
    await w3.addSharedKey(w1.account.accountKey);
    await w3.addSharedKey(w2.account.accountKey);

    // Our p2sh address
    let b58 = w1.account[rec].getAddress('string');
    const addr = Address.fromString(b58);

    if (witness) {
      if (bullshitNesting)
        assert.equal(addr.type, Address.types.SCRIPTHASH);
      else
        assert.equal(addr.type, Address.types.WITNESS);
    } else {
      assert.equal(addr.type, Address.types.SCRIPTHASH);
    }

    assert.equal(w1.account[rec].getAddress('string'), b58);
    assert.equal(w2.account[rec].getAddress('string'), b58);
    assert.equal(w3.account[rec].getAddress('string'), b58);

    const paddr = w1.getNested();

    if (witness) {
      assert(paddr);
      assert.equal(w1.getNested('string'), paddr.toString());
      assert.equal(w2.getNested('string'), paddr.toString());
      assert.equal(w3.getNested('string'), paddr.toString());
    }

    // Add a shared unspent transaction to our wallets
    let utx = new MTX();
    utx.addInput(dummy());
    utx.addOutput(bullshitNesting ? paddr : addr, 5460 * 10);
    utx = utx.toTX();

    // Simulate a confirmation
    let block = nextBlock();

    assert.equal(w1.account[depth], 1);

    await wdb.addBlock(block, [utx]);

    assert.equal(w1.account[depth], 2);

    assert.equal(w1.account.changeDepth, 1);

    assert(w1.account[rec].getAddress('string') !== b58);
    b58 = w1.account[rec].getAddress('string');
    assert.equal(w1.account[rec].getAddress('string'), b58);
    assert.equal(w2.account[rec].getAddress('string'), b58);
    assert.equal(w3.account[rec].getAddress('string'), b58);

    // Create a tx requiring 2 signatures
    let send = new MTX();
    send.addOutput(receive.getAddress(), 5460);
    assert(!send.verify(flags));
    await w1.fund(send, { rate: 10000, round: true });

    await w1.sign(send);

    assert(!send.verify(flags));

    await w2.sign(send);

    const view = send.view;
    send = send.toTX();
    assert(send.verify(view, flags));

    assert.equal(w1.account.changeDepth, 1);

    let change = w1.account.change.getAddress('string');
    assert.equal(w1.account.change.getAddress('string'), change);
    assert.equal(w2.account.change.getAddress('string'), change);
    assert.equal(w3.account.change.getAddress('string'), change);

    // Simulate a confirmation
    block = nextBlock();

    await wdb.addBlock(block, [send]);

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
  }

  it('should verify 2-of-3 p2sh tx', async () => {
    await testMultisig(false, false);
  });

  it('should verify 2-of-3 p2wsh tx', async () => {
    await testMultisig(true, false);
  });

  it('should verify 2-of-3 p2wsh tx w/ nested bullshit', async () => {
    await testMultisig(true, true);
  });

  it('should fill tx with account 1', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();

    let account = await w1.createAccount({ name: 'foo' });
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);

    account = await w1.getAccount('foo');
    assert.equal(account.name, 'foo');
    assert.equal(account.accountIndex, 1);
    const rec = account.receive;

    // Coinbase
    let t1 = new MTX();
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);
    t1.addOutput(rec.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(w2.getAddress(), 5460);
    await w1.fund(t2, { rate: 10000, round: true });
    await w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 16380);
    assert.equal(t2.getOutputValue(), 6380);
    assert.equal(t2.getFee(), 10000);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(w2.getAddress(), 15000);

    let err;
    try {
      await w1.fund(t3, { rate: 10000, round: true });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.equal(err.requiredFunds, 25000);

    const accounts = await w1.getAccounts();
    assert.deepEqual(accounts, ['default', 'foo']);
  });

  it('should fail to fill tx with account 1', async () => {
    const w = await wdb.create();

    wallet = w;

    const acc = await w.createAccount({ name: 'foo' });
    assert.equal(acc.name, 'foo');
    assert.equal(acc.accountIndex, 1);

    const account = await w.getAccount('foo');
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
    let t1 = new MTX();
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Should fill from `foo` and fail
    let t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    let err;
    try {
      await w.fund(t2, { rate: 10000, round: true, account: 'foo' });
    } catch (e) {
      err = e;
    }
    assert(err);

    // Should fill from whole wallet and succeed
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    await w.fund(t2, { rate: 10000, round: true });

    // Coinbase
    t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(account.receive.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);
    t1.addOutput(account.receive.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Should fill from `foo` and succeed
    t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    await w.fund(t2, { rate: 10000, round: true, account: 'foo' });
  });

  it('should create two accounts (multiple encryption)', async () => {
    let w = await wdb.create({ id: 'foobar', passphrase: 'foo' });

    await w.destroy();

    w = await wdb.get('foobar');

    const account = await w.createAccount({ name: 'foo1' }, 'foo');
    assert(account);

    await w.lock();
  });

  it('should fill tx with inputs when encrypted', async () => {
    const w = await wdb.create({ passphrase: 'foo' });

    w.master.stop();
    w.master.key = null;

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1.addOutput(w.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(w.getAddress(), 5460);
    await w.fund(t2, { rate: 10000, round: true });

    // Should fail
    let err;
    try {
      await w.sign(t2, 'bar');
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!t2.verify());

    // Should succeed
    await w.sign(t2, 'foo');
    assert(t2.verify());
  });

  it('should fill tx with inputs with subtract fee (1)', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(w2.getAddress(), 21840);
    await w1.fund(t2, { rate: 10000, round: true, subtractFee: true });
    await w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 5460 * 4);
    assert.equal(t2.getOutputValue(), 21840 - 10000);
    assert.equal(t2.getFee(), 10000);
  });

  it('should fill tx with inputs with subtract fee (2)', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    const options = {
      subtractFee: true,
      rate: 10000,
      round: true,
      outputs: [{ address: w2.getAddress(), value: 21840 }]
    };

    // Create new transaction
    const t2 = await w1.createTX(options);
    await w1.sign(t2);

    assert(t2.verify());

    assert.equal(t2.getInputValue(), 5460 * 4);
    assert.equal(t2.getOutputValue(), 21840 - 10000);
    assert.equal(t2.getFee(), 10000);
  });

  it('should fill tx with smart coin selection', async () => {
    const w1 = await wdb.create();
    const w2 = await wdb.create();
    let found = false;
    let total = 0;

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1.addOutput(w1.getAddress(), 5460);
    t1 = t1.toTX();

    await wdb.addTX(t1);

    // Coinbase
    let t2 = new MTX();
    t2.addInput(dummy());
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2.addOutput(w1.getAddress(), 5460);
    t2 = t2.toTX();

    const block = nextBlock();

    await wdb.addBlock(block, [t2]);

    let coins = await w1.getSmartCoins();
    assert.equal(coins.length, 4);

    for (let i = 0; i < coins.length; i++) {
      const coin = coins[i];
      assert.equal(coin.height, block.height);
    }

    // Create a change output for ourselves.
    await w1.send({
      subtractFee: true,
      rate: 1000,
      depth: 1,
      outputs: [{ address: w2.getAddress(), value: 1461 }]
    });

    coins = await w1.getSmartCoins();
    assert.equal(coins.length, 4);

    for (let i = 0; i < coins.length; i++) {
      const coin = coins[i];
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
    const options = {
      subtractFee: true,
      smart: true,
      rate: 10000,
      outputs: [{ address: w2.getAddress(), value: total }]
    };

    const t3 = await w1.createTX(options);
    assert.equal(t3.inputs.length, 4);

    found = false;
    for (let i = 0; i < t3.inputs.length; i++) {
      const coin = t3.view.getCoinFor(t3.inputs[i]);
      if (coin.height === -1) {
        assert(!found);
        assert(coin.value < 5460);
        found = true;
      } else {
        assert.equal(coin.height, block.height);
      }
    }

    assert(found);

    await w1.sign(t3);

    assert(t3.verify());
  });

  it('should get range of txs', async () => {
    const w = wallet;
    const txs = await w.getRange({ start: util.now() - 1000 });
    assert.equal(txs.length, 2);
  });

  it('should get range of txs from account', async () => {
    const w = wallet;
    const txs = await w.getRange('foo', { start: util.now() - 1000 });
    assert.equal(txs.length, 2);
  });

  it('should not get range of txs from non-existent account', async () => {
    const w = wallet;
    let txs, err;

    try {
      txs = await w.getRange('bad', { start: 0xdeadbeef - 1000 });
    } catch (e) {
      err = e;
    }

    assert(!txs);
    assert(err);
    assert.equal(err.message, 'Account not found.');
  });

  it('should get account balance', async () => {
    const w = wallet;
    const balance = await w.getBalance('foo');
    assert.equal(balance.unconfirmed, 21840);
  });

  it('should import privkey', async () => {
    const key = KeyRing.generate();
    const w = await wdb.create({ passphrase: 'test' });

    await w.importKey('default', key, 'test');

    const k = await w.getKey(key.getHash('hex'));

    assert.equal(k.getHash('hex'), key.getHash('hex'));

    // Coinbase
    let t1 = new MTX();
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);

    t1.addInput(dummy());
    t1 = t1.toTX();

    await wdb.addTX(t1);

    const wtx = await w.getTX(t1.hash('hex'));
    assert(wtx);
    assert.equal(t1.hash('hex'), wtx.hash);

    const options = {
      rate: 10000,
      round: true,
      outputs: [{ address: w.getAddress(), value: 7000 }]
    };

    // Create new transaction
    const t2 = await w.createTX(options);
    await w.sign(t2);
    assert(t2.verify());
    assert(t2.inputs[0].prevout.hash === wtx.hash);

    ewallet = w;
    ekey = key;
  });

  it('should import pubkey', async () => {
    const priv = KeyRing.generate();
    const key = new KeyRing(priv.publicKey);
    const w = await wdb.create({ watchOnly: true });

    await w.importKey('default', key);

    let k = await w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = await w.getKey(key.getHash('hex'));
    assert(k);
  });

  it('should import address', async () => {
    const key = KeyRing.generate();
    const w = await wdb.create({ watchOnly: true });

    await w.importAddress('default', key.getAddress());

    let k = await w.getPath(key.getHash('hex'));

    assert.equal(k.hash, key.getHash('hex'));

    k = await w.getKey(key.getHash('hex'));
    assert(!k);
  });

  it('should get details', async () => {
    const w = wallet;
    const txs = await w.getRange('foo', { start: util.now() - 1000 });
    const details = await w.toDetails(txs);
    assert(details.some((tx) => {
      return tx.toJSON().outputs[0].path.name === 'foo';
    }));
  });

  it('should rename wallet', async () => {
    const w = wallet;
    await wallet.rename('test');
    const txs = await w.getRange('foo', { start: util.now() - 1000 });
    const details = await w.toDetails(txs);
    assert.equal(details[0].toJSON().id, 'test');
  });

  it('should change passphrase with encrypted imports', async () => {
    const w = ewallet;
    const addr = ekey.getAddress();

    assert(w.master.encrypted);

    let path = await w.getPath(addr);
    assert(path);
    assert(path.data && path.encrypted);
    const d1 = path.data;

    await w.decrypt('test');

    path = await w.getPath(addr);
    assert(path);
    assert(path.data && !path.encrypted);

    let k = await w.getKey(addr);
    assert(k);

    await w.encrypt('foo');

    path = await w.getPath(addr);
    assert(path);
    assert(path.data && path.encrypted);
    const d2 = path.data;

    assert(!d1.equals(d2));

    k = await w.getKey(addr);
    assert(!k);

    await w.unlock('foo');
    k = await w.getKey(addr);
    assert(k);
    assert.equal(k.getHash('hex'), addr.getHash('hex'));
  });

  it('should recover from a missed tx', async () => {
    const wdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    await wdb.open();

    const alice = await wdb.create({ master: KEY1 });
    const bob = await wdb.create({ master: KEY1 });
    const addr = alice.getAddress();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(addr, 50000);
    t1 = t1.toTX();

    await alice.add(t1);
    await bob.add(t1);

    // Bob misses this tx!
    let t2 = new MTX();
    t2.addTX(t1, 0);
    t2.addOutput(addr, 24000);
    t2.addOutput(addr, 24000);

    await alice.sign(t2);
    t2 = t2.toTX();

    await alice.add(t2);

    assert.notEqual(
      (await alice.getBalance()).unconfirmed,
      (await bob.getBalance()).unconfirmed);

    // Bob sees this one.
    let t3 = new MTX();
    t3.addTX(t2, 0);
    t3.addTX(t2, 1);
    t3.addOutput(addr, 30000);

    await alice.sign(t3);
    t3 = t3.toTX();

    assert.equal((await bob.getBalance()).unconfirmed, 50000);

    await alice.add(t3);
    await bob.add(t3);

    assert.equal((await alice.getBalance()).unconfirmed, 30000);

    // Bob sees t2 on the chain.
    await bob.add(t2);

    // Bob sees t3 on the chain.
    await bob.add(t3);

    assert.equal((await bob.getBalance()).unconfirmed, 30000);
  });

  it('should recover from a missed tx and double spend', async () => {
    const wdb = new WalletDB({
      name: 'wallet-test',
      db: 'memory',
      verify: false
    });

    await wdb.open();

    const alice = await wdb.create({ master: KEY1 });
    const bob = await wdb.create({ master: KEY1 });
    const addr = alice.getAddress();

    // Coinbase
    let t1 = new MTX();
    t1.addInput(dummy());
    t1.addOutput(addr, 50000);
    t1 = t1.toTX();

    await alice.add(t1);
    await bob.add(t1);

    // Bob misses this tx!
    let t2 = new MTX();
    t2.addTX(t1, 0);
    t2.addOutput(addr, 24000);
    t2.addOutput(addr, 24000);

    await alice.sign(t2);
    t2 = t2.toTX();

    await alice.add(t2);

    assert.notEqual(
      (await alice.getBalance()).unconfirmed,
      (await bob.getBalance()).unconfirmed);

    // Bob doublespends.
    let t2a = new MTX();
    t2a.addTX(t1, 0);
    t2a.addOutput(addr, 10000);
    t2a.addOutput(addr, 10000);

    await bob.sign(t2a);
    t2a = t2a.toTX();

    await bob.add(t2a);

    // Bob sees this one.
    let t3 = new MTX();
    t3.addTX(t2, 0);
    t3.addTX(t2, 1);
    t3.addOutput(addr, 30000);

    await alice.sign(t3);
    t3 = t3.toTX();

    assert.equal((await bob.getBalance()).unconfirmed, 20000);

    await alice.add(t3);
    await bob.add(t3);

    assert.equal((await alice.getBalance()).unconfirmed, 30000);

    // Bob sees t2 on the chain.
    await bob.add(t2);

    // Bob sees t3 on the chain.
    await bob.add(t3);

    assert.equal((await bob.getBalance()).unconfirmed, 30000);
  });

  it('should cleanup', () => {
    consensus.COINBASE_MATURITY = 100;
  });
});

/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const consensus = require('../lib/protocol/consensus');
const util = require('../lib/utils/util');
const hash256 = require('bcrypto/lib/hash256');
const random = require('bcrypto/lib/random');
const WalletDB = require('../lib/wallet/walletdb');
const WorkerPool = require('../lib/workers/workerpool');
const Address = require('../lib/primitives/address');
const MTX = require('../lib/primitives/mtx');
const Coin = require('../lib/primitives/coin');
const KeyRing = require('../lib/primitives/keyring');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');
const Script = require('../lib/script/script');
const HD = require('../lib/hd');
const Wallet = require('../lib/wallet/wallet');
const nodejsUtil = require('util');

const KEY1 = 'xprv9s21ZrQH143K3Aj6xQBymM31Zb4BVc7wxqfUhMZrzewdDVCt'
  + 'qUP9iWfcHgJofs25xbaUpCps9GDXj83NiWvQCAkWQhVj5J4CorfnpKX94AZ';

const KEY2 = 'xprv9s21ZrQH143K3mqiSThzPtWAabQ22Pjp3uSNnZ53A5bQ4udp'
  + 'faKekc2m4AChLYH1XDzANhrSdxHYWUeTWjYJwFwWFyHkTMnMeAcW4JyRCZa';

// abandon abandon... about key at m'/44'/0'/0'
const PUBKEY = 'xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhaw'
  + 'A7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj';

const workers = new WorkerPool({
  enabled: true,
  size: 2
});

const wdb = new WalletDB({ workers });

let currentWallet = null;
let importedWallet = null;
let importedKey = null;
let doubleSpendWallet = null;
let doubleSpendCoin = null;

function fromU32(num) {
  const data = Buffer.allocUnsafe(4);
  data.writeUInt32LE(num, 0, true);
  return data;
}

function curBlock(wdb) {
  return fakeBlock(wdb.state.height);
};

function nextBlock(wdb) {
  return fakeBlock(wdb.state.height + 1);
}

function fakeBlock(height) {
  const prev = hash256.digest(fromU32((height - 1) >>> 0));
  const hash = hash256.digest(fromU32(height >>> 0));
  const root = hash256.digest(fromU32((height | 0x80000000) >>> 0));

  return {
    hash: hash,
    prevBlock: prev,
    merkleRoot: root,
    time: 500000000 + (height * (10 * 60)),
    bits: 0,
    nonce: 0,
    height: height
  };
}

function dummyInput() {
  const hash = random.randomBytes(32);
  return Input.fromOutpoint(new Outpoint(hash, 0));
}

async function testP2PKH(witness, nesting) {
  const flags = Script.flags.STANDARD_VERIFY_FLAGS;
  const receiveAddress = nesting ? 'nestedAddress' : 'receiveAddress';
  const type = witness ? Address.types.WITNESS : Address.types.PUBKEYHASH;
  const wallet = await wdb.create({ witness });

  const waddr = await wallet.receiveAddress();
  const addr = Address.fromString(waddr.toString(wdb.network), wdb.network);

  assert.strictEqual(addr.type, type);
  assert.strictEqual(addr.type, waddr.type);

  const src = new MTX();
  src.addInput(dummyInput());
  src.addOutput(await wallet[receiveAddress](), 5460 * 2);
  src.addOutput(new Address(), 2 * 5460);

  const mtx = new MTX();
  mtx.addTX(src, 0);
  mtx.addOutput(await wallet.receiveAddress(), 5460);

  await wallet.sign(mtx);

  const [tx, view] = mtx.commit();

  assert(tx.verify(view, flags));
}

async function testP2SH(witness, nesting) {
  const flags = Script.flags.STANDARD_VERIFY_FLAGS;
  const receiveAddress = nesting ? 'nestedAddress' : 'receiveAddress';
  const receiveDepth = nesting ? 'nestedDepth' : 'receiveDepth';
  const vector = witness ? 'witness' : 'script';

  // Create 3 2-of-3 wallets with our pubkeys as "shared keys"
  const options = {
    witness,
    type: 'multisig',
    m: 2,
    n: 3
  };

  const alice = await wdb.create(options);
  const bob = await wdb.create(options);
  const carol = await wdb.create(options);
  const recipient = await wdb.create();

  await alice.addSharedKey(0, await bob.accountKey(0));
  await alice.addSharedKey(0, await carol.accountKey(0));

  await bob.addSharedKey(0, await alice.accountKey(0));
  await bob.addSharedKey(0, await carol.accountKey(0));

  await carol.addSharedKey(0, await alice.accountKey(0));
  await carol.addSharedKey(0, await bob.accountKey(0));

  // Our p2sh address
  const addr1 = await alice[receiveAddress]();

  if (witness) {
    const type = nesting ? Address.types.SCRIPTHASH : Address.types.WITNESS;
    assert.strictEqual(addr1.type, type);
  } else {
    assert.strictEqual(addr1.type, Address.types.SCRIPTHASH);
  }

  assert((await alice[receiveAddress]()).equals(addr1));
  assert((await bob[receiveAddress]()).equals(addr1));
  assert((await carol[receiveAddress]()).equals(addr1));

  const nestedAddr1 = await alice.nestedAddress();

  if (witness) {
    assert(nestedAddr1);
    assert((await alice.nestedAddress()).equals(nestedAddr1));
    assert((await bob.nestedAddress()).equals(nestedAddr1));
    assert((await carol.nestedAddress()).equals(nestedAddr1));
  }

  {
    // Add a shared unspent transaction to our wallets
    const fund = new MTX();
    fund.addInput(dummyInput());
    fund.addOutput(nesting ? nestedAddr1 : addr1, 5460 * 10);

    // Simulate a confirmation
    assert.strictEqual(await alice[receiveDepth](), 1);

    await wdb.addBlock(nextBlock(wdb), [fund.toTX()]);

    assert.strictEqual(await alice[receiveDepth](), 2);
    assert.strictEqual(await alice.changeDepth(), 1);
  }

  const addr2 = await alice[receiveAddress]();
  assert(!addr2.equals(addr1));

  assert((await alice[receiveAddress]()).equals(addr2));
  assert((await bob[receiveAddress]()).equals(addr2));
  assert((await carol[receiveAddress]()).equals(addr2));

  // Create a tx requiring 2 signatures
  const send = new MTX();

  send.addOutput(await recipient.receiveAddress(), 5460);

  assert(!send.verify(flags));

  await alice.fund(send, {
    rate: 10000,
    round: true
  });

  await alice.sign(send);

  assert(!send.verify(flags));

  await bob.sign(send);

  const [tx, view] = send.commit();
  assert(tx.verify(view, flags));

  assert.strictEqual(await alice.changeDepth(), 1);

  const change = await alice.changeAddress();

  assert((await alice.changeAddress()).equals(change));
  assert((await bob.changeAddress()).equals(change));
  assert((await carol.changeAddress()).equals(change));

  // Simulate a confirmation
  {
    await wdb.addBlock(nextBlock(wdb), [tx]);

    assert.strictEqual(await alice[receiveDepth](), 2);
    assert.strictEqual(await alice.changeDepth(), 2);

    assert((await alice[receiveAddress]()).equals(addr2));
    assert(!(await alice.changeAddress()).equals(change));
  }

  const change2 = await alice.changeAddress();

  assert((await alice.changeAddress()).equals(change2));
  assert((await bob.changeAddress()).equals(change2));
  assert((await carol.changeAddress()).equals(change2));

  const input = tx.inputs[0];
  input[vector].setData(2, Buffer.alloc(73, 0x00));
  input[vector].compile();

  assert(!tx.verify(view, flags));
  assert.strictEqual(tx.getFee(view), 10000);
}

describe('Wallet', function() {
  this.timeout(process.browser ? 20000 : 5000);

  before(async () => {
    await wdb.open();
    await workers.open();
  });

  after(async () => {
    await wdb.close();
    await workers.close();
  });

  it('should open walletdb', () => {
    consensus.COINBASE_MATURITY = 0;
  });

  it('should generate new key and address', async () => {
    const wallet = await wdb.create();

    const addr1 = await wallet.receiveAddress();
    assert(addr1);

    const str = addr1.toString(wdb.network);
    const addr2 = Address.fromString(str, wdb.network);

    assert(addr2.equals(addr1));
  });

  it('should validate existing address', () => {
    assert(Address.fromString('1KQ1wMNwXHUYj1nV2xzsRcKUH8gVFpTFUc', 'main'));
  });

  it('should fail to validate invalid address', () => {
    assert.throws(() => {
      Address.fromString('1KQ1wMNwXHUYj1nv2xzsRcKUH8gVFpTFUc', 'main');
    });
  });

  it('should create and get wallet', async () => {
    const wallet1 = await wdb.create();
    const wallet2 = await wdb.get(wallet1.id);
    assert(wallet1 === wallet2);
  });

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
    const wallet = await wdb.create({
      type: 'multisig',
      m: 1,
      n: 2
    });

    const xpriv = HD.PrivateKey.generate();
    const key = xpriv.deriveAccount(44, 0, 0).toPublic();

    await wallet.addSharedKey(0, key);

    const script = Script.fromMultisig(1, 2, [
      (await wallet.receiveKey()).publicKey,
      key.derivePath('m/0/0').publicKey
    ]);

    // Input transaction (bare 1-of-2 multisig)
    const src = new MTX();
    src.addInput(dummyInput());
    src.addOutput(script, 5460 * 2);
    src.addOutput(new Address(), 5460 * 2);

    const tx = new MTX();
    tx.addTX(src, 0);
    tx.addOutput(await wallet.receiveAddress(), 5460);

    const maxSize = await tx.estimateSize();

    await wallet.sign(tx);

    assert(tx.toRaw().length <= maxSize);
    assert(tx.verify());
  });

  it('should handle missed txs', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    // balance: 51000
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 50000);
    t1.addOutput(await alice.receiveAddress(), 1000);

    const t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(await alice.receiveAddress(), 24000);
    t2.addOutput(await alice.receiveAddress(), 24000);

    // Save for later.
    doubleSpendWallet = alice;
    doubleSpendCoin = Coin.fromTX(t1, 0, -1);

    // balance: 49000
    await alice.sign(t2);

    const t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(await alice.receiveAddress(), 23000);

    // balance: 47000
    await alice.sign(t3);

    const t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(await alice.receiveAddress(), 11000);
    t4.addOutput(await alice.receiveAddress(), 11000);

    // balance: 22000
    await alice.sign(t4);

    const f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(await bob.receiveAddress(), 10000);

    // balance: 11000
    await alice.sign(f1);

    {
      await wdb.addTX(t4.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 22000);
    }

    {
      await wdb.addTX(t1.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 73000);
    }

    {
      await wdb.addTX(t2.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 71000);
    }

    {
      await wdb.addTX(t3.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 69000);
    }

    {
      await wdb.addTX(f1.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 58000);

      const txs = await alice.getHistory();
      assert(txs.some((wtx) => {
        return wtx.hash.equals(f1.hash());
      }));
    }

    {
      const balance = await bob.getBalance();
      assert.strictEqual(balance.unconfirmed, 10000);

      const txs = await bob.getHistory();
      assert(txs.some((wtx) => {
        return wtx.tx.hash().equals(f1.hash());
      }));
    }

    // Should recover from missed txs on block.
    await wdb.addBlock(nextBlock(wdb), [
      t1.toTX(),
      t2.toTX(),
      t3.toTX(),
      t4.toTX(),
      f1.toTX()
    ]);

    {
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 11000);
      assert.strictEqual(balance.confirmed, 11000);

      const txs = await alice.getHistory();
      assert(txs.some((wtx) => {
        return wtx.hash.equals(f1.hash());
      }));
    }

    {
      const balance = await bob.getBalance();
      assert.strictEqual(balance.unconfirmed, 10000);
      assert.strictEqual(balance.confirmed, 10000);

      const txs = await bob.getHistory();
      assert(txs.some((wtx) => {
        return wtx.tx.hash().equals(f1.hash());
      }));
    }
  });

  it('should cleanup spenders after double-spend', async () => {
    const wallet = doubleSpendWallet;

    // Reorg and unconfirm all previous txs.
    await wdb.removeBlock(curBlock(wdb));

    {
      const txs = await wallet.getHistory();
      assert.strictEqual(txs.length, 5);

      const total = txs.reduce((t, wtx) => {
        return t + wtx.tx.getOutputValue();
      }, 0);
      assert.strictEqual(total, 154000);
    }

    {
      const balance = await wallet.getBalance();
      assert.strictEqual(balance.unconfirmed, 11000);
      assert.strictEqual(balance.confirmed, 0);
    }

    {
      const tx = new MTX();
      tx.addCoin(doubleSpendCoin);
      tx.addOutput(await wallet.receiveAddress(), 5000);

      await wallet.sign(tx);

      await wdb.addTX(tx.toTX());

      const balance = await wallet.getBalance();
      assert.strictEqual(balance.unconfirmed, 6000);
    }

    {
      const txs = await wallet.getHistory();
      assert.strictEqual(txs.length, 2);

      const total = txs.reduce((t, wtx) => {
        return t + wtx.tx.getOutputValue();
      }, 0);
      assert.strictEqual(total, 56000);
    }
  });

  it('should handle double-spend (not our input)', async () => {
    const wallet = await wdb.create();

    const t1 = new MTX();
    const input = dummyInput();
    t1.addInput(input);
    t1.addOutput(await wallet.receiveAddress(), 50000);
    await wdb.addTX(t1.toTX());
    assert.strictEqual((await wallet.getBalance()).unconfirmed, 50000);

    let conflict = false;
    wallet.on('conflict', () => {
      conflict = true;
    });

    const t2 = new MTX();
    t2.addInput(input);
    t2.addOutput(new Address(), 5000);
    await wdb.addTX(t2.toTX());
    assert(conflict);
    assert.strictEqual((await wallet.getBalance()).unconfirmed, 0);
  });

  it('should handle double-spend (multiple inputs)', async () => {
    const wallet = await wdb.create();
    const address = await wallet.receiveAddress();

    const hash = random.randomBytes(32);
    const input0 = Input.fromOutpoint(new Outpoint(hash, 0));
    const input1 = Input.fromOutpoint(new Outpoint(hash, 1));

    const txa = new MTX();
    txa.addInput(input0);
    txa.addInput(input1);
    txa.addOutput(address, 50000);
    await wdb.addTX(txa.toTX());
    assert.strictEqual((await wallet.getBalance()).unconfirmed, 50000);

    let conflict = false;
    wallet.on('conflict', () => {
      conflict = true;
    });

    const txb = new MTX();
    txb.addInput(input0);
    txb.addInput(input1);
    txb.addOutput(address, 49000);
    await wdb.addTX(txb.toTX());

    assert(conflict);
    assert.strictEqual((await wallet.getBalance()).unconfirmed, 49000);
  });

  it('should handle more missed txs', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 50000);
    t1.addOutput(await alice.receiveAddress(), 1000);

    // balance: 51000

    const t2 = new MTX();
    t2.addTX(t1, 0); // 50000
    t2.addOutput(await alice.receiveAddress(), 24000);
    t2.addOutput(await alice.receiveAddress(), 24000);

    // balance: 49000
    await alice.sign(t2);

    const t3 = new MTX();
    t3.addTX(t1, 1); // 1000
    t3.addTX(t2, 0); // 24000
    t3.addOutput(await alice.receiveAddress(), 23000);

    // balance: 47000
    await alice.sign(t3);

    const t4 = new MTX();
    t4.addTX(t2, 1); // 24000
    t4.addTX(t3, 0); // 23000
    t4.addOutput(await alice.receiveAddress(), 11000);
    t4.addOutput(await alice.receiveAddress(), 11000);

    // balance: 22000
    await alice.sign(t4);

    const f1 = new MTX();
    f1.addTX(t4, 1); // 11000
    f1.addOutput(await bob.receiveAddress(), 10000);

    // balance: 11000
    await alice.sign(f1);

    {
      await wdb.addTX(t4.toTX());
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 22000);
    }

    {
      await wdb.addTX(t1.toTX());
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 73000);
    }

    {
      await wdb.addTX(t2.toTX());
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 71000);
    }

    {
      await wdb.addTX(t3.toTX());
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 69000);
    }

    {
      await wdb.addTX(f1.toTX());

      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 58000);

      const txs = await alice.getHistory();
      assert(txs.some((wtx) => {
        return wtx.tx.hash().equals(f1.hash());
      }));
    }

    {
      const balance = await bob.getBalance();
      assert.strictEqual(balance.unconfirmed, 10000);

      const txs = await bob.getHistory();
      assert(txs.some((wtx) => {
        return wtx.tx.hash().equals(f1.hash());
      }));
    }

    // Should recover from missed txs on block.
    await wdb.addBlock(nextBlock(wdb), [
      t1.toTX(),
      t2.toTX(),
      t3.toTX(),
      t4.toTX(),
      f1.toTX()
    ]);

    {
      const balance = await alice.getBalance();
      assert.strictEqual(balance.unconfirmed, 11000);
    }

    {
      const balance = await bob.getBalance();
      assert.strictEqual(balance.unconfirmed, 10000);
    }
  });

  it('should fill tx with inputs', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Create new transaction
    const m2 = new MTX();
    m2.addOutput(await bob.receiveAddress(), 5460);

    await alice.fund(m2, {
      rate: 10000,
      round: true
    });

    await alice.sign(m2);

    const [t2, v2] = m2.commit();

    assert(t2.verify(v2));

    assert.strictEqual(t2.getInputValue(v2), 16380);
    assert.strictEqual(t2.getOutputValue(), 6380);
    assert.strictEqual(t2.getFee(v2), 10000);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(await bob.receiveAddress(), 15000);

    let err;
    try {
      await alice.fund(t3, {
        rate: 10000,
        round: true
      });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.requiredFunds, 25000);
  });

  it('should fill tx with inputs with accurate fee', async () => {
    const alice = await wdb.create({
      master: KEY1
    });

    const bob = await wdb.create({
      master: KEY2
    });

    // Coinbase
    const t1 = new MTX();
    t1.addOutpoint(new Outpoint(consensus.ZERO_HASH, 0));
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Create new transaction
    const m2 = new MTX();
    m2.addOutput(await bob.receiveAddress(), 5460);

    await alice.fund(m2, {
      rate: 10000
    });

    await alice.sign(m2);

    const [t2, v2] = m2.commit();

    assert(t2.verify(v2));

    assert.strictEqual(t2.getInputValue(v2), 16380);

    // Should now have a change output:
    assert.strictEqual(t2.getOutputValue(), 11130);

    assert.strictEqual(t2.getFee(v2), 5250);

    assert.strictEqual(t2.getWeight(), 2084);
    assert.strictEqual(t2.getBaseSize(), 521);
    assert.strictEqual(t2.getSize(), 521);
    assert.strictEqual(t2.getVirtualSize(), 521);

    let balance = null;
    bob.once('balance', (b) => {
      balance = b;
    });

    await wdb.addTX(t2);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(await bob.receiveAddress(), 15000);

    let err;
    try {
      await alice.fund(t3, {
        rate: 10000
      });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(balance);
    assert.strictEqual(balance.unconfirmed, 5460);
  });

  it('should sign multiple inputs using different keys', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();
    const carol = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    // Coinbase
    const t2 = new MTX();
    t2.addInput(dummyInput());
    t2.addOutput(await bob.receiveAddress(), 5460);
    t2.addOutput(await bob.receiveAddress(), 5460);
    t2.addOutput(await bob.receiveAddress(), 5460);
    t2.addOutput(await bob.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());
    await wdb.addTX(t2.toTX());

    // Create our tx with an output
    const tx = new MTX();
    tx.addOutput(await carol.receiveAddress(), 5460);

    const coins1 = await alice.getCoins();
    const coins2 = await bob.getCoins();

    // Add our unspent inputs to sign
    tx.addCoin(coins1[0]);
    tx.addCoin(coins1[1]);
    tx.addCoin(coins2[0]);

    // Sign transaction
    assert.strictEqual(await alice.sign(tx), 2);
    assert.strictEqual(await bob.sign(tx), 1);

    // Verify
    assert.strictEqual(tx.verify(), true);

    tx.inputs.length = 0;
    tx.addCoin(coins1[1]);
    tx.addCoin(coins1[2]);
    tx.addCoin(coins2[1]);

    assert.strictEqual(await alice.sign(tx), 2);
    assert.strictEqual(await bob.sign(tx), 1);

    // Verify
    assert.strictEqual(tx.verify(), true);
  });

  it('should verify 2-of-3 p2sh tx', async () => {
    await testP2SH(false, false);
  });

  it('should verify 2-of-3 p2wsh tx', async () => {
    await testP2SH(true, false);
  });

  it('should verify 2-of-3 p2wsh tx w/ nested bullshit', async () => {
    await testP2SH(true, true);
  });

  it('should create account', async () => {
    const wallet = await wdb.create();
    const account = await wallet.createAccount({
      name: 'foo'
    });

    assert(account);
    assert(account.initialized);
    assert.strictEqual(account.name, 'foo');
    assert.strictEqual(account.accountIndex, 1);
    assert.strictEqual(account.m, 1);
    assert.strictEqual(account.n, 1);
  });

  it('should inspect Wallet', async () => {
    const wallet = await wdb.create();

    const fmt = nodejsUtil.format(wallet);
    assert(typeof fmt === 'string');
    assert(fmt.includes('master'));
    assert(fmt.includes('network'));
    assert(fmt.includes('accountDepth'));
  });

  it('should inspect Account', async () => {
    const wallet = await wdb.create();
    const account = await wallet.createAccount({
      name: 'foo'
    });

    const fmt = nodejsUtil.format(account);
    assert(typeof fmt === 'string');
    assert(fmt.includes('name'));
    assert(fmt.includes('foo'));
    assert(fmt.includes('initialized'));
    assert(fmt.includes('lookahead'));
  });

  it('should fail to create duplicate account', async () => {
    const wallet = await wdb.create();
    const name = 'foo';

    await wallet.createAccount({ name });

    let err;
    try {
      await wallet.createAccount({ name });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.message, 'Account already exists.');
  });

  it('should fill tx with account 1', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    {
      const account = await alice.createAccount({
        name: 'foo'
      });
      assert.strictEqual(account.name, 'foo');
      assert.strictEqual(account.accountIndex, 1);
    }

    const account = await alice.getAccount('foo');
    assert.strictEqual(account.name, 'foo');
    assert.strictEqual(account.accountIndex, 1);

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(account.receiveAddress(), 5460);
    t1.addOutput(account.receiveAddress(), 5460);
    t1.addOutput(account.receiveAddress(), 5460);
    t1.addOutput(account.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(await bob.receiveAddress(), 5460);

    await alice.fund(t2, {
      rate: 10000,
      round: true
    });

    await alice.sign(t2);

    assert(t2.verify());

    assert.strictEqual(t2.getInputValue(), 16380);
    assert.strictEqual(t2.getOutputValue(), 6380);
    assert.strictEqual(t2.getFee(), 10000);

    // Create new transaction
    const t3 = new MTX();
    t3.addOutput(await bob.receiveAddress(), 15000);

    let err;
    try {
      await alice.fund(t3, {
        rate: 10000,
        round: true
      });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(err.requiredFunds, 25000);

    const accounts = await alice.getAccounts();
    assert.deepStrictEqual(accounts, ['default', 'foo']);
  });

  it('should fail to fill tx with account 1', async () => {
    const wallet = await wdb.create();

    {
      const account = await wallet.createAccount({
        name: 'foo'
      });
      assert.strictEqual(account.name, 'foo');
      assert.strictEqual(account.accountIndex, 1);
    }

    const account = await wallet.getAccount('foo');
    assert.strictEqual(account.name, 'foo');
    assert.strictEqual(account.accountIndex, 1);

    assert(!account.receiveAddress().equals(await wallet.receiveAddress()));

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(account.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Should fill from `foo` and fail
    const t2 = new MTX();

    t2.addOutput(await wallet.receiveAddress(), 5460);

    let err;
    try {
      await wallet.fund(t2, {
        rate: 10000,
        round: true,
        account: 'foo'
      });
    } catch (e) {
      err = e;
    }

    assert(err);

    // Should fill from whole wallet and succeed
    const t3 = new MTX();
    t3.addOutput(await wallet.receiveAddress(), 5460);

    await wallet.fund(t3, {
      rate: 10000,
      round: true
    });

    // Coinbase
    const t4 = new MTX();
    t4.addInput(dummyInput());
    t4.addOutput(await wallet.receiveAddress('foo'), 5460);
    t4.addOutput(await wallet.receiveAddress('foo'), 5460);
    t4.addOutput(await wallet.receiveAddress('foo'), 5460);

    await wdb.addTX(t4.toTX());

    // Should fill from `foo` and succeed
    const t5 = new MTX();
    t5.addOutput(await wallet.receiveAddress(), 5460);

    await wallet.fund(t5, {
      rate: 10000,
      round: true,
      account: 'foo'
    });

    currentWallet = wallet;
  });

  it('should create two accounts (multiple encryption)', async () => {
    {
      const wallet = await wdb.create({
        id: 'foobar',
        passphrase: 'foo'
      });
      await wallet.destroy();
      wdb.unregister(wallet);
    }

    const wallet = await wdb.get('foobar');
    assert(wallet);

    const options = {
      name: 'foo1'
    };

    const account = await wallet.createAccount(options, 'foo');

    assert(account);

    await wallet.lock();
  });

  it('should fill tx with inputs when encrypted', async () => {
    const wallet = await wdb.create({
      passphrase: 'foo'
    });

    wallet.master.stop();
    wallet.master.key = null;

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(await wallet.receiveAddress(), 5460);
    t1.addOutput(await wallet.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(await wallet.receiveAddress(), 5460);

    await wallet.fund(t2, {
      rate: 10000,
      round: true
    });

    // Should fail
    let err;
    try {
      await wallet.sign(t2, 'bar');
    } catch (e) {
      err = e;
    }

    assert(err);
    assert(!t2.verify());

    // Should succeed
    await wallet.sign(t2, 'foo');
    assert(t2.verify());
  });

  it('should fill tx with inputs with subtract fee (1)', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Create new transaction
    const t2 = new MTX();
    t2.addOutput(await bob.receiveAddress(), 21840);

    await alice.fund(t2, {
      rate: 10000,
      round: true,
      subtractFee: true
    });

    await alice.sign(t2);

    assert(t2.verify());

    assert.strictEqual(t2.getInputValue(), 5460 * 4);
    assert.strictEqual(t2.getOutputValue(), 21840 - 10000);
    assert.strictEqual(t2.getFee(), 10000);
  });

  it('should fill tx with inputs with subtract fee (2)', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    const options = {
      subtractFee: true,
      rate: 10000,
      round: true,
      outputs: [{ address: await bob.receiveAddress(), value: 21840 }]
    };

    // Create new transaction
    const t2 = await alice.createTX(options);
    await alice.sign(t2);

    assert(t2.verify());

    assert.strictEqual(t2.getInputValue(), 5460 * 4);
    assert.strictEqual(t2.getOutputValue(), 21840 - 10000);
    assert.strictEqual(t2.getFee(), 10000);
  });

  it('should fill tx with smart coin selection', async () => {
    const alice = await wdb.create();
    const bob = await wdb.create();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);
    t1.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addTX(t1.toTX());

    // Coinbase
    const t2 = new MTX();
    t2.addInput(dummyInput());
    t2.addOutput(await alice.receiveAddress(), 5460);
    t2.addOutput(await alice.receiveAddress(), 5460);
    t2.addOutput(await alice.receiveAddress(), 5460);
    t2.addOutput(await alice.receiveAddress(), 5460);

    await wdb.addBlock(nextBlock(wdb), [t2.toTX()]);

    {
      const coins = await alice.getSmartCoins();
      assert.strictEqual(coins.length, 4);

      for (let i = 0; i < coins.length; i++) {
        const coin = coins[i];
        assert.strictEqual(coin.height, wdb.state.height);
      }
    }

    // Create a change output for ourselves.
    await alice.send({
      subtractFee: true,
      rate: 1000,
      depth: 1,
      outputs: [{ address: await bob.receiveAddress(), value: 1461 }]
    });

    const coins = await alice.getSmartCoins();
    assert.strictEqual(coins.length, 4);

    let total = 0;

    {
      let found = false;

      for (let i = 0; i < coins.length; i++) {
        const coin = coins[i];
        if (coin.height === -1) {
          assert(!found);
          assert(coin.value < 5460);
          found = true;
        } else {
          assert.strictEqual(coin.height, wdb.state.height);
        }
        total += coin.value;
      }

      assert(found);
    }

    // Use smart selection
    const options = {
      subtractFee: true,
      smart: true,
      rate: 10000,
      outputs: [{
        address: await bob.receiveAddress(),
        value: total
      }]
    };

    const t3 = await alice.createTX(options);
    assert.strictEqual(t3.inputs.length, 4);

    {
      let found = false;

      for (let i = 0; i < t3.inputs.length; i++) {
        const coin = t3.view.getCoinFor(t3.inputs[i]);
        if (coin.height === -1) {
          assert(!found);
          assert(coin.value < 5460);
          found = true;
        } else {
          assert.strictEqual(coin.height, wdb.state.height);
        }
      }

      assert(found);
    }

    await alice.sign(t3);

    assert(t3.verify());
  });

  for (const witness of [true, false]) {
    it(`should create non-templated tx (witness=${witness})`, async () => {
      const wallet = await wdb.create({ witness });

      // Fund wallet
      const t1 = new MTX();
      t1.addInput(dummyInput());
      t1.addOutput(await wallet.receiveAddress(), 500000);

      await wdb.addTX(t1.toTX());

      const options = {
        rate: 10000,
        round: true,
        outputs: [{
          address: await wallet.receiveAddress(),
          value: 7000
        }],
        template: false
      };

      const t2 = await wallet.createTX(options);

      assert(t2, 'Could not create tx.');

      for (const input of t2.inputs) {
        const {script, witness} = input;

        assert.strictEqual(script.length, 0, 'Input is templated.');
        assert.strictEqual(witness.length, 0, 'Input is templated.');
      }
    });
  }

  it('should get range of txs', async () => {
    const wallet = currentWallet;
    const txs = await wallet.getRange(null, {
      start: util.now() - 1000
    });
    assert.strictEqual(txs.length, 2);
  });

  it('should get range of txs from account', async () => {
    const wallet = currentWallet;
    const txs = await wallet.getRange('foo', {
      start: util.now() - 1000
    });
    assert.strictEqual(txs.length, 2);
  });

  it('should not get range of txs from non-existent account', async () => {
    const wallet = currentWallet;

    let txs, err;
    try {
      txs = await wallet.getRange('bad', {
        start: 0xdeadbeef - 1000
      });
    } catch (e) {
      err = e;
    }

    assert(!txs);
    assert(err);
    assert.strictEqual(err.message, 'Account not found.');
  });

  it('should get account balance', async () => {
    const wallet = currentWallet;
    const balance = await wallet.getBalance('foo');
    assert.strictEqual(balance.unconfirmed, 21840);
  });

  it('should import privkey', async () => {
    const key = KeyRing.generate();

    const wallet = await wdb.create({
      passphrase: 'test'
    });

    await wallet.importKey('default', key, 'test');

    const wkey = await wallet.getKey(key.getHash());

    assert.bufferEqual(wkey.getHash(), key.getHash());

    // Coinbase
    const t1 = new MTX();
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);
    t1.addOutput(key.getAddress(), 5460);

    t1.addInput(dummyInput());

    await wdb.addTX(t1.toTX());

    const wtx = await wallet.getTX(t1.hash());
    assert(wtx);
    assert.bufferEqual(t1.hash(), wtx.hash);

    const options = {
      rate: 10000,
      round: true,
      outputs: [{
        address: await wallet.receiveAddress(),
        value: 7000
      }]
    };

    // Create new transaction
    const t2 = await wallet.createTX(options);
    await wallet.sign(t2);
    assert(t2.verify());
    assert.bufferEqual(t2.inputs[0].prevout.hash, wtx.hash);

    importedWallet = wallet;
    importedKey = key;
  });

  it('should require account key to create watch only wallet', async () => {
    let err = null;

    try {
      await wdb.create({
        watchOnly: true
      });
    } catch (e) {
      err = e;
    }

    assert(err);
    assert.strictEqual(
      err.message,
      'Must add HD public keys to watch only wallet.'
    );
  });

  it('should import pubkey', async () => {
    const key = KeyRing.generate();
    const pub = new KeyRing(key.publicKey);

    const wallet = await wdb.create({
      watchOnly: true,
      accountKey: PUBKEY
    });

    await wallet.importKey('default', pub);

    const path = await wallet.getPath(pub.getHash());
    assert.bufferEqual(path.hash, pub.getHash());

    const wkey = await wallet.getKey(pub.getHash());
    assert(wkey);
  });

  it('should import address', async () => {
    const key = KeyRing.generate();

    const wallet = await wdb.create({
      watchOnly: true,
      accountKey: PUBKEY
    });

    await wallet.importAddress('default', key.getAddress());

    const path = await wallet.getPath(key.getHash());
    assert(path);
    assert.bufferEqual(path.hash, key.getHash());

    const wkey = await wallet.getKey(key.getHash());
    assert(!wkey);
  });

  it('should get details', async () => {
    const wallet = currentWallet;

    const txs = await wallet.getRange('foo', {
      start: util.now() - 1000
    });

    const details = await wallet.toDetails(txs);

    assert(details.some((tx) => {
      return tx.toJSON(wdb.network).outputs[0].path.name === 'foo';
    }));
  });

  it('should rename wallet', async () => {
    const wallet = currentWallet;

    await wallet.rename('test');

    const txs = await wallet.getRange('foo', {
      start: util.now() - 1000
    });

    const details = await wallet.toDetails(txs);

    assert(details.length > 0);
    assert.strictEqual(wallet.id, 'test');
  });

  it('should change passphrase with encrypted imports', async () => {
    const wallet = importedWallet;
    const addr = importedKey.getAddress();

    assert(wallet.master.encrypted);

    let data;
    {
      const path = await wallet.getPath(addr);
      assert(path);
      assert(path.data && path.encrypted);
      data = path.data;
    }

    await wallet.decrypt('test');

    {
      const path = await wallet.getPath(addr);
      assert(path);
      assert(path.data && !path.encrypted);
      assert(await wallet.getKey(addr));
    }

    await wallet.encrypt('foo');

    {
      const path = await wallet.getPath(addr);
      assert(path);
      assert(path.data && path.encrypted);
      assert(!data.equals(path.data));
      assert(!await wallet.getKey(addr));
    }

    await wallet.unlock('foo');

    const key = await wallet.getKey(addr);
    assert(key);
    assert.bufferEqual(key.getHash(), addr.getHash());
  });

  it('should recover from a missed tx', async () => {
    const wdb = new WalletDB({ workers });
    await wdb.open();

    const alice = await wdb.create({
      master: KEY1
    });

    const bob = await wdb.create({
      master: KEY1
    });

    const addr = await alice.receiveAddress();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(addr, 50000);

    await wdb.addTX(t1.toTX());

    // Bob misses this tx!
    const t2 = new MTX();
    t2.addTX(t1, 0);
    t2.addOutput(addr, 24000);
    t2.addOutput(addr, 24000);

    await alice.sign(t2);

    await alice.add(t2.toTX());

    assert.notStrictEqual(
      (await alice.getBalance()).unconfirmed,
      (await bob.getBalance()).unconfirmed);

    // Bob sees this one.
    const t3 = new MTX();
    t3.addTX(t2, 0);
    t3.addTX(t2, 1);
    t3.addOutput(addr, 30000);

    await alice.sign(t3);

    assert.strictEqual((await bob.getBalance()).unconfirmed, 50000);

    await wdb.addTX(t3.toTX());

    assert.strictEqual((await alice.getBalance()).unconfirmed, 30000);

    // t1 gets confirmed.
    await wdb.addBlock(nextBlock(wdb), [t1.toTX()]);

    // Bob sees t2 on the chain.
    await wdb.addBlock(nextBlock(wdb), [t2.toTX()]);

    // Bob sees t3 on the chain.
    await wdb.addBlock(nextBlock(wdb), [t3.toTX()]);

    assert.strictEqual((await bob.getBalance()).unconfirmed, 30000);
  });

  it('should recover from a missed tx and double spend', async () => {
    const wdb = new WalletDB({ workers });
    await wdb.open();

    const alice = await wdb.create({
      master: KEY1
    });

    const bob = await wdb.create({
      master: KEY1
    });

    const addr = await alice.receiveAddress();

    // Coinbase
    const t1 = new MTX();
    t1.addInput(dummyInput());
    t1.addOutput(addr, 50000);

    await wdb.addTX(t1.toTX());

    // Bob misses this tx!
    const t2a = new MTX();
    t2a.addTX(t1, 0);
    t2a.addOutput(addr, 24000);
    t2a.addOutput(addr, 24000);

    await alice.sign(t2a);

    await alice.add(t2a.toTX());

    assert.notStrictEqual(
      (await alice.getBalance()).unconfirmed,
      (await bob.getBalance()).unconfirmed);

    // Bob doublespends.
    const t2b = new MTX();
    t2b.addTX(t1, 0);
    t2b.addOutput(addr, 10000);
    t2b.addOutput(addr, 10000);

    await bob.sign(t2b);

    await bob.add(t2b.toTX());

    // Bob sees this one.
    const t3 = new MTX();
    t3.addTX(t2a, 0);
    t3.addTX(t2a, 1);
    t3.addOutput(addr, 30000);

    await alice.sign(t3);

    assert.strictEqual((await bob.getBalance()).unconfirmed, 20000);

    await wdb.addTX(t3.toTX());

    assert.strictEqual((await alice.getBalance()).unconfirmed, 30000);

    // t1 gets confirmed.
    await wdb.addBlock(nextBlock(wdb), [t1.toTX()]);

    // Bob sees t2a on the chain.
    await wdb.addBlock(nextBlock(wdb), [t2a.toTX()]);

    // Bob sees t3 on the chain.
    await wdb.addBlock(nextBlock(wdb), [t3.toTX()]);

    assert.strictEqual((await bob.getBalance()).unconfirmed, 30000);
  });

  it('should remove a wallet', async () => {
    await wdb.create({
      id: 'alice100'
    });
    assert(await wdb.get('alice100'));
    await wdb.remove('alice100');
    assert(!await wdb.get('alice100'));
  });

  const keyTypes = [
    {
      name: 'receive',
      method: 'createReceive',
      branch: 0
    },
    {
      name: 'change',
      method: 'createChange',
      branch: 1
    },
    {
      name: 'nested',
      method: 'createNested',
      branch: 2
    }
  ];

  for (const type of keyTypes) {
    it(`should create ${type.name} addresses`, async () => {
      const account = 0;
      const wallet = await wdb.create({
        witness: true
      });
      const addresses = new Set();

      for (let i = 0; i < 100; i++) {
        const key = await wallet[type.method](account);
        addresses.add(key.getAddress('string'));
        assert.strictEqual(key.account, account);
        assert.strictEqual(key.branch, type.branch);
        assert.strictEqual(key.index, i + 1);
      }

      assert.strictEqual(addresses.size, 100);
    });

    it(`should create ${type.name} addresses and get their keys`, async () => {
      const account = 0;
      const wallet = await wdb.create({
        witness: true
      });

      const addresses = new Set();

      for (let i = 0; i < 100; i++) {
        const key1 = await wallet[type.method](account);
        const address = key1.getAddress();

        assert(key1, `Could not get ${type.name}`);
        addresses.add(address);

        assert.strictEqual(key1.account, account);
        assert.strictEqual(key1.branch, type.branch);
        assert.strictEqual(key1.index, i + 1);

        const key2 = await wallet.getKey(address);
        assert(key2, `Could not get key for ${address.toString()}` +
          `, Key: xpub/${type.branch}/${i+1}`);

        assert.strictEqual(key2.name, key1.name);
        assert.strictEqual(key2.account, key1.account);
        assert.strictEqual(key2.branch, key1.branch);
        assert.strictEqual(key2.witness, key1.witness);
        assert.strictEqual(key2.nested, key1.nested);
        assert.bufferEqual(key2.publicKey, key1.publicKey);
        assert.strictEqual(key2.getType(), key1.getType());
      }

      assert.strictEqual(addresses.size, 100);
    });
  }

  it('should throw error with missing outputs', async () => {
    const wallet = new Wallet({});

    let err = null;

    try {
       await wallet.send({outputs: []});
    } catch (e) {
      err = e;
   }

    assert(err);
    assert.equal(err.message, 'At least one output required.');
  });

  it('should cleanup', async () => {
    consensus.COINBASE_MATURITY = 100;
    // await wdb.close();
  });
});

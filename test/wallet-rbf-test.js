/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {forEvent} = require('./util/common');
const FullNode = require('../lib/node/fullnode');
const MTX = require('../lib/primitives/mtx');

const node = new FullNode({
  network: 'regtest',
  plugins: [require('../lib/wallet/plugin')]
});

let alice = null;
let bob = null;
let aliceReceive = null;
let bobReceive = null;
const {wdb} = node.require('walletdb');

describe('Wallet RBF', function () {
  before(async () => {
    await node.open();
  });

  after(async () => {
    await node.close();
  });

  it('should create and fund wallet', async () => {
    alice = await wdb.create({id: 'alice'});
    bob = await wdb.create({id: 'bob'});

    aliceReceive = (await alice.receiveAddress()).toString('regtest');
    bobReceive = (await bob.receiveAddress()).toString('regtest');

    await node.rpc.generateToAddress([110, aliceReceive]);

    const aliceBal = await alice.getBalance();
    assert.strictEqual(aliceBal.confirmed, 110 * 50e8);

    const bobBal = await bob.getBalance();
    assert.strictEqual(bobBal.confirmed, 0);
  });

  it('should not replace missing tx', async () => {
    const dummyHash = Buffer.alloc(32, 0x10);
    assert.rejects(async () => {
      await alice.bumpTXFee(dummyHash, 1000 /* satoshis per kvB */, true, null);
    }, {
      message: 'Transaction not found.'
    });
  });

  it('should not replace confirmed tx', async () => {
    const txs = await alice.getHistory();
    const cb = txs[0];
    assert.rejects(async () => {
      await alice.bumpTXFee(cb.hash, 1000 /* satoshis per kvB */, true, null);
    }, {
      message: 'Transaction is confirmed.'
    });
  });

  it('should not replace a non-replaceable tx', async () => {
    const tx = await alice.send({
      outputs: [{
        address: aliceReceive,
        value: 1e8
      }],
      replaceable: false
    });

    assert(!tx.isRBF());

    await forEvent(node.mempool, 'tx');
    assert(node.mempool.hasEntry(tx.hash()));

    assert.rejects(async () => {
      await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);
    }, {
      message: 'Transaction does not signal opt-in replace-by-fee.'
    });
  });

  it('should not replace a wallet tx with child spends', async () => {
    const tx1 = await alice.send({
      outputs: [{
        address: aliceReceive,
        value: 1e8
      }]
    });

    assert(tx1.isRBF());

    await forEvent(node.mempool, 'tx');
    assert(node.mempool.hasEntry(tx1.hash()));

    const mtx2 = new MTX();
    mtx2.addTX(tx1, 0);
    mtx2.addOutput(aliceReceive, 1e8 - 1000);
    mtx2.inputs[0].sequence = 0xfffffffd;
    await alice.sign(mtx2);
    const tx2 = mtx2.toTX();
    await wdb.addTX(tx2);
    await wdb.send(tx2);

    assert(tx2.isRBF());

    await forEvent(node.mempool, 'tx');
    assert(node.mempool.hasEntry(tx2.hash()));

    assert.rejects(async () => {
      await alice.bumpTXFee(tx1.hash(), 1000 /* satoshis per kvB */, true, null);
    }, {
      message: 'Transaction has descendants in the wallet.'
    });
  });

  it('should replace a replaceable tx', async () => {
    const tx = await alice.send({
      outputs: [{
        address: bobReceive,
        value: 1e8
      }],
      replaceable: true
    });

    assert(tx.isRBF());

    await forEvent(node.mempool, 'tx');
    assert(node.mempool.has(tx.hash()));

    const rtx = await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);

    await forEvent(node.mempool, 'tx');
    assert(!node.mempool.hasEntry(tx.hash()));
    assert(node.mempool.hasEntry(rtx.hash()));
  });

  it('should only have paid Bob once', async () => {
    let bobBal = await bob.getBalance();
    assert.strictEqual(bobBal.unconfirmed, 1e8);

    await node.rpc.generateToAddress([1, aliceReceive]);
    bobBal = await bob.getBalance();
    assert.strictEqual(bobBal.confirmed, 1e8);
  });

  it('should not send replacement if original has more than one change address', async () => {
    const changeAddr = (await alice.createChange()).getAddress('string');
    const tx = await alice.send({
      outputs: [{
        address: changeAddr,
        value: 1e8
      }],
      replaceable: true
    });
    await forEvent(node.mempool, 'tx');

    assert.rejects(async () => {
      await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);
    }, {
      message: 'Found more than one change address.'
    });
    await node.rpc.generateToAddress([1, aliceReceive]);
  });

  it('should not send replacement with too-low fee rate', async () => {
    const tx = await alice.send({
      outputs: [{
        address: bobReceive,
        value: 1e8
      }],
      replaceable: true,
      rate: 100000
    });
    await forEvent(node.mempool, 'tx');

    assert.rejects(async () => {
      // Try a fee rate below minRelay (1000)
      await alice.bumpTXFee(tx.hash(), 999 /* satoshis per kvB */, true, null);
    }, {
      message: 'Fee rate is below minimum.'
    });
    await node.rpc.generateToAddress([1, aliceReceive]);
  });

  it('should bump a tx with no change by adding new in/out pair', async () => {
    const coins = await alice.getCoins();
    let coin;
    for (coin of coins) {
      if (!coin.coinbase)
        break;
    }
    const mtx = new MTX();
    mtx.addCoin(coin);
    mtx.addOutput(bobReceive, coin.value - 200);
    mtx.inputs[0].sequence = 0xfffffffd;
    await alice.sign(mtx);
    const tx = mtx.toTX();
    assert.strictEqual(tx.inputs.length, 1);
    assert.strictEqual(tx.outputs.length, 1);
    await alice.wdb.addTX(tx);
    await alice.wdb.send(tx);
    await forEvent(node.mempool, 'tx');

    const rtx = await alice.bumpTXFee(tx.hash(), 2000 /* satoshis per kvB */, true, null);
    assert.strictEqual(rtx.inputs.length, 2);
    assert.strictEqual(rtx.outputs.length, 2);
    assert(rtx.getRate() >= 2000 && rtx.getRate() < 3000);

    await forEvent(node.mempool, 'tx');
    assert(!node.mempool.hasEntry(tx.hash()));
    assert(node.mempool.hasEntry(rtx.hash()));

    await node.rpc.generateToAddress([1, aliceReceive]);
  });

  it('should not violate rule 6 signed or unsigned', async () => {
    const coins = await alice.getCoins();
    let coin;
    for (coin of coins) {
      if (!coin.coinbase)
        break;
    }
    const mtx = new MTX();
    mtx.addCoin(coin);
    mtx.addOutput(bobReceive, coin.value - 200);
    mtx.inputs[0].sequence = 0xfffffffd;
    await alice.sign(mtx);
    const tx = mtx.toTX();
    assert.strictEqual(tx.inputs.length, 1);
    assert.strictEqual(tx.outputs.length, 1);
    await alice.wdb.addTX(tx);
    await alice.wdb.send(tx);
    await forEvent(node.mempool, 'tx');

    // Do not sign, estimate fee rate
    await assert.rejects(async () => {
      await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, false, null);
    }, {
      message: /^Provided fee rate of 1000 s\/kvB results in insufficient estimated total fee rate/
    });

    // Do sign, then check fee rate
    await assert.rejects(async () => {
      await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);
    }, {
      message: /^Provided fee rate of 1000 s\/kvB results in insufficient total fee rate/
    });

    await node.rpc.generateToAddress([1, aliceReceive]);
  });

  it('should remove change and pay to fees if below dust', async () => {
    const coins = await alice.getCoins();
    let coin;
    for (coin of coins) {
      if (!coin.coinbase)
        break;
    }
    const mtx = new MTX();
    const changeAddr = (await alice.createChange()).getAddress('string');
    mtx.addCoin(coin);
    mtx.addOutput(bobReceive, coin.value - 400 - 141); // Bob gets most of it

    mtx.addOutput(changeAddr, 400);   // small change output
    assert(!mtx.outputs[1].isDust()); // not dust yet but will be after RBF
    mtx.inputs[0].sequence = 0xfffffffd;
    await alice.sign(mtx);
    const tx = mtx.toTX();
    await alice.wdb.addTX(tx);
    await alice.wdb.send(tx);
    await forEvent(node.mempool, 'tx');

    const rtx = await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);

    assert.strictEqual(rtx.outputs.length, 1); // change output was removed

    await forEvent(node.mempool, 'tx');
    assert(!node.mempool.hasEntry(tx.hash()));
    assert(node.mempool.hasEntry(rtx.hash()));

    await node.rpc.generateToAddress([1, aliceReceive]);
  });

  it('should add inputs if change output is insufficient for RBF', async () => {
    const coins = await alice.getCoins();
    let coin;
    for (coin of coins) {
      if (!coin.coinbase)
        break;
    }
    const mtx = new MTX();
    const changeAddr = (await alice.createChange()).getAddress('string');
    mtx.addCoin(coin);
    mtx.addOutput(bobReceive, coin.value - 100 - 141); // Bob gets most of it
    mtx.addOutput(changeAddr, 100);   // change too small to pay for fee bump

    mtx.inputs[0].sequence = 0xfffffffd;
    await alice.sign(mtx);
    const tx = mtx.toTX();
    await alice.wdb.addTX(tx);
    await alice.wdb.send(tx);
    await forEvent(node.mempool, 'tx');

    const rtx = await alice.bumpTXFee(tx.hash(), 1000 /* satoshis per kvB */, true, null);

    await forEvent(node.mempool, 'tx');
    assert(!node.mempool.hasEntry(tx.hash()));
    assert(node.mempool.hasEntry(rtx.hash()));

    await node.rpc.generateToAddress([1, aliceReceive]);
  });
});

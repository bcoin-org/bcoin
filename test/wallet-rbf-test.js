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
});

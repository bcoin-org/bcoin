/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {CoinSelector, CoinPointer} = require('../lib/wallet/coinselector');
const TX = require('../lib/primitives/tx');
const random = require('bcrypto/lib/random');
const WorkerPool = require('../lib/workers/workerpool');
const WalletDB = require('../lib/wallet/walletdb');
const Amount = require('../lib/btc/amount');
const data = require('./data/bustabit-2019-2020-tiny-hot-wallet.json');
const MTX = require('../lib/primitives/mtx');
const Input = require('../lib/primitives/input');
const Outpoint = require('../lib/primitives/outpoint');

describe('Coin Selector', function () {
  function build(values) {
    const pointers = [];
    for (let i = 0; i < values.length; i++) {
      // spending size of P2WPKH is 69
      pointers.push(new CoinPointer(69, values[i], i));
    }
    return pointers;
  }

  const selector = new CoinSelector(new TX());
  const values = [100000, 50000, 30000, 20000, 10000, 5000, 3000, 2000, 1000];
  const pointers = build(values);
  selector.coinPointers = pointers;
  const costOfChange = 345; // this is cost of producing and spending a change output

  const targetSet1 = [221000, 220000, 215000, 214000, 211000, 208000, 206000, 203000, 201000,
    195000, 186000, 178000, 166000, 160000, 155000, 152000, 146000, 139000, 119000,
    116000, 110000, 109000, 108000, 106000, 105000, 101000, 98000, 96000, 90000,
    85000, 82000, 81000, 80000, 78000, 71000, 67000, 66000, 63000, 55000, 53000,
    51000, 45000, 44000, 41000, 38000, 36000, 23000, 19000, 16000, 11000, 6000];

  const targetSet2 = [150000, 130000, 101000, 50000, 15000, 13000, 5000, 3000];

  const targetSet3 = [219000, 217000, 213000, 212000, 211000, 205000, 202000, 201000, 190000,
    185000, 183000, 182000, 181000, 170000, 155000, 153000, 152000, 151000, 130000,
    120000, 110000, 105000, 103000, 102000, 101000];

  describe('Branch and Bound Selection', function () {
    // try to select single UTXOs
    for (const value of values) {
      it(`should select target=${value} using Branch and Bound`, () => {
        const selection = selector.selectBnB(value, costOfChange);
        assert.strictEqual(selection.length, 1);
        assert.strictEqual(pointers[selection[0]].effectiveValue, value);
      });
    }

    // these targets have exact solutions
    for (const target of targetSet1) {
      it(`should select target=${target} using Branch and Bound`, () => {
        const selection = selector.selectBnB(target, costOfChange);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert.strictEqual(selectedValues, target);
      });
    }

    // testing upper bound for BnB
    for (const target of targetSet1) {
      it(`should select target=${target - costOfChange} using Branch and Bound`, () => {
        const selection = selector.selectBnB(target - costOfChange, costOfChange);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert.strictEqual(selectedValues, target);
      });
    }

    // these should fail because we are using (target - 500)
    for (const target of targetSet1) {
      it(`should fail to select target=${target - 500} using Branch and Bound`, () => {
        const selection = selector.selectBnB(target - 500, costOfChange);
        assert.strictEqual(selection.length, 0);
      });
    }

    // these targets have multiple solutions
    for (const target of targetSet2) {
      it(`should select more inputs in low feerate environment, target=${target}`, () => {
        selector.rate = 4000;
        const lowFeeSelection = selector.selectBnB(target, costOfChange);

        let selectedValues = 0;
        for (const i of lowFeeSelection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert.strictEqual(selectedValues, target);

        selector.rate = 6000;
        const highFeeSelection = selector.selectBnB(target, costOfChange);

        selectedValues = 0;
        for (const i of highFeeSelection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert.strictEqual(selectedValues, target);
        assert(lowFeeSelection.length > highFeeSelection.length);
      });
    }
  });

  describe('Lowest Larger Selection', function () {
    // try selecting a single UTXO
    for (const value of values) {
      it(`should select target=${value} using Lowest Larger`, () => {
        const selection = selector.selectLowestLarger(value);
        assert.strictEqual(selection.length, 1);
        assert.strictEqual(pointers[selection[0]].effectiveValue, value);
      });
    }

    // these targets may or may not have exact solutions
    for (const target of targetSet1) {
      it(`should select target=${target} using Lowest Larger`, () => {
        const selection = selector.selectLowestLarger(target);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert(selectedValues >= target);
      });
    }

    // Lowest Larger should select (target - 500)
    for (const target of targetSet1) {
      it(`should select target=${target - 500} using Lowest Larger`, () => {
        const selection = selector.selectLowestLarger(target - 500);
        assert(selection.length > 0);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert(selectedValues > target - 500);
      });
    }

    // these targets have exact solution
    for (const target of targetSet3) {
      it(`should select target=${target} using Lowest Larger for exact matches`, () => {
        const selection = selector.selectLowestLarger(target);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert.strictEqual(selectedValues, target);
      });
    }

    it('should be able to fund all values in range 1 to 221000 using Lowest Larger', () => {
      for (let target = 1; target <= 221000; target++) {
        const selection = selector.selectLowestLarger(target);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert(selectedValues >= target);
      }
    });
  });

  describe('Single Random Draw Selection', function () {
    it('should be able to fund all values in range 1 to 221000 using Single Random Draw', () => {
      for (let target = 1; target <= 221000; target++) {
        const selection = selector.selectSRD(target);

        let selectedValues = 0;
        for (const i of selection) {
          selectedValues += pointers[i].effectiveValue;
        }

        assert(selectedValues >= target);
      }
    });
  });
});

describe('Integration', function () {
  this.timeout(360000);

  const workers = new WorkerPool({
    enabled: true,
    size: 2
  });

  const wdb = new WalletDB({workers});

  function nextBlock(wdb) {
    return fakeBlock(wdb.state.height + 1);
  }

  function fakeBlock(height) {
    const prev = Buffer.allocUnsafe(32);
    const hash = Buffer.allocUnsafe(32);
    const root = Buffer.allocUnsafe(32);

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

  function getReceiveAddress(wallet) {
    let addr;
    switch (Math.floor(Math.random() * 3)) {
      case 0:
        addr = wallet.receiveAddress(); // native segwit
        break;
      case 1:
        addr = wallet.receiveAddress(1); // p2pkh
        break;
      case 2:
        addr = wallet.nestedAddress(); // nested segwit
    }
    return addr;
  }

  before(async () => {
    await workers.open();
    await wdb.open();
  });

  let oldBalance, newBalance, oldCoins, newCoins;

  after(async () => {
    await wdb.close();
    await workers.close();
  });

  for (const useSelectEstimate of [true, false]) {
    it(`should send transactions using ${useSelectEstimate ? 'old' : 'new'} selection`, async () => {
      const alice = await wdb.create();
      await alice.createAccount({witness: false});
      const bob = await wdb.create();

      for (const payment of data) {
        let value = Amount.value(payment.value);
        const rate = Amount.value(payment.rate);

        // remove dust outputs
        if (Math.abs(value) < 500)
          continue;

        let tx;

        if (value > 0) {
          // send to Alice's wallet
          const t1 = new MTX();
          t1.addInput(dummyInput());
          t1.addOutput(await getReceiveAddress(alice), value);
          tx = t1.toTX();
        } else {
          // send from Alice's wallet
          const address = await bob.receiveAddress();
          value = -value;
          tx = await alice.send({
            outputs: [{value, address}],
            rate,
            useSelectEstimate
          });
        }

        // confirm tx
        await wdb.addBlock(nextBlock(wdb), [tx]);
      }
      // check balance after simulation
      const balance = await alice.getBalance();
      if (useSelectEstimate) {
        oldBalance = balance.unconfirmed;
        oldCoins = balance.coin;
      } else {
        newBalance = balance.unconfirmed;
        newCoins = balance.coin;
      }
    });
  }

  it('should prove new selection is better', () => {
    assert(newCoins * 10 < oldCoins);
    assert(newBalance - oldBalance > 500000);
  });
});

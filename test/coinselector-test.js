/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {CoinSelector, CoinPointer} = require('../lib/wallet/coinselector');
const TX = require('../lib/primitives/tx');

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

describe('Coin Selector', function() {
  describe('Branch and Bound Selection', function() {
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

  describe('Lowest Larger Selection', function() {
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

  describe('Single Random Draw Selection', function() {
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

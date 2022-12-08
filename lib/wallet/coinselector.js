/*!
 * coinselector.js - coin selector class for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {BufferMap} = require('buffer-map');
const Output = require('../primitives/output');
const Coin = require('../primitives/coin');
const Outpoint = require('../primitives/outpoint');
const Address = require('../primitives/address');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const Amount = require('../btc/amount');

/**
 * CoinPointer
 */

class CoinPointer {
  /**
   * Create a credit.
   * @constructor
   * @param {Number} spendingSize
   * @param {Number} effectiveValue
   * @param {number} index
   */

  constructor(spendingSize, effectiveValue, index) {
    this.spendingSize = spendingSize;
    this.effectiveValue = effectiveValue;
    this.index = index;
  }
}

/**
 * Coin Selector
 * @alias module:primitives.CoinSelector
 */

class CoinSelector {
  /**
   * Create a coin selector.
   * @constructor
   * @param {MTX} tx
   * @param {Object?} options
   */

  constructor(tx, options) {
    this.tx = tx.clone();
    this.coins = [];
    this.coinPointers = [];
    this.outputValue = 0;
    this.chosen = [];
    this.change = 0;
    this.fee = CoinSelector.MIN_FEE;

    this.selection = 'value';
    this.subtractFee = false;
    this.subtractIndex = -1;
    this.height = -1;
    this.depth = -1;
    this.hardFee = -1;
    this.rate = CoinSelector.FEE_RATE;
    this.maxFee = -1;
    this.round = false;
    this.changeAddress = null;
    this.inputs = new BufferMap();
    this.useSelectEstimate = false;

    // Needed for size estimation.
    this.getAccount = null;

    this.injectInputs();

    if (options)
      this.fromOptions(options);
  }

  /**
   * Initialize selector options.
   * @param {Object} options
   * @private
   */

  fromOptions(options) {
    if (options.selection) {
      assert(typeof options.selection === 'string');
      this.selection = options.selection;
    }

    if (options.subtractFee != null) {
      if (typeof options.subtractFee === 'number') {
        assert(Number.isSafeInteger(options.subtractFee));
        assert(options.subtractFee >= -1);
        this.subtractIndex = options.subtractFee;
        this.subtractFee = this.subtractIndex !== -1;
      } else {
        assert(typeof options.subtractFee === 'boolean');
        this.subtractFee = options.subtractFee;
      }
    }

    if (options.subtractIndex != null) {
      assert(Number.isSafeInteger(options.subtractIndex));
      assert(options.subtractIndex >= -1);
      this.subtractIndex = options.subtractIndex;
      this.subtractFee = this.subtractIndex !== -1;
    }

    if (options.height != null) {
      assert(Number.isSafeInteger(options.height));
      assert(options.height >= -1);
      this.height = options.height;
    }

    if (options.confirmations != null) {
      assert(Number.isSafeInteger(options.confirmations));
      assert(options.confirmations >= -1);
      this.depth = options.confirmations;
    }

    if (options.depth != null) {
      assert(Number.isSafeInteger(options.depth));
      assert(options.depth >= -1);
      this.depth = options.depth;
    }

    if (options.hardFee != null) {
      assert(Number.isSafeInteger(options.hardFee));
      assert(options.hardFee >= -1);
      this.hardFee = options.hardFee;
    }

    if (options.rate != null) {
      assert(Number.isSafeInteger(options.rate));
      assert(options.rate >= 0);
      this.rate = options.rate;
    }

    if (options.maxFee != null) {
      assert(Number.isSafeInteger(options.maxFee));
      assert(options.maxFee >= -1);
      this.maxFee = options.maxFee;
    }

    if (options.round != null) {
      assert(typeof options.round === 'boolean');
      this.round = options.round;
    }

    if (options.useSelectEstimate != null) {
      assert(typeof options.useSelectEstimate === 'boolean');
      this.useSelectEstimate = options.useSelectEstimate;
    }

    if (options.changeAddress) {
      const addr = options.changeAddress;
      if (typeof addr === 'string') {
        this.changeAddress = Address.fromString(addr);
      } else {
        assert(addr instanceof Address);
        this.changeAddress = addr;
      }
    }

    if (options.getAccount) {
      assert(typeof options.getAccount === 'function');
      this.getAccount = options.getAccount;
    }

    if (options.inputs) {
      assert(Array.isArray(options.inputs));
      for (let i = 0; i < options.inputs.length; i++) {
        const prevout = options.inputs[i];
        assert(prevout && typeof prevout === 'object');
        const {hash, index} = prevout;
        assert(Buffer.isBuffer(hash));
        assert(typeof index === 'number');
        this.inputs.set(Outpoint.toKey(hash, index), i);
      }
    }

    return this;
  }

  /**
   * Attempt to inject existing inputs.
   * @private
   */

  injectInputs() {
    if (this.tx.inputs.length > 0) {
      for (let i = 0; i < this.tx.inputs.length; i++) {
        const {prevout} = this.tx.inputs[i];
        this.inputs.set(prevout.toKey(), i);
      }
    }
  }

  /**
   * Initialize the selector with coins to select from.
   * @param {Coin[]} coins
   */

  async init(coins) {
    this.coins = coins.slice();
    this.outputValue = this.tx.getOutputValue();
    this.chosen = [];
    this.change = 0;
    this.fee = CoinSelector.MIN_FEE;
    this.tx.inputs.length = 0;

    switch (this.selection) {
      case 'all':
      case 'random':
        this.coins.sort(sortRandom);
        break;
      case 'age':
        this.coins.sort(sortAge);
        break;
      case 'value':
        this.coins.sort(sortValue);
        break;
      default:
        throw new FundingError(`Bad selection type: ${this.selection}.`);
    }

    if (!this.useSelectEstimate) {
      for (let i = 0, n = coins.length; i < n; i++) {
        const coin = this.coins[i];
        if (this.isSpendable(coin)) {
          const spendingSize = await coin.estimateSpendingSize(this.getAccount);
          const effectiveValue = coin.value - this.getFee(spendingSize);
          const pointer = new CoinPointer(spendingSize, effectiveValue, i);
          this.coinPointers.push(pointer);
        }
      }
      this.coinPointers.sort((a, b) => b.effectiveValue - a.effectiveValue);
    }
  }

  /**
   * Calculate total value required.
   * @returns {Number}
   */

  total() {
    if (this.subtractFee)
      return this.outputValue;
    return this.outputValue + this.fee;
  }

  /**
   * Test whether the selector has
   * completely funded the transaction.
   * @returns {Boolean}
   */

  isFull() {
    return this.tx.getInputValue() >= this.total();
  }

  /**
   * Test whether a coin is spendable
   * with regards to the options.
   * @param {Coin} coin
   * @returns {Boolean}
   */

  isSpendable(coin) {
    if (this.tx.view.hasEntry(coin))
      return false;

    if (this.height === -1)
      return true;

    if (coin.coinbase) {
      if (coin.height === -1)
        return false;

      if (this.height + 1 < coin.height + consensus.COINBASE_MATURITY)
        return false;

      return true;
    }

    if (this.depth === -1)
      return true;

    const depth = coin.getDepth(this.height);

    if (depth < this.depth)
      return false;

    return true;
  }

  /**
   * Get the current fee based on a size.
   * @param {Number} size
   * @returns {Number} fee
   */

  getFee(size) {
    // This is mostly here for testing.
    // i.e. A fee rounded to the nearest
    // kb is easier to predict ahead of time.
    if (this.round) {
      const fee = policy.getRoundFee(size, this.rate);
      return Math.min(fee, CoinSelector.MAX_FEE);
    }

    const fee = policy.getMinFee(size, this.rate);
    return Math.min(fee, CoinSelector.MAX_FEE);
  }

  /**
   * Fund the transaction with more
   * coins if the `output value + fee`
   * total was updated.
   * @param {Number} index
   * @returns {Number} index
   */

  fund(index) {
    // Ensure all preferred inputs first.
    if (this.inputs.size > 0) {
      const coins = [];

      for (let i = 0; i < this.inputs.size; i++)
        coins.push(null);

      for (const coin of this.coins) {
        const {hash, index} = coin;
        const key = Outpoint.toKey(hash, index);
        const i = this.inputs.get(key);

        if (i != null) {
          coins[i] = coin;
          this.inputs.delete(key);
        }
      }

      if (this.inputs.size > 0)
        throw new Error('Could not resolve preferred inputs.');

      for (const coin of coins) {
        this.tx.addCoin(coin);
        this.chosen.push(coin);
      }
    }

    while (index < this.coins.length) {
      const coin = this.coins[index++];

      if (!this.isSpendable(coin))
        continue;

      this.tx.addCoin(coin);
      this.chosen.push(coin);

      if (this.selection === 'all')
        continue;

      if (this.isFull())
        break;
    }
    return index;
  }

  /**
   * Initiate selection from `coins`.
   * @param {Coin[]} coins
   * @returns {CoinSelector}
   */

  async select(coins) {
    await this.init(coins);

    if (this.hardFee !== -1) {
      this.selectHard();
    } else if (this.useSelectEstimate) {
      // This is potentially asynchronous:
      // it may invoke the size estimator
      // required for redeem scripts (we
      // may be calling out to a wallet
      // or something similar).
      await this.selectEstimate();

      if (!this.isFull()) {
        // Still failing to get enough funds.
        throw new FundingError(
          'Not enough funds.',
          this.tx.getInputValue(),
          this.total());
      }
    } else {
      await this.attemptSelection();
    }

    // How much money is left after filling outputs.
    this.change = this.tx.getInputValue() - this.total();

    return this;
  }

  /**
   * Initialize selection based on size estimate.
   */

  async selectEstimate() {
    // Set minimum fee and do
    // an initial round of funding.
    let index = 0;
    this.fee = CoinSelector.MIN_FEE;
    index = this.fund(index);

    // Add dummy output for change.
    const change = new Output();

    if (this.changeAddress) {
      change.script.fromAddress(this.changeAddress);
    } else {
      // In case we don't have a change address,
      // we use a fake p2wpkh output to gauge size.
      change.script.fromProgram(0, Buffer.allocUnsafe(20));
    }

    this.tx.outputs.push(change);

    // Keep recalculating the fee and funding
    // until we reach some sort of equilibrium.
    do {
      const size = await this.tx.estimateSize(this.getAccount);

      this.fee = this.getFee(size);

      if (this.maxFee > 0 && this.fee > this.maxFee)
        throw new FundingError('Fee is too high.');

      // Failed to get enough funds, add more coins.
      if (!this.isFull())
        index = this.fund(index);
    } while (!this.isFull() && index < this.coins.length);
  }

  /**
   * Initiate selection based on a hard fee.
   */

  selectHard() {
    this.fee = Math.min(this.hardFee, CoinSelector.MAX_FEE);
    this.fund(0);
  }

  /**
   * Initiate multi algorithm coin selection.
   */

  async attemptSelection() {
    // calculate cost of creating and spending a change output
    // add dummy output for change.
    const change = new Output();

    if (this.changeAddress) {
      change.script.fromAddress(this.changeAddress);
    } else {
      // In case we don't have a change address,
      // we use a fake p2wpkh output to gauge size.
      change.script.fromProgram(0, Buffer.allocUnsafe(20));
    }

    const changeOutputSize = change.getSize();
    const changeOutputCoin = new Coin();
    changeOutputCoin.script = change.script;
    const changeSpendingSize =
      await changeOutputCoin.estimateSpendingSize(this.getAccount);
    const costOfSpendingChange =
      changeSpendingSize * CoinSelector.LONG_TERM_FEERATE;

    // cost of change = fee paid to create change +
    // fee paid to spend that change in future
    const costOfChange = this.getFee(changeOutputSize) + costOfSpendingChange;

    let target = this.outputValue;
    let size = await this.tx.estimateSize(this.getAccount);
    const fee = this.getFee(size);
    target += fee;

    let bestSelection = [];
    let bestWaste = consensus.MAX_MONEY;
    let isChange = false; // true if change output

    // try to find a changeless solution using BnB
    let result = this.selectBnB(target, costOfChange);
    if (result && result.length > 0) {
      bestSelection = result;
      bestWaste = this.getWaste(result, costOfChange, target);
    }

    // fallback to other algorithms as we can't find a changeless solution
    // update target to include cost of producing change
    target += this.getFee(changeOutputSize);

    // find a solution of target using Lowest Larger
    result = this.selectLowestLarger(target);
    if (result.length > 0) {
      const currWaste = this.getWaste(result, costOfChange, target);
      if (currWaste < bestWaste) {
        bestSelection = result;
        bestWaste = currWaste;
        isChange = true;
      }
    }

    // find a solution of target using SRD
    result = this.selectSRD(target);
    if (result.length > 0) {
      const currWaste = this.getWaste(result, costOfChange, target);
      if (currWaste <= bestWaste) {
        bestSelection = result;
        bestWaste = currWaste;
        isChange = true;
      }
    }

    if (bestSelection && bestSelection.length > 0) {
      for (const i of bestSelection) {
        const coin = this.coins[this.coinPointers[i].index];
        this.tx.addCoin(coin);
        this.chosen.push(coin);
      }
      // add change output if solution is not found by BnB
      if (isChange)
        this.tx.outputs.push(change);
      // update fee
      size = await this.tx.estimateSize(this.getAccount);
      this.fee = this.getFee(size);
    }
  }

  /**
   * Initiate selection using Single Random Draw selection.
   * @param {Number} target - Selection target
   * @returns {Number[]} selected - array of indicies of selected coins
   */

  selectSRD(target) {
    // create an array of indices and randomly sort it
    const arr = [...this.coinPointers.keys()];
    arr.sort(() => Math.random() - 0.5);

    let index = 0;
    const selected = [];
    let selectedValue = 0;

    while (index < arr.length) {
      const pointer = this.coinPointers[arr[index]];
      selectedValue += pointer.effectiveValue;
      selected.push(arr[index]);
      if (selectedValue >= target)
        return selected;
      index++;
    }

    return [];
  }

  /**
   * Initiate selection using Branch and Bound selection.
   * @param {Number} target - Selection target
   * @param {Number} costOfChange - Cost of producing and spending change
   * @returns {Number[]} selected - array of indicies of selected coins
   */

  selectBnB(target, costOfChange) {
    const selected = [];
    let currValue = 0;
    let remainingValue = 0;
    let index = 0;
    for (const pointer of this.coinPointers)
      remainingValue += pointer.effectiveValue;

    // we don't have enough funds
    if (remainingValue < target) {
      throw new FundingError(
        'Not enough funds.',
        remainingValue,
        target);
    }

    let tries = 100000;
    let bestWaste = consensus.MAX_MONEY;
    let bestSelection = [];
    // perform depth-first search for choosing CoinPointers
    while (tries-- > 0) {
      let backtrack = false;
      // conditions for backtracking
      // 1. cannot reach target with remaining amount
      // 2. selected value is greater than upper bound
      if (   currValue + remainingValue < target
          || currValue > target + costOfChange
      ) {
        backtrack = true;
      } else if (currValue >= target) {
        // we have a solution, we will compare it with current best solution
        // we will try to find the solution with minimum waste
        const currWaste = this.getWaste(selected, 0, target);
        if (currWaste <= bestWaste) {
          bestSelection = selected.slice();
          bestWaste = currWaste;
        }
        backtrack = true;
      }

      // backtracking here
      if (backtrack) {
        // we have backtracked to the first CoinPointer,
        // all branches are traversed, we are done here
        if (selected.length === 0)
          break;

        // Add omitted CoinPointer back before traversing
        // the omission branch of last included CoinPointer
        // we are using a while loop here beacuse
        // there can be more than one CoinPointers that were omitted
        while (--index > selected[selected.length - 1]) {
          remainingValue += this.coinPointers[index].effectiveValue;
        }

        // Remove last included CoinPointer from selected list.
        currValue -= this.coinPointers[index].effectiveValue;
        selected.pop();
      } else {
        const pointer = this.coinPointers[index];
        // remove this CoinPointer from total available amount
        remainingValue -= pointer.effectiveValue;
        // if this CoinPointer is the first one or
        // if the previous index is included or
        // if this CoinPointer's value is different from the previous one
        if (   selected.length === 0
            || index - 1 === selected[selected.length - 1]
            || pointer.effectiveValue !==
               this.coinPointers[index - 1].effectiveValue
        ) {
          selected.push(index);
          currValue += this.coinPointers[index].effectiveValue;
        }
      }
      index++;
    }

    return bestSelection;
  }

  /**
   * Initiate selection using Lowest Larger selection algorithm.
   * @param {Number} target - Selection target
   * @returns {Number[]} selected - array of indicies of selected coins
   */

  selectLowestLarger(target) {
    // while target is greater than
    // the largest coin we have, we
    // will keep selecting the largest coin

    let index = 0;
    const selected = [];
    let effectiveValue = this.coinPointers[index].effectiveValue;
    while (target >= effectiveValue) {
      // update target, select current coin and increment index
      selected.push(index);
      target -= effectiveValue;
      index++;

      if (index === this.coinPointers.length)
        break;

      effectiveValue = this.coinPointers[index].effectiveValue;
    }

    if (target > 0 && index !== this.coinPointers.length) {
      // now we are sure that target < largest unselected coin
      // we will perform Binary search to find the smallest coin
      // which is greater than target value

      const lowestLargerIndex = this.findLowestLarger(target, index);
      target -= this.coinPointers[lowestLargerIndex].effectiveValue;
      selected.push(lowestLargerIndex);
    }

    return target > 0 ? [] : selected;
  }

  /**
   * Find smallest coin greater than
   * the target using binary search
   * @param {Number} target
   * @param {Number} index
   * @returns {Number} index
   */

  findLowestLarger(target, index) {
    let i = index;
    let j = this.coinPointers.length - 1;

    // begin binary search
    let lowestLargerIndex = 0;
    let mid = 0;
    while (i <= j) {
      mid = Math.floor((i + j) / 2);

      // calculate effective value of coin at mid
      const effectiveValue = this.coinPointers[mid].effectiveValue;

      // if target is less than coin at mid
      // then search in right part of array
      if (target <= effectiveValue) {
        lowestLargerIndex = mid;
        // repeat for right half
        i = mid + 1;
      } else {
        // repeat for left half
        j = mid - 1;
      }
    }

    return lowestLargerIndex;
  }

  /**
   * Calculate waste for a selection
   * @param {Number[]} selected - indicies of selected coins
   * @param {Number} costOfChange - the cost of making change and spending it
   * @param {Number} target - selection target
   * @returns {Number} - waste
   */

  getWaste(selected, costOfChange, target) {
    let waste = 0;
    let selectedAmount = 0;
    // calculate current fee rate in sats/byte
    const currentFeeRate = this.getFee(1);

    for (const i of selected) {
      const pointer = this.coinPointers[i];
      selectedAmount += pointer.effectiveValue;
      // Consider the cost of spending an input now vs in the future
      waste += (currentFeeRate - CoinSelector.LONG_TERM_FEERATE)
        * pointer.spendingSize;
    }

    if (costOfChange > 0) {
      // Consider the cost of making change and spending it in the future
      waste += costOfChange;
    } else {
      // if costOfChange is not set,
      // consider the excess we are throwing away to fees
      waste += selectedAmount - target;
    }

    return waste;
  }
}

/**
 * Default fee rate
 * for coin selection.
 * @const {Number}
 * @default
 */

CoinSelector.FEE_RATE = 10000;

/**
 * Minimum fee to start with
 * during coin selection.
 * @const {Number}
 * @default
 */

CoinSelector.MIN_FEE = 10000;

/**
 * Maximum fee to allow
 * after coin selection.
 * @const {Number}
 * @default
 */

CoinSelector.MAX_FEE = consensus.COIN / 10;

/**
 * Long term feerate (sats/vbyte)
 * @const {Number}
 * @default
 */

CoinSelector.LONG_TERM_FEERATE = 5;

/**
 * Funding Error
 * An error thrown from the coin selector.
 * @ignore
 * @extends Error
 * @property {String} message - Error message.
 * @property {Number} availableFunds
 * @property {Number} requiredFunds
 */

class FundingError extends Error {
  /**
   * Create a funding error.
   * @constructor
   * @param {String} msg
   * @param {Number} available
   * @param {Number} required
   */

  constructor(msg, available, required) {
    super();

    this.type = 'FundingError';
    this.message = msg;
    this.availableFunds = -1;
    this.requiredFunds = -1;

    if (available != null) {
      this.message += ` (available=${Amount.btc(available)},`;
      this.message += ` required=${Amount.btc(required)})`;
      this.availableFunds = available;
      this.requiredFunds = required;
    }

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, FundingError);
  }
}

/*
 * Helpers
 */

function sortAge(a, b) {
  a = a.height === -1 ? 0x7fffffff : a.height;
  b = b.height === -1 ? 0x7fffffff : b.height;
  return a - b;
}

function sortRandom(a, b) {
  return Math.random() > 0.5 ? 1 : -1;
}

function sortValue(a, b) {
  if (a.height === -1 && b.height !== -1)
    return 1;

  if (a.height !== -1 && b.height === -1)
    return -1;

  return b.value - a.value;
}

exports.CoinSelector = CoinSelector;
exports.CoinPointer = CoinPointer;
exports.FundingError = FundingError;

module.exports = exports;

/*!
 * mtx.js - mutable transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('bsert');
const {encoding} = require('bufio');
const Script = require('../script/script');
const TX = require('./tx');
const Input = require('./input');
const Output = require('./output');
const Coin = require('./coin');
const Outpoint = require('./outpoint');
const CoinView = require('../coins/coinview');
const consensus = require('../protocol/consensus');
const policy = require('../protocol/policy');
const Stack = require('../script/stack');
const util = require('../utils/util');
const {inspectSymbol} = require('../utils');
const {CoinSelector, FundingError} = require('../wallet/coinselector');

/**
 * MTX
 * A mutable transaction object.
 * @alias module:primitives.MTX
 * @extends TX
 * @property {Number} changeIndex
 * @property {CoinView} view
 */

class MTX extends TX {
  /**
   * Create a mutable transaction.
   * @alias module:primitives.MTX
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.mutable = true;
    this.changeIndex = -1;
    this.view = new CoinView();

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    if (options.version != null) {
      assert((options.version >>> 0) === options.version,
        'Version must a be uint32.');
      this.version = options.version;
    }

    if (options.inputs) {
      assert(Array.isArray(options.inputs), 'Inputs must be an array.');
      for (const input of options.inputs)
        this.addInput(input);
    }

    if (options.outputs) {
      assert(Array.isArray(options.outputs), 'Outputs must be an array.');
      for (const output of options.outputs)
        this.addOutput(output);
    }

    if (options.locktime != null) {
      assert((options.locktime >>> 0) === options.locktime,
        'Locktime must be a uint32.');
      this.locktime = options.locktime;
    }

    if (options.changeIndex != null) {
      if (options.changeIndex !== -1) {
        assert((options.changeIndex >>> 0) === options.changeIndex,
          'Change index must be a uint32.');
        this.changeIndex = options.changeIndex;
      } else {
        this.changeIndex = -1;
      }
    }

    return this;
  }

  /**
   * Instantiate MTX from options.
   * @param {Object} options
   * @returns {MTX}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Clone the transaction. Note that
   * this will not carry over the view.
   * @returns {MTX}
   */

  clone() {
    const mtx = new this.constructor();
    mtx.inject(this);
    mtx.changeIndex = this.changeIndex;
    return mtx;
  }

  /**
   * Add an input to the transaction.
   * @param {Input|Object} options
   * @returns {Input}
   *
   * @example
   * mtx.addInput({ prevout: { hash: ... }, script: ... });
   * mtx.addInput(new Input());
   */

  addInput(options) {
    const input = Input.fromOptions(options);
    this.inputs.push(input);
    return input;
  }

  /**
   * Add an outpoint as an input.
   * @param {Outpoint|Object} outpoint
   * @returns {Input}
   *
   * @example
   * mtx.addOutpoint({ hash: ..., index: 0 });
   * mtx.addOutpoint(new Outpoint(hash, index));
   */

  addOutpoint(outpoint) {
    const prevout = Outpoint.fromOptions(outpoint);
    const input = Input.fromOutpoint(prevout);
    this.inputs.push(input);
    return input;
  }

  /**
   * Add a coin as an input. Note that this will
   * add the coin to the internal coin viewpoint.
   * @param {Coin} coin
   * @returns {Input}
   *
   * @example
   * mtx.addCoin(Coin.fromTX(tx, 0, -1));
   */

  addCoin(coin) {
    assert(coin instanceof Coin, 'Cannot add non-coin.');

    const input = Input.fromCoin(coin);

    this.inputs.push(input);
    this.view.addCoin(coin);

    return input;
  }

  /**
   * Add a transaction as an input. Note that
   * this will add the coin to the internal
   * coin viewpoint.
   * @param {TX} tx
   * @param {Number} index
   * @param {Number?} height
   * @returns {Input}
   *
   * @example
   * mtx.addTX(tx, 0);
   */

  addTX(tx, index, height) {
    assert(tx instanceof TX, 'Cannot add non-transaction.');

    if (height == null)
      height = -1;

    const input = Input.fromTX(tx, index);

    this.inputs.push(input);

    this.view.addIndex(tx, index, height);

    return input;
  }

  /**
   * Add an output.
   * @param {Address|Script|Output|Object} script - Script or output options.
   * @param {Amount?} value
   * @returns {Output}
   *
   * @example
   * mtx.addOutput(new Output());
   * mtx.addOutput({ address: ..., value: 100000 });
   * mtx.addOutput(address, 100000);
   * mtx.addOutput(script, 100000);
   */

  addOutput(script, value) {
    let output;

    if (value != null)
      output = Output.fromScript(script, value);
    else
      output = Output.fromOptions(script);

    this.outputs.push(output);

    return output;
  }

  /**
   * Verify all transaction inputs.
   * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
   * @returns {Boolean} Whether the inputs are valid.
   * @throws {ScriptError} on invalid inputs
   */

  check(flags) {
    return super.check(this.view, flags);
  }

  /**
   * Verify the transaction inputs on the worker pool
   * (if workers are enabled).
   * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
   * @param {WorkerPool?} pool
   * @returns {Promise}
   */

  checkAsync(flags, pool) {
    return super.checkAsync(this.view, flags, pool);
  }

  /**
   * Verify all transaction inputs.
   * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
   * @returns {Boolean} Whether the inputs are valid.
   */

  verify(flags) {
    try {
      this.check(flags);
    } catch (e) {
      if (e.type === 'ScriptError')
        return false;
      throw e;
    }
    return true;
  }

  /**
   * Verify the transaction inputs on the worker pool
   * (if workers are enabled).
   * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
   * @param {WorkerPool?} pool
   * @returns {Promise}
   */

  async verifyAsync(flags, pool) {
    try {
      await this.checkAsync(flags, pool);
    } catch (e) {
      if (e.type === 'ScriptError')
        return false;
      throw e;
    }
    return true;
  }

  /**
   * Calculate the fee for the transaction.
   * @returns {Amount} fee (zero if not all coins are available).
   */

  getFee() {
    return super.getFee(this.view);
  }

  /**
   * Calculate the total input value.
   * @returns {Amount} value
   */

  getInputValue() {
    return super.getInputValue(this.view);
  }

  /**
   * Get all input addresses.
   * @returns {Address[]} addresses
   */

  getInputAddresses() {
    return super.getInputAddresses(this.view);
  }

  /**
   * Get all addresses.
   * @returns {Address[]} addresses
   */

  getAddresses() {
    return super.getAddresses(this.view);
  }

  /**
   * Get all input address hashes.
   * @returns {Hash[]} hashes
   */

  getInputHashes(enc) {
    return super.getInputHashes(this.view, enc);
  }

  /**
   * Get all address hashes.
   * @returns {Hash[]} hashes
   */

  getHashes(enc) {
    return super.getHashes(this.view, enc);
  }

  /**
   * Test whether the transaction has
   * all coins available/filled.
   * @returns {Boolean}
   */

  hasCoins() {
    return super.hasCoins(this.view);
  }

  /**
   * Calculate virtual sigop count.
   * @param {VerifyFlags?} flags
   * @returns {Number} sigop count
   */

  getSigops(flags) {
    return super.getSigops(this.view, flags);
  }

  /**
   * Calculate sigops weight, taking into account witness programs.
   * @param {VerifyFlags?} flags
   * @returns {Number} sigop weight
   */

  getSigopsCost(flags) {
    return super.getSigopsCost(this.view, flags);
  }

  /**
   * Calculate the virtual size of the transaction
   * (weighted against bytes per sigop cost).
   * @returns {Number} vsize
   */

  getSigopsSize() {
    return super.getSigopsSize(this.getSigopsCost());
  }

  /**
   * Perform contextual checks to verify input, output,
   * and fee values, as well as coinbase spend maturity
   * (coinbases can only be spent 100 blocks or more
   * after they're created). Note that this function is
   * consensus critical.
   * @param {Number} height - Height at which the
   * transaction is being spent. In the mempool this is
   * the chain height plus one at the time it entered the pool.
   * @returns {Boolean}
   */

  verifyInputs(height) {
    const [fee] = this.checkInputs(height);
    return fee !== -1;
  }

  /**
   * Perform contextual checks to verify input, output,
   * and fee values, as well as coinbase spend maturity
   * (coinbases can only be spent 100 blocks or more
   * after they're created). Note that this function is
   * consensus critical.
   * @param {Number} height - Height at which the
   * transaction is being spent. In the mempool this is
   * the chain height plus one at the time it entered the pool.
   * @returns {Array} [fee, reason, score]
   */

  checkInputs(height) {
    return super.checkInputs(this.view, height);
  }

  /**
   * Build input script (or witness) templates (with
   * OP_0 in place of signatures).
   * @param {Number} index - Input index.
   * @param {Coin|Output} coin
   * @param {KeyRing} ring
   * @returns {Boolean} Whether the script was able to be built.
   */

  scriptInput(index, coin, ring) {
    const input = this.inputs[index];

    assert(input, 'Input does not exist.');
    assert(coin, 'No coin passed.');

    // Don't bother with any below calculation
    // if the output is already templated.
    if (input.script.raw.length !== 0
        || input.witness.items.length !== 0) {
      return true;
    }

    // Get the previous output's script
    const prev = coin.script;

    // This is easily the hardest part about
    // building a transaction with segwit:
    // figuring out where the redeem script
    // and witness redeem scripts go.
    const sh = prev.getScripthash();

    if (sh) {
      const redeem = ring.getRedeem(sh);

      if (!redeem)
        return false;

      // Witness program nested in regular P2SH.
      if (redeem.isProgram()) {
        // P2WSH nested within pay-to-scripthash.
        const wsh = redeem.getWitnessScripthash();
        if (wsh) {
          const wredeem = ring.getRedeem(wsh);

          if (!wredeem)
            return false;

          const witness = this.scriptVector(wredeem, ring);

          if (!witness)
            return false;

          witness.push(wredeem.toRaw());

          input.witness.fromStack(witness);
          input.script.fromItems([redeem.toRaw()]);

          return true;
        }

        // P2WPKH nested within pay-to-scripthash.
        const wpkh = redeem.getWitnessPubkeyhash();
        if (wpkh) {
          const pkh = Script.fromPubkeyhash(wpkh);
          const witness = this.scriptVector(pkh, ring);

          if (!witness)
            return false;

          input.witness.fromStack(witness);
          input.script.fromItems([redeem.toRaw()]);

          return true;
        }

        // Unknown witness program.
        return false;
      }

      // Regular P2SH.
      const vector = this.scriptVector(redeem, ring);

      if (!vector)
        return false;

      vector.push(redeem.toRaw());

      input.script.fromStack(vector);

      return true;
    }

    // Witness program.
    if (prev.isProgram()) {
      // Bare P2WSH.
      const wsh = prev.getWitnessScripthash();
      if (wsh) {
        const wredeem = ring.getRedeem(wsh);

        if (!wredeem)
          return false;

        const vector = this.scriptVector(wredeem, ring);

        if (!vector)
          return false;

        vector.push(wredeem.toRaw());

        input.witness.fromStack(vector);

        return true;
      }

      // Bare P2WPKH.
      const wpkh = prev.getWitnessPubkeyhash();
      if (wpkh) {
        const pkh = Script.fromPubkeyhash(wpkh);
        const vector = this.scriptVector(pkh, ring);

        if (!vector)
          return false;

        input.witness.fromStack(vector);

        return true;
      }

      // Bare... who knows?
      return false;
    }

    // Wow, a normal output! Praise be to Jengus and Gord.
    const vector = this.scriptVector(prev, ring);

    if (!vector)
      return false;

    input.script.fromStack(vector);

    return true;
  }

  /**
   * Build script for a single vector
   * based on a previous script.
   * @param {Script} prev
   * @param {Buffer} ring
   * @return {Stack}
   */

  scriptVector(prev, ring) {
    // P2PK
    const pk = prev.getPubkey();
    if (pk) {
      if (!pk.equals(ring.publicKey))
        return null;

      const stack = new Stack();

      stack.pushInt(0);

      return stack;
    }

    // P2PKH
    const pkh = prev.getPubkeyhash();
    if (pkh) {
      if (!pkh.equals(ring.getKeyHash()))
        return null;

      const stack = new Stack();

      stack.pushInt(0);
      stack.pushData(ring.publicKey);

      return stack;
    }

    // Multisig
    const [, n] = prev.getMultisig();
    if (n !== -1) {
      if (prev.indexOf(ring.publicKey) === -1)
        return null;

      // Technically we should create m signature slots,
      // but we create n signature slots so we can order
      // the signatures properly.
      const stack = new Stack();

      stack.pushInt(0);

      // Fill script with `n` signature slots.
      for (let i = 0; i < n; i++)
        stack.pushInt(0);

      return stack;
    }

    return null;
  }

  /**
   * Sign a transaction input on the worker pool
   * (if workers are enabled).
   * @param {Number} index
   * @param {Coin|Output} coin
   * @param {KeyRing} ring
   * @param {SighashType?} type
   * @param {WorkerPool?} pool
   * @returns {Promise}
   */

  async signInputAsync(index, coin, ring, type, pool) {
    if (!pool)
      return this.signInput(index, coin, ring, type);

    return await pool.signInput(this, index, coin, ring, type, pool);
  }

  /**
   * Sign an input.
   * @param {Number} index - Index of input being signed.
   * @param {Coin|Output} coin
   * @param {KeyRing} ring - Private key.
   * @param {SighashType} type
   * @returns {Boolean} Whether the input was able to be signed.
   */

  signInput(index, coin, ring, type) {
    const input = this.inputs[index];
    const key = ring.privateKey;

    assert(input, 'Input does not exist.');
    assert(coin, 'No coin passed.');

    // Get the previous output's script
    const value = coin.value;
    let prev = coin.script;
    let vector = input.script;
    let version = 0;
    let redeem = false;

    // Grab regular p2sh redeem script.
    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      if (!prev)
        throw new Error('Input has not been templated.');
      redeem = true;
    }

    // If the output script is a witness program,
    // we have to switch the vector to the witness
    // and potentially alter the length. Note that
    // witnesses are stack items, so the `dummy`
    // _has_ to be an empty buffer (what OP_0
    // pushes onto the stack).
    if (prev.isWitnessScripthash()) {
      prev = input.witness.getRedeem();
      if (!prev)
        throw new Error('Input has not been templated.');
      vector = input.witness;
      redeem = true;
      version = 1;
    } else {
      const wpkh = prev.getWitnessPubkeyhash();
      if (wpkh) {
        prev = Script.fromPubkeyhash(wpkh);
        vector = input.witness;
        redeem = false;
        version = 1;
      }
    }

    // Create our signature.
    const sig = this.signature(index, prev, value, key, type, version);

    if (redeem) {
      const stack = vector.toStack();
      const redeem = stack.pop();

      const result = this.signVector(prev, stack, sig, ring);

      if (!result)
        return false;

      result.push(redeem);

      vector.fromStack(result);

      return true;
    }

    const stack = vector.toStack();
    const result = this.signVector(prev, stack, sig, ring);

    if (!result)
      return false;

    vector.fromStack(result);

    return true;
  }

  /**
   * Add a signature to a vector
   * based on a previous script.
   * @param {Script} prev
   * @param {Stack} vector
   * @param {Buffer} sig
   * @param {KeyRing} ring
   * @return {Stack|null}
   */

  signVector(prev, vector, sig, ring) {
    // P2PK
    const pk = prev.getPubkey();
    if (pk) {
      // Make sure the pubkey is ours.
      if (!ring.publicKey.equals(pk))
        return null;

      if (vector.length === 0)
        throw new Error('Input has not been templated.');

      // Already signed.
      if (vector.get(0).length > 0)
        return vector;

      vector.set(0, sig);

      return vector;
    }

    // P2PKH
    const pkh = prev.getPubkeyhash();
    if (pkh) {
      // Make sure the pubkey hash is ours.
      if (!ring.getKeyHash().equals(pkh))
        return null;

      if (vector.length !== 2)
        throw new Error('Input has not been templated.');

      if (vector.get(1).length === 0)
        throw new Error('Input has not been templated.');

      // Already signed.
      if (vector.get(0).length > 0)
        return vector;

      vector.set(0, sig);

      return vector;
    }

    // Multisig
    const [m, n] = prev.getMultisig();
    if (m !== -1) {
      if (vector.length < 2)
        throw new Error('Input has not been templated.');

      if (vector.get(0).length !== 0)
        throw new Error('Input has not been templated.');

      // Too many signature slots. Abort.
      if (vector.length - 1 > n)
        throw new Error('Input has not been templated.');

      // Count the number of current signatures.
      let total = 0;
      for (let i = 1; i < vector.length; i++) {
        const item = vector.get(i);
        if (item.length > 0)
          total += 1;
      }

      // Signatures are already finalized.
      if (total === m && vector.length - 1 === m)
        return vector;

      // Add some signature slots for us to use if
      // there was for some reason not enough.
      while (vector.length - 1 < n)
        vector.pushInt(0);

      // Grab the redeem script's keys to figure
      // out where our key should go.
      const keys = [];
      for (const op of prev.code) {
        if (op.data)
          keys.push(op.data);
      }

      // Find the key index so we can place
      // the signature in the same index.
      let keyIndex = -1;

      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (key.equals(ring.publicKey)) {
          keyIndex = i;
          break;
        }
      }

      // Our public key is not in the prev_out
      // script. We tried to sign a transaction
      // that is not redeemable by us.
      if (keyIndex === -1)
        return null;

      // Offset key index by one to turn it into
      // "sig index". Accounts for OP_0 byte at
      // the start.
      keyIndex += 1;

      // Add our signature to the correct slot
      // and increment the total number of
      // signatures.
      if (keyIndex < vector.length && total < m) {
        if (vector.get(keyIndex).length === 0) {
          vector.set(keyIndex, sig);
          total += 1;
        }
      }

      // All signatures added. Finalize.
      if (total >= m) {
        // Remove empty slots left over.
        for (let i = vector.length - 1; i >= 1; i--) {
          const item = vector.get(i);
          if (item.length === 0)
            vector.remove(i);
        }

        // Remove signatures which are not required.
        // This should never happen.
        while (total > m) {
          vector.pop();
          total -= 1;
        }

        // Sanity checks.
        assert(total === m);
        assert(vector.length - 1 === m);
      }

      return vector;
    }

    return null;
  }

  /**
   * Test whether the transaction is fully-signed.
   * @returns {Boolean}
   */

  isSigned() {
    for (let i = 0; i < this.inputs.length; i++) {
      const {prevout} = this.inputs[i];
      const coin = this.view.getOutput(prevout);

      if (!coin)
        return false;

      if (!this.isInputSigned(i, coin))
        return false;
    }

    return true;
  }

  /**
   * Test whether an input is fully-signed.
   * @param {Number} index
   * @param {Coin|Output} coin
   * @returns {Boolean}
   */

  isInputSigned(index, coin) {
    const input = this.inputs[index];

    assert(input, 'Input does not exist.');
    assert(coin, 'No coin passed.');

    let prev = coin.script;
    let vector = input.script;
    let redeem = false;

    // Grab redeem script if possible.
    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      if (!prev)
        return false;
      redeem = true;
    }

    // If the output script is a witness program,
    // we have to switch the vector to the witness
    // and potentially alter the length.
    if (prev.isWitnessScripthash()) {
      prev = input.witness.getRedeem();
      if (!prev)
        return false;
      vector = input.witness;
      redeem = true;
    } else {
      const wpkh = prev.getWitnessPubkeyhash();
      if (wpkh) {
        prev = Script.fromPubkeyhash(wpkh);
        vector = input.witness;
        redeem = false;
      }
    }

    const stack = vector.toStack();

    if (redeem)
      stack.pop();

    return this.isVectorSigned(prev, stack);
  }

  /**
   * Test whether a vector is fully-signed.
   * @param {Script} prev
   * @param {Stack} vector
   * @returns {Boolean}
   */

  isVectorSigned(prev, vector) {
    if (prev.isPubkey()) {
      if (vector.length !== 1)
        return false;

      if (vector.get(0).length === 0)
        return false;

      return true;
    }

    if (prev.isPubkeyhash()) {
      if (vector.length !== 2)
        return false;

      if (vector.get(0).length === 0)
        return false;

      if (vector.get(1).length === 0)
        return false;

      return true;
    }

    const [m] = prev.getMultisig();

    if (m !== -1) {
      // Ensure we have the correct number
      // of required signatures.
      if (vector.length - 1 !== m)
        return false;

      // Ensure all members are signatures.
      for (let i = 1; i < vector.length; i++) {
        const item = vector.get(i);
        if (item.length === 0)
          return false;
      }

      return true;
    }

    return false;
  }

  /**
   * Build input scripts (or witnesses).
   * @param {KeyRing} ring - Address used to sign. The address
   * must be able to redeem the coin.
   * @returns {Number} Number of inputs templated.
   */

  template(ring) {
    if (Array.isArray(ring)) {
      let total = 0;
      for (const key of ring)
        total += this.template(key);
      return total;
    }

    let total = 0;

    for (let i = 0; i < this.inputs.length; i++) {
      const {prevout} = this.inputs[i];
      const coin = this.view.getOutput(prevout);

      if (!coin)
        continue;

      if (!ring.ownOutput(coin))
        continue;

      // Build script for input
      if (!this.scriptInput(i, coin, ring))
        continue;

      total += 1;
    }

    return total;
  }

  /**
   * Build input scripts (or witnesses) and sign the inputs.
   * @param {KeyRing} ring - Address used to sign. The address
   * must be able to redeem the coin.
   * @param {SighashType} type
   * @returns {Number} Number of inputs signed.
   */

  sign(ring, type) {
    if (Array.isArray(ring)) {
      let total = 0;
      for (const key of ring)
        total += this.sign(key, type);
      return total;
    }

    assert(ring.privateKey, 'No private key available.');

    let total = 0;

    for (let i = 0; i < this.inputs.length; i++) {
      const {prevout} = this.inputs[i];
      const coin = this.view.getOutput(prevout);

      if (!coin)
        continue;

      if (!ring.ownOutput(coin))
        continue;

      // Build script for input
      if (!this.scriptInput(i, coin, ring))
        continue;

      // Sign input
      if (!this.signInput(i, coin, ring, type))
        continue;

      total += 1;
    }

    return total;
  }

  /**
   * Sign the transaction inputs on the worker pool
   * (if workers are enabled).
   * @param {KeyRing} ring
   * @param {SighashType?} type
   * @param {WorkerPool?} pool
   * @returns {Promise}
   */

  async signAsync(ring, type, pool) {
    if (!pool)
      return this.sign(ring, type);

    return await pool.sign(this, ring, type);
  }

  /**
   * Estimate maximum possible size.
   * @param {Function?} getAccount - Returns account that can spend
   * from a given address.
   * @returns {Number}
   */

  async estimateSize(getAccount) {
    let total = 0;

    // Version
    total += 4;

    // timelock
    total += 4;

    // Number of inputs
    total += encoding.sizeVarint(this.inputs.length);

    // Number of outputs
    total += encoding.sizeVarint(this.outputs.length);

    // since outputs are final, we can get final size
    for (const output of this.outputs)
      total += output.getSize();

    // Assume it's a witness txin
    // Witness marker and flag
    total += 2;

    // Add size for inputs
    for (const input of this.inputs) {
      const coin = this.view.getCoinFor(input);

      // We're out of luck here.
      // Just assume it's a p2pkh.
      if (!coin) {
        total += 110;
        continue;
      }

      total += await coin.estimateSpendingSize(getAccount);
    }

    return total;
  }

  /**
   * Select necessary coins based on total output value.
   * @param {Coin[]} coins
   * @param {Object?} options
   * @returns {CoinSelector}
   * @throws on not enough funds available.
   */

  selectCoins(coins, options) {
    const selector = new CoinSelector(this, options);
    return selector.select(coins);
  }

  /**
   * Attempt to subtract a fee from a single output.
   * @param {Number} index
   * @param {Amount} fee
   */

  subtractIndex(index, fee) {
    assert(typeof index === 'number');
    assert(typeof fee === 'number');

    const output = this.outputs[index];

    if (!output)
      throw new Error('Subtraction index does not exist.');

    if (output.value < fee + output.getDustThreshold())
      throw new Error('Could not subtract fee.');

    output.value -= fee;
  }

  /**
   * Attempt to subtract a fee from all outputs evenly.
   * @param {Amount} fee
   */

  subtractFee(fee) {
    assert(typeof fee === 'number');

    let outputs = 0;

    for (const output of this.outputs) {
      // Ignore nulldatas and
      // other OP_RETURN scripts.
      if (output.script.isUnspendable())
        continue;
      outputs += 1;
    }

    if (outputs === 0)
      throw new Error('Could not subtract fee.');

    const left = fee % outputs;
    const share = (fee - left) / outputs;

    // First pass, remove even shares.
    for (const output of this.outputs) {
      if (output.script.isUnspendable())
        continue;

      if (output.value < share + output.getDustThreshold())
        throw new Error('Could not subtract fee.');

      output.value -= share;
    }

    // Second pass, remove the remainder
    // for the one unlucky output.
    for (const output of this.outputs) {
      if (output.script.isUnspendable())
        continue;

      if (output.value >= left + output.getDustThreshold()) {
        output.value -= left;
        return;
      }
    }

    throw new Error('Could not subtract fee.');
  }

  /**
   * Select coins and fill the inputs.
   * @param {Coin[]} coins
   * @param {Object} options - See {@link MTX#selectCoins} options.
   * @returns {CoinSelector}
   */

  async fund(coins, options) {
    assert(options, 'Options are required.');
    assert(options.changeAddress, 'Change address is required.');
    assert(this.inputs.length === 0, 'TX is already funded.');

    // Select necessary coins.
    const select = await this.selectCoins(coins, options);

    // Add coins to transaction.
    for (const coin of select.chosen)
      this.addCoin(coin);

    // Attempt to subtract fee.
    if (select.subtractFee) {
      const index = select.subtractIndex;
      if (index !== -1)
        this.subtractIndex(index, select.fee);
      else
        this.subtractFee(select.fee);
    }

    // Add a change output.
    const output = new Output();
    output.value = select.change;
    output.script.fromAddress(select.changeAddress);

    if (output.isDust(policy.MIN_RELAY)) {
      // Do nothing. Change is added to fee.
      this.changeIndex = -1;
      assert.strictEqual(this.getFee(), select.fee + select.change);
    } else {
      this.outputs.push(output);
      this.changeIndex = this.outputs.length - 1;
      assert.strictEqual(this.getFee(), select.fee);
    }

    return select;
  }

  /**
   * Sort inputs and outputs according to BIP69.
   * @see https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
   */

  sortMembers() {
    let changeOutput = null;

    if (this.changeIndex !== -1) {
      changeOutput = this.outputs[this.changeIndex];
      assert(changeOutput);
    }

    this.inputs.sort(sortInputs);
    this.outputs.sort(sortOutputs);

    if (this.changeIndex !== -1) {
      this.changeIndex = this.outputs.indexOf(changeOutput);
      assert(this.changeIndex !== -1);
    }
  }

  /**
   * Avoid fee sniping.
   * @param {Number} height - Current chain height.
   * @see bitcoin/src/wallet/wallet.cpp
   */

  avoidFeeSniping(height) {
    assert(typeof height === 'number', 'Must pass in height.');

    if ((Math.random() * 10 | 0) === 0) {
      height -= Math.random() * 100 | 0;

      if (height < 0)
        height = 0;
    }

    this.setLocktime(height);
  }

  /**
   * Set locktime and sequences appropriately.
   * @param {Number} locktime
   */

  setLocktime(locktime) {
    assert((locktime >>> 0) === locktime, 'Locktime must be a uint32.');
    assert(this.inputs.length > 0, 'Cannot set sequence with no inputs.');

    for (const input of this.inputs) {
      if (input.sequence === 0xffffffff)
        input.sequence = 0xfffffffe;
    }

    this.locktime = locktime;
  }

  /**
   * Set sequence locktime.
   * @param {Number} index - Input index.
   * @param {Number} locktime
   * @param {Boolean?} seconds
   */

  setSequence(index, locktime, seconds) {
    const input = this.inputs[index];

    assert(input, 'Input does not exist.');
    assert((locktime >>> 0) === locktime, 'Locktime must be a uint32.');

    this.version = 2;

    if (seconds) {
      locktime >>>= consensus.SEQUENCE_GRANULARITY;
      locktime &= consensus.SEQUENCE_MASK;
      locktime |= consensus.SEQUENCE_TYPE_FLAG;
    } else {
      locktime &= consensus.SEQUENCE_MASK;
    }

    input.sequence = locktime;
  }

  /**
   * Inspect the transaction.
   * @returns {Object}
   */

  [inspectSymbol]() {
    return this.format();
  }

  /**
   * Inspect the transaction.
   * @returns {Object}
   */

  format() {
    return super.format(this.view);
  }

  /**
   * Convert transaction to JSON.
   * @returns {Object}
   */

  toJSON() {
    return super.toJSON(null, this.view);
  }

  /**
   * Convert transaction to JSON.
   * @param {Network} network
   * @returns {Object}
   */

  getJSON(network) {
    return super.getJSON(network, this.view);
  }

  /**
   * Inject properties from a json object
   * @param {Object} json
   */

  fromJSON(json) {
    super.fromJSON(json);

    for (let i = 0; i < json.inputs.length; i++) {
      const input = json.inputs[i];
      const {prevout} = input;

      if (!input.coin)
        continue;

      const coin = Coin.fromJSON(input.coin);

      coin.hash = util.fromRev(prevout.hash);
      coin.index = prevout.index;

      this.view.addCoin(coin);
    }

    return this;
  }

  /**
   * Instantiate a transaction from a
   * jsonified transaction object.
   * @param {Object} json - The jsonified transaction object.
   * @returns {MTX}
   */

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  /**
   * Instantiate a transaction from a buffer reader.
   * @param {BufferReader} br
   * @returns {MTX}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate a transaction from a serialized Buffer.
   * @param {Buffer} data
   * @param {String?} enc - Encoding, can be `'hex'` or null.
   * @returns {MTX}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Convert the MTX to a TX.
   * @returns {TX}
   */

  toTX() {
    return new TX().inject(this);
  }

  /**
   * Convert the MTX to a TX.
   * @returns {Array} [tx, view]
   */

  commit() {
    return [this.toTX(), this.view];
  }

  /**
   * Instantiate MTX from TX.
   * @param {TX} tx
   * @returns {MTX}
   */

  static fromTX(tx) {
    return new this().inject(tx);
  }

  /**
   * Test whether an object is an MTX.
   * @param {Object} obj
   * @returns {Boolean}
   */

  static isMTX(obj) {
    return obj instanceof MTX;
  }
}

function sortInputs(a, b) {
  return a.compare(b);
}

function sortOutputs(a, b) {
  return a.compare(b);
}

/*
 * Expose
 */

exports = MTX;
exports.MTX = MTX;
exports.FundingError = FundingError;

module.exports = exports;

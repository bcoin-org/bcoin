/*!
 * mtx.js - mutable transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var btcutils = require('../btc/utils');
var constants = require('../protocol/constants');
var Script = require('../script/script');
var opcodes = Script.opcodes;
var FundingError = require('../btc/errors').FundingError;
var TX = require('./tx');
var Input = require('./input');
var Output = require('./output');
var Coin = require('./coin');
var KeyRing = require('./keyring');
var Address = require('./address');
var workerPool = require('../workers/workerpool').pool;
var encoding = require('../utils/encoding');

/**
 * A mutable transaction object.
 * @exports MTX
 * @extends TX
 * @constructor
 * @param {Object} options
 * @param {Number?} options.version
 * @param {Number?} options.ps
 * @param {Number?} options.changeIndex
 * @param {Input[]?} options.inputs
 * @param {Output[]?} options.outputs
 * @property {Number} version - Transaction version. Note that BCoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Number} flag - Flag field for segregated witness.
 * Always non-zero (1 if not present).
 * @property {Input[]} inputs
 * @property {Output[]} outputs
 * @property {Number} locktime - nLockTime
 * @property {Number} ts - Timestamp of the block the transaction
 * was included in (unix time).
 * @property {Hash|null} block - Hash of the block the transaction
 * was included in.
 * @property {Number} index - Transaction's index in the block tx vector.
 * @property {Number} ps - "Pending Since": The time at which the transaction
 * was first seen. Only non-zero on unconfirmed transactions.
 * @property {Number} changeIndex - Index of the change output (-1 if unknown).
 * @property {Number} height - Height of the block the
 * transaction was included in (-1 if unconfirmed).
 * @property {ReversedHash|null} rblock - Reversed block hash (uint256le).
 * @property {ReversedHash} rhash - Reversed transaction hash (uint256le).
 * @property {ReversedHash} rwhash - Reversed witness
 * transaction hash (uint256le).
 * @property {String} txid - Transaction ID.
 * @property {String} wtxid - Witness transaction ID (Same as txid if no
 * witness is present. All zeroes if coinbase).
 */

function MTX(options) {
  if (!(this instanceof MTX))
    return new MTX(options);

  TX.call(this);

  this.mutable = true;
  this.changeIndex = -1;

  if (options)
    this.fromOptions(options);
}

util.inherits(MTX, TX);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MTX.prototype.fromOptions = function fromOptions(options) {
  var i;

  if (options.version != null) {
    assert(util.isNumber(options.version));
    this.version = options.version;
  }

  if (options.flag != null) {
    assert(util.isNumber(options.flag));
    this.flag = options.flag;
  }

  if (options.inputs) {
    assert(Array.isArray(options.inputs));
    for (i = 0; i < options.inputs.length; i++)
      this.addInput(options.inputs[i]);
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    for (i = 0; i < options.outputs.length; i++)
      this.addOutput(options.outputs[i]);
  }

  if (options.locktime != null) {
    assert(util.isNumber(options.locktime));
    this.locktime = options.locktime;
  }

  if (options.ps != null) {
    assert(util.isNumber(options.ps));
    this.ps = options.ps;
  }

  if (options.changeIndex != null) {
    assert(util.isNumber(options.changeIndex));
    this.changeIndex = options.changeIndex;
  }

  return this;
};

/**
 * Instantiate MTX from options.
 * @param {Object} options
 * @returns {MTX}
 */

MTX.fromOptions = function fromOptions(options) {
  return new MTX().fromOptions(options);
};

/**
 * Clone the transaction.
 * @returns {MTX}
 */

MTX.prototype.clone = function clone() {
  return new MTX(this);
};

/**
 * Add an input to the transaction.
 * @example
 * tx.addInput({ prevout: { hash: ... }, sequence: ... });
 * tx.addInput(prev, prevIndex);
 * tx.addInput(coin);
 * tx.addInput(bcoin.coin.fromTX(prev, prevIndex));
 * @param {Object|TX|Coin} options - Options object, transaction, or coin.
 * @param {Number?} index - Input of output if `options` is a TX.
 */

MTX.prototype.addInput = function addInput(options, index) {
  var input = new Input();
  input.mutable = true;

  if (options instanceof TX)
    input.fromTX(options, index);
  else if (options instanceof Coin)
    input.fromCoin(options);
  else
    input.fromOptions(options);

  this.inputs.push(input);

  return this;
};

/**
 * Add an output.
 * @example
 * tx.addOutput({ address: ..., value: 100000 });
 * tx.addOutput({ address: ..., value: Amount.value('0.1') });
 * tx.addOutput(receivingWallet, Amount.value('0.1'));
 * @param {Wallet|KeyRing|Object} obj - Wallet, Address,
 * or options (see {@link Script.createOutputScript} for options).
 * @param {Amount?} value - Only needs to be present for non-options.
 */

MTX.prototype.addOutput = function addOutput(options, value) {
  var output;

  if (options instanceof KeyRing)
    options = options.getAddress();

  if (typeof options === 'string')
    options = Address.fromBase58(options);

  if (options instanceof Address)
    options = Script.fromAddress(options);

  output = new Output();
  output.mutable = true;

  if (options instanceof Script) {
    assert(util.isNumber(value));
    assert(value >= 0);
    output.script.fromOptions(options);
    output.value = value;
  } else {
    output.fromOptions(options);
    assert(output.value >= 0);
  }

  this.outputs.push(output);

  return this;
};

/**
 * Build input script (or witness) templates (with
 * OP_0 in place of signatures).
 * @param {Number} index - Input index.
 * @param {KeyRing} ring
 * @returns {Boolean} Whether the script was able to be built.
 */

MTX.prototype.scriptInput = function scriptInput(index, ring) {
  var input = this.inputs[index];
  var prev, redeem;

  assert(input, 'Input does not exist.');

  // We should have previous outputs by now.
  if (!input.coin)
    return false;

  // Don't bother with any below calculation
  // if the output is already templated.
  if (input.script.length !== 0
      || input.witness.length !== 0) {
    return true;
  }

  // Get the previous output's script
  prev = input.coin.script;

  // This is easily the hardest part about building a transaction
  // with segwit: figuring out where the redeem script and witness
  // redeem scripts go.
  if (prev.isScripthash()) {
    redeem = ring.getRedeem(prev.get(1));

    if (!redeem)
      return false;

    // Witness program nested in regular P2SH.
    if (redeem.isProgram()) {
      // P2WSH nested within pay-to-scripthash.
      if (redeem.isWitnessScripthash()) {
        prev = ring.getRedeem(redeem.get(1));

        if (!prev)
          return false;

        if (!this.scriptVector(prev, input.witness, ring))
          return false;

        input.witness.push(prev.toRaw());
        input.script.push(redeem.toRaw());
        input.script.compile();

        return true;
      }

      // P2WPKH nested within pay-to-scripthash.
      if (redeem.isWitnessPubkeyhash()) {
        prev = Script.fromPubkeyhash(ring.keyHash);

        if (!this.scriptVector(prev, input.witness, ring))
          return false;

        input.script.push(redeem.toRaw());
        input.script.compile();

        return true;
      }

      // Unknown witness program.
      return false;
    }

    // Regular P2SH.
    if (!this.scriptVector(redeem, input.script, ring))
      return false;

    input.script.push(redeem.toRaw());
    input.script.compile();

    return true;
  }

  // Witness program.
  if (prev.isProgram()) {
    // Bare P2WSH.
    if (prev.isWitnessScripthash()) {
      redeem = ring.getRedeem(prev.get(1));

      if (!redeem)
        return false;

      if (!this.scriptVector(redeem, input.witness, ring))
        return false;

      input.witness.push(redeem.toRaw());
      input.script.compile();

      return true;
    }

    // Bare P2WPKH.
    if (prev.isWitnessPubkeyhash()) {
      prev = Script.fromPubkeyhash(prev.get(1));

      if (!this.scriptVector(prev, input.witness, ring))
        return false;

      input.script.compile();

      return true;
    }

    // Bare... who knows?
    return false;
  }

  // Wow, a normal output! Praise be to Jengus and Gord.
  return this.scriptVector(prev, input.script, ring);
};

/**
 * Build script for a single vector
 * based on a previous script.
 * @param {Script} prev
 * @param {Witness|Script} vector
 * @param {Buffer} ring
 * @return {Boolean}
 */

MTX.prototype.scriptVector = function scriptVector(prev, vector, ring) {
  var i, n;

  // P2PK
  if (prev.isPubkey()) {
    if (!util.equal(prev.get(0), ring.publicKey))
      return false;

    vector.set(0, opcodes.OP_0);

    return true;
  }

  // P2PKH
  if (prev.isPubkeyhash()) {
    if (!util.equal(prev.get(2), ring.keyHash))
      return false;

    vector.set(0, opcodes.OP_0);
    vector.set(1, ring.publicKey);

    return true;
  }

  // Multisig
  if (prev.isMultisig()) {
    if (prev.indexOf(ring.publicKey) === -1)
      return false;

    // Technically we should create m signature slots,
    // but we create n signature slots so we can order
    // the signatures properly.
    vector.set(0, opcodes.OP_0);

    // Grab `n` value (number of keys).
    n = prev.getSmall(prev.length - 2);

    // Fill script with `n` signature slots.
    for (i = 0; i < n; i++)
      vector.set(i + 1, opcodes.OP_0);

    return true;
  }

  return false;
};

/**
 * Sign a transaction input on the worker pool
 * (if workers are enabled).
 * @param {Number} index
 * @param {KeyRing} ring
 * @param {SighashType?} type
 * @returns {Promise}
 */

MTX.prototype.signInputAsync = function signInputAsync(index, ring, type) {
  return workerPool.signInput(this, index, ring, type);
};

/**
 * Sign an input.
 * @param {Number} index - Index of input being signed.
 * @param {KeyRing} ring - Private key.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 */

MTX.prototype.signInput = function signInput(index, ring, type) {
  var input = this.inputs[index];
  var version = 0;
  var redeem = false;
  var key = ring.privateKey;
  var prev, vector, sig, result;

  assert(input, 'Input does not exist.');

  // We should have previous outputs by now.
  if (!input.coin)
    return false;

  // Get the previous output's script
  prev = input.coin.script;
  vector = input.script;

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
  } else if (prev.isWitnessPubkeyhash()) {
    prev = Script.fromPubkeyhash(prev.get(1));
    vector = input.witness;
    redeem = false;
    version = 1;
  }

  // Create our signature.
  sig = this.signature(index, prev, key, type, version);

  if (redeem) {
    redeem = vector.pop();
    result = this.signVector(prev, vector, sig, ring);
    vector.push(redeem);
    vector.compile();
    return result;
  }

  return this.signVector(prev, vector, sig, ring);
};

/**
 * Add a signature to a vector
 * based on a previous script.
 * @param {Script} prev
 * @param {Witness|Script} vector
 * @param {Buffer} sig
 * @param {KeyRing} ring
 * @return {Boolean}
 */

MTX.prototype.signVector = function signVector(prev, vector, sig, ring) {
  var i, m, n, keys, keyIndex, total;

  // P2PK
  if (prev.isPubkey()) {
    // Make sure the pubkey is ours.
    if (!util.equal(ring.publicKey, prev.get(0)))
      return false;

    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    if (vector.getSmall(0) !== 0)
      throw new Error('Input has not been templated.');

    vector.set(0, sig);
    vector.compile();

    return true;
  }

  // P2PKH
  if (prev.isPubkeyhash()) {
    // Make sure the pubkey hash is ours.
    if (!util.equal(ring.keyHash, prev.get(2)))
      return false;

    // Already signed.
    if (Script.isSignature(vector.get(0)))
      return true;

    if (!Script.isKey(vector.get(1)))
      throw new Error('Input has not been templated.');

    vector.set(0, sig);
    vector.compile();

    return true;
  }

  // Multisig
  if (prev.isMultisig()) {
    // Grab the redeem script's keys to figure
    // out where our key should go.
    keys = [];

    for (i = 1; i < prev.length - 2; i++)
      keys.push(prev.get(i));

    // Grab `m` value (number of sigs required).
    m = prev.getSmall(0);

    // Grab `n` value (number of keys).
    n = prev.getSmall(prev.length - 2);

    if (vector.getSmall(0) !== 0)
      throw new Error('Input has not been templated.');

    // Too many signature slots. Abort.
    if (vector.length - 1 > n)
      return false;

    // Count the number of current signatures.
    total = 0;
    for (i = 1; i < vector.length; i++) {
      if (Script.isSignature(vector.get(i)))
        total++;
    }

    // Signatures are already finalized.
    if (total === m && vector.length - 1 === m)
      return true;

    // Add some signature slots for us to use if
    // there was for some reason not enough.
    while (vector.length - 1 < n)
      vector.push(opcodes.OP_0);

    // Find the key index so we can place
    // the signature in the same index.
    keyIndex = util.indexOf(keys, ring.publicKey);

    // Our public key is not in the prev_out
    // script. We tried to sign a transaction
    // that is not redeemable by us.
    if (keyIndex === -1)
      return false;

    // Offset key index by one to turn it into
    // "sig index". Accounts for OP_0 byte at
    // the start.
    keyIndex++;

    // Add our signature to the correct slot
    // and increment the total number of
    // signatures.
    if (keyIndex < vector.length && total < m) {
      if (vector.getSmall(keyIndex) === 0) {
        vector.set(keyIndex, sig);
        total++;
      }
    }

    // All signatures added. Finalize.
    if (total >= m) {
      // Remove empty slots left over.
      for (i = vector.length - 1; i >= 1; i--) {
        if (vector.getSmall(i) === 0)
          vector.remove(i);
      }

      // Remove signatures which are not required.
      // This should never happen.
      while (total > m) {
        vector.pop();
        total--;
      }

      // Sanity checks.
      assert(total === m);
      assert(vector.length - 1 === m);
    }

    vector.compile();

    if (total !== m)
      return false;

    return true;
  }

  return false;
};

/**
 * Combine and sort multisig signatures for script.
 * Mimics bitcoind's behavior.
 * @param {Number} index
 * @param {Script} prev
 * @param {Witness|Script} vector
 * @param {Number} version
 * @param {Buffer} data
 * @return {Boolean}
 */

MTX.prototype.combine = function combine(index, prev, vector, version, data) {
  var m = prev.getSmall(0);
  var sigs = [];
  var map = {};
  var result = false;
  var i, j, sig, type, msg, key, pub, res;

  if (data)
    sigs.push(data);

  for (i = 1; i < vector.length; i++) {
    sig = vector.get(i);
    if (Script.isSignature(sig))
      sigs.push(sig);
  }

  for (i = 0; i < sigs.length; i++) {
    sig = sigs[i];
    type = sig[sig.length - 1];

    msg = this.signatureHash(index, prev, type, version);

    for (j = 1; j < prev.length - 2; j++) {
      key = prev.get(j);
      pub = key.toString('hex');

      if (map[pub])
        continue;

      res = Script.checksig(msg, sig, key);

      if (res) {
        map[pub] = sig;
        if (util.equal(sig, data))
          result = true;
        break;
      }
    }
  }

  vector.clear();
  vector.push(opcodes.OP_0);

  for (i = 1; i < prev.length - 2; i++) {
    key = prev.get(i);
    pub = key.toString('hex');
    sig = map[pub];
    if (sig)
      vector.push(sig);
  }

  while (vector.length - 1 < m)
    vector.push(opcodes.OP_0);

  vector.compile();

  return result;
};

/**
 * Create a signature suitable for inserting into scriptSigs/witnesses.
 * @param {Number} index - Index of input being signed.
 * @param {Script} prev - Previous output script or redeem script
 * (in the case of witnesspubkeyhash, this should be the generated
 * p2pkh script).
 * @param {SighashType} type
 * @param {Number} version - Sighash version (0=legacy, 1=segwit).
 * @returns {Buffer} Signature in DER format.
 */

MTX.prototype.signature = function signature(index, prev, key, type, version) {
  var hash;

  if (type == null)
    type = constants.hashType.ALL;

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  // Get the hash of the current tx, minus the other
  // inputs, plus the sighash type.
  hash = this.signatureHash(index, prev, type, version);

  // Sign the transaction with our one input
  return Script.sign(hash, key, type);
};

/**
 * Test whether the transaction is fully-signed.
 * @returns {Boolean}
 */

MTX.prototype.isSigned = function isSigned() {
  for (var i = 0; i < this.inputs.length; i++) {
    if (!this.isInputSigned(i))
      return false;
  }
  return true;
};

/**
 * Test whether an input is fully-signed.
 * @param {Number} index
 * @returns {Boolean}
 */

MTX.prototype.isInputSigned = function isInputSigned(index) {
  var input = this.inputs[index];
  var prev, vector, redeem, result;

  assert(input, 'Input does not exist.');

  // We can't check for signatures unless
  // we have the previous output.
  if (!input.coin)
    return false;

  // Get the prevout's script
  prev = input.coin.script;

  // Script length, needed for multisig
  vector = input.script;
  redeem = false;

  // We need to grab the redeem script when
  // signing p2sh transactions.
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
  } else if (prev.isWitnessPubkeyhash()) {
    prev = Script.fromPubkeyhash(prev.get(1));
    vector = input.witness;
    redeem = false;
  }

  if (redeem) {
    redeem = vector.pop();
    result = this.isVectorSigned(prev, vector);
    vector.push(redeem);
    return result;
  }

  return this.isVectorSigned(prev, vector);
};

/**
 * Test whether a vector is fully-signed.
 * @param {Script} prev
 * @param {Script|Witness} vector
 * @returns {Boolean}
 */

MTX.prototype.isVectorSigned = function isVectorSigned(prev, vector) {
  var i, m;

  if (prev.isPubkey()) {
    if (!Script.isSignature(vector.get(0)))
      return false;
    return true;
  }

  if (prev.isPubkeyhash()) {
    if (!Script.isSignature(vector.get(0)))
      return false;
    return true;
  }

  if (prev.isMultisig()) {
    // Grab `m` value (number of required sigs).
    m = prev.getSmall(0);

    // Ensure all members are signatures.
    for (i = 1; i < vector.length; i++) {
      if (!Script.isSignature(vector.get(i)))
        return false;
    }

    // Ensure we have the correct number
    // of required signatures.
    if (vector.length - 1 !== m)
      return false;

    return true;
  }

  return false;
};

/**
 * Built input scripts (or witnesses) and sign the inputs.
 * @param {KeyRing} ring - Address used to sign. The address
 * must be able to redeem the coin.
 * @returns {Boolean} Whether the input was able to be signed.
 */

MTX.prototype.template = function template(ring) {
  var total = 0;
  var i;

  if (Array.isArray(ring)) {
    for (i = 0; i < ring.length; i++)
      total += this.template(ring[i]);
    return total;
  }

  for (i = 0; i < this.inputs.length; i++) {
    if (!ring.ownInput(this, i))
      continue;

    // Build script for input
    if (!this.scriptInput(i, ring))
      continue;

    total++;
  }

  return total;
};

/**
 * Built input scripts (or witnesses) and sign the inputs.
 * @param {KeyRing} ring - Address used to sign. The address
 * must be able to redeem the coin.
 * @param {SighashType} type
 * @returns {Boolean} Whether the input was able to be signed.
 */

MTX.prototype.sign = function sign(ring, type) {
  var total = 0;
  var i;

  if (Array.isArray(ring)) {
    for (i = 0; i < ring.length; i++)
      total += this.sign(ring[i], type);
    return total;
  }

  assert(ring.privateKey, 'No private key available.');

  for (i = 0; i < this.inputs.length; i++) {
    if (!ring.ownInput(this, i))
      continue;

    // Build script for input
    if (!this.scriptInput(i, ring))
      continue;

    // Sign input
    if (!this.signInput(i, ring, type))
      continue;

    total++;
  }

  return total;
};

/**
 * Sign the transaction inputs on the worker pool
 * (if workers are enabled).
 * @param {KeyRing} ring
 * @param {SighashType?} type
 * @returns {Promise}
 * @returns {Boolean} Whether the inputs are valid.
 */

MTX.prototype.signAsync = function signAsync(ring, type) {
  return workerPool.sign(this, ring, type);
};

/**
 * Test whether the transaction at least
 * has all script templates built.
 * @returns {Boolean}
 */

MTX.prototype.isScripted = function isScripted() {
  var i;

  if (this.outputs.length === 0)
    return false;

  if (this.inputs.length === 0)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    if (!this.isInputScripted(i))
      return false;
  }

  return true;
};

/**
 * Test whether the input at least
 * has all script templates built.
 * @returns {Boolean}
 */

MTX.prototype.isInputScripted = function isInputScripted(index) {
  var input = this.inputs[index];

  assert(input, 'Input does not exist.');

  if (input.script.raw.length === 0
      && input.witness.items.length === 0) {
    return false;
  }

  return true;
};

/**
 * Estimate maximum possible size.
 * @param {Object?} options - Wallet or options object.
 * @param {Number} options.m - Multisig `m` value.
 * @param {Number} options.n - Multisig `n` value.
 * @returns {Number}
 */

MTX.prototype.maxSize = function maxSize(options) {
  var scale = constants.WITNESS_SCALE_FACTOR;
  var i, j, input, total, size, prev, m, n, sz;
  var witness, hadWitness, redeem;

  if (!options && this.isScripted())
    return this.getVirtualSize();

  if (!options)
    options = {};

  // Calculate the size, minus the input scripts.
  total = this.getBaseSize();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    size = input.script.getSize();
    total -= encoding.sizeVarint(size) + size;
  }

  // Add size for signatures and public keys
  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    size = 0;
    witness = false;
    redeem = null;

    // We're out of luck here.
    // Just assume it's a p2pkh.
    if (!input.coin) {
      total += 110;
      continue;
    }

    // Get the previous output's script
    prev = input.coin.script;

    // If we have access to the redeem script,
    // we can use it to calculate size much easier.
    if (prev.isScripthash()) {
      // Need to add the redeem script size
      // here since it will be ignored by
      // the isMultisig clause.
      // OP_PUSHDATA2 [redeem]
      redeem = this._guessRedeem(prev.get(1), options);
      if (redeem) {
        prev = redeem;
        sz = prev.getSize();
        size += Script.sizePush(sz);
        size += sz;
      }
    }

    if (prev.isProgram()) {
      witness = true;

      // Now calculating vsize.
      if (redeem) {
        // The regular redeem script
        // is now worth 4 points.
        size += encoding.sizeVarint(size);
        size *= 4;
      } else {
        // Add one varint byte back
        // for the 0-byte input script.
        size += 1 * 4;
      }

      // Add 2 bytes for flag and marker.
      if (!hadWitness)
        size += 2;

      hadWitness = true;

      if (prev.isWitnessScripthash()) {
        redeem = this._guessRedeem(prev.get(1), options);
        if (redeem) {
          prev = redeem;
          sz = prev.getSize();
          size += encoding.sizeVarint(sz);
          size += sz;
        }
      } else if (prev.isWitnessPubkeyhash()) {
        prev = Script.fromPubkeyhash(prev.get(1));
      }
    }

    if (prev.isPubkey()) {
      // P2PK
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
    } else if (prev.isPubkeyhash()) {
      // P2PKH
      // OP_PUSHDATA0 [signature]
      size += 1 + 73;
      // OP_PUSHDATA0 [key]
      size += 1 + 33;
    } else if (prev.isMultisig()) {
      // Bare Multisig
      // Get the previous m value:
      m = prev.getSmall(0);
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
    } else if (prev.isScripthash() || prev.isWitnessScripthash()) {
      // P2SH Multisig
      // This technically won't work well for other
      // kinds of P2SH. It will also over-estimate
      // the fee by a lot (at least 10000 satoshis
      // since we don't have access to the m and n
      // values), which will be recalculated later.
      // If fee turns out to be smaller later, we
      // simply add more of the fee to the change
      // output.
      // m value
      m = options.m || 2;
      // n value
      n = options.n || 3;
      // OP_0
      size += 1;
      // OP_PUSHDATA0 [signature] ...
      size += (1 + 73) * m;
      // OP_PUSHDATA2 [redeem]
      size += 3;
      // m value
      size += 1;
      // OP_PUSHDATA0 [key] ...
      size += (1 + 33) * n;
      // n value
      size += 1;
      // OP_CHECKMULTISIG
      size += 1;
    } else {
      // OP_PUSHDATA0 [signature]
      for (j = 0; j < prev.length; j++) {
        if (Script.isKey(prev.get(j)))
          size += 1 + 73;
      }
    }

    if (witness) {
      // Calculate vsize if
      // we're a witness program.
      size = (size + scale - 1) / scale | 0;
    } else {
      // Byte for varint
      // size of input script.
      size += encoding.sizeVarint(size);
    }

    total += size;
  }

  return total;
};

/**
 * "Guess" a redeem script based on some options.
 * @private
 * @param {Object} options
 * @param {Buffer} hash
 * @returns {Script|null}
 */

MTX.prototype._guessRedeem = function guessRedeem(options, hash) {
  switch (hash.length) {
    case 20:
      if (options.witness) {
        if (options.n > 1)
          return Script.fromProgram(0, constants.ZERO_HASH);
        return Script.fromProgram(0, constants.ZERO_HASH160);
      }
      return options.script;
    case 32:
      return options.script;
  }
};

/**
 * Select necessary coins based on total output value.
 * @param {Coin[]} coins
 * @param {Object?} options
 * @param {String?} options.selection - Coin selection priority. Can
 * be `age`, `random`, or `all`. (default=age).
 * @param {Boolean} options.confirmed - Select only confirmed coins.
 * @param {Boolean} options.round - Whether to round to the nearest
 * kilobyte for fee calculation.
 * See {@link TX#getMinFee} vs. {@link TX#getRoundFee}.
 * @param {Boolean} options.free - Do not apply a fee if the
 * transaction priority is high enough to be considered free.
 * @param {Amount?} options.hardFee - Use a hard fee rather
 * than calculating one.
 * @param {Rate?} options.rate - Rate used for fee calculation.
 * @param {Number|Boolean} options.subtractFee - Whether to subtract the
 * fee from * existing outputs rather than adding more inputs.
 * @returns {CoinSelection}
 * @throws on not enough funds available.
 * @throws on unable to subtract fee.
 */

MTX.prototype.selectCoins = function selectCoins(coins, options) {
  var selector = new CoinSelector(this, options);
  return selector.select(coins);
};

/**
 * Attempt to subtract a fee from outputs.
 * @param {Amount} fee
 * @param {Number?} index
 */

MTX.prototype.subtractFee = function subtractFee(fee, index) {
  var i, min, output, hash, addrs;

  if (Buffer.isBuffer(index) || typeof index === 'string')
    index = [index];

  if (Array.isArray(index)) {
    addrs = [];
    for (i = 0; i < index.length; i++) {
      hash = Address.getHash(index[i]);
      if (hash)
        addrs.push(hash);
    }
  }

  if (typeof index === 'number') {
    output = this.outputs[index];

    if (!output)
      throw new Error('Subtraction index does not exist.');

    min = fee + output.getDustThreshold();

    if (output.value < min)
      throw new Error('Could not subtract fee.');

    output.value -= fee;

    return;
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    min = fee + output.getDustThreshold();

    if (addrs) {
      hash = output.getHash();

      if (!hash)
        continue;

      if (util.indexOf(addrs, hash) === -1)
        continue;
    }

    if (output.value >= min) {
      output.value -= fee;
      break;
    }
  }

  if (i === this.outputs.length)
    throw new Error('Could not subtract fee.');
};

/**
 * Select coins and fill the inputs.
 * @param {Coin[]} coins
 * @param {Object} options - See {@link MTX#selectCoins} options.
 * @returns {CoinSelector}
 */

MTX.prototype.fund = function fund(coins, options) {
  var i, select, change, changeAddress;

  assert(this.inputs.length === 0, 'TX is already filled.');

  // Select necessary coins.
  select = this.selectCoins(coins, options);

  // We need a change address.
  changeAddress = select.changeAddress;

  // If change address is not available,
  // send back to one of the coins' addresses.
  for (i = 0; i < select.chosen.length && !changeAddress; i++)
    changeAddress = select.chosen[i].getAddress();

  // Will only happen in rare cases where
  // we're redeeming all non-standard coins.
  if (!changeAddress)
    throw new Error('No change address available.');

  // Add coins to transaction.
  for (i = 0; i < select.chosen.length; i++)
    this.addInput(select.chosen[i]);

  // Attempt to subtract fee.
  if (select.shouldSubtract)
    this.subtractFee(select.fee, select.subtractFee);

  // Add a change output.
  this.addOutput({
    address: changeAddress,
    value: select.change
  });

  change = this.outputs[this.outputs.length - 1];

  if (change.isDust(constants.tx.MIN_RELAY)) {
    // Do nothing. Change is added to fee.
    this.outputs.pop();
    this.changeIndex = -1;
    assert.equal(this.getFee(), select.fee + select.change);
  } else {
    this.changeIndex = this.outputs.length - 1;
    assert.equal(this.getFee(), select.fee);
  }

  return select;
};

/**
 * Sort inputs and outputs according to BIP69.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki
 */

MTX.prototype.sortMembers = function sortMembers() {
  var changeOutput;

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
};

/**
 * Avoid fee sniping.
 * @param {Number?} [height=network.height] - Current chain height.
 * @see bitcoin/src/wallet/wallet.cpp
 */

MTX.prototype.avoidFeeSniping = function avoidFeeSniping(height) {
  assert(typeof height === 'number', 'Must pass in height.');

  if ((Math.random() * 10 | 0) === 0)
    height = Math.max(0, height - (Math.random() * 100 | 0));

  this.setLocktime(height);
};

/**
 * Set locktime and sequences appropriately.
 * @param {Number} locktime
 */

MTX.prototype.setLocktime = function setLocktime(locktime) {
  var i, input;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence === 0xffffffff)
      input.sequence = 0xffffffff - 1;
  }

  this.locktime = locktime;
};

/**
 * Set sequence locktime.
 * @param {Number} index - Input index.
 * @param {Number} locktime
 * @param {Boolean?} seconds
 */

MTX.prototype.setSequence = function setSequence(index, locktime, seconds) {
  var input = this.inputs[index];

  assert(input, 'Input does not exist.');

  this.version = 2;

  if (seconds) {
    locktime >>>= constants.sequence.GRANULARITY;
    locktime = constants.sequence.TYPE_FLAG | locktime;
  } else {
    locktime = constants.sequence.MASK & locktime;
  }

  input.sequence = locktime;
};

/**
 * Mark inputs and outputs as mutable.
 * @private
 */

MTX.prototype._mutable = function _mutable() {
  var i;
  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].mutable = true;
  for (i = 0; i < this.outputs.length; i++)
    this.outputs[i].mutable = true;
  return this;
};

/**
 * @see TX.fromJSON
 */

MTX.fromJSON = function fromJSON(json) {
  return new MTX().fromJSON(JSON)._mutable();
};

/**
 * @see TX.fromRaw
 */

MTX.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new MTX().fromRaw(data)._mutable();
};

/**
 * @see TX.fromExtended
 */

MTX.fromExtended = function fromExtended(data, saveCoins, enc) {
  if (typeof saveCoins === 'string') {
    enc = saveCoins;
    saveCoins = false;
  }

  if (typeof data === 'string')
    data = new Buffer(data, enc);

  return new MTX().fromExtended(data, saveCoins)._mutable();
};

/**
 * Convert the MTX to a TX.
 * @returns {TX}
 */

MTX.prototype.toTX = function toTX() {
  return new TX(this);
};

/**
 * Test whether an object is an MTX.
 * @param {Object} obj
 * @returns {Boolean}
 */

MTX.isMTX = function isMTX(obj) {
  return obj
    && Array.isArray(obj.inputs)
    && typeof obj.locktime === 'number'
    && typeof obj.scriptInput === 'function';
};

/**
 * Coin Selector
 * @constructor
 * @param {TX} tx
 * @param {Object?} options
 */

function CoinSelector(tx, options) {
  if (!(this instanceof CoinSelector))
    return new CoinSelector(tx, options);

  this.tx = tx.clone();
  this.coins = [];
  this.outputValue = 0;
  this.index = 0;
  this.chosen = [];
  this.change = 0;
  this.fee = 0;

  this.selection = 'age';
  this.shouldSubtract = false;
  this.subtractFee = null;
  this.free = false;
  this.height = -1;
  this.confirmations = -1;
  this.hardFee = -1;
  this.rate = constants.tx.MIN_RELAY;
  this.maxFee = -1;
  this.round = false;
  this.changeAddress = null;

  // Needed for size estimation.
  this.m = null;
  this.n = null;
  this.witness = false;
  this.script = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Initialize selector options.
 * @param {Object} options
 * @private
 */

CoinSelector.prototype.fromOptions = function fromOptions(options) {
  var addr;

  if (options.selection) {
    assert(typeof options.selection === 'string');
    this.selection = options.selection;
  }

  if (options.subtractFee != null) {
    this.subtractFee = options.subtractFee;
    this.shouldSubtract = options.subtractFee !== false;
  }

  if (options.free != null) {
    assert(typeof options.free === 'boolean');
    this.free = options.free;
  }

  if (options.height != null) {
    assert(util.isNumber(options.height));
    assert(options.height >= -1);
    this.height = options.height;
  }

  if (options.confirmations != null) {
    assert(util.isNumber(options.confirmations));
    assert(options.confirmations >= -1);
    this.confirmations = options.confirmations;
  }

  if (options.hardFee != null) {
    assert(util.isNumber(options.hardFee));
    assert(options.hardFee >= -1);
    this.hardFee = options.hardFee;
  }

  if (options.rate != null) {
    assert(util.isNumber(options.rate));
    assert(options.rate >= 0);
    this.rate = options.rate;
  }

  if (options.maxFee != null) {
    assert(util.isNumber(options.maxFee));
    assert(options.maxFee >= -1);
    this.maxFee = options.maxFee;
  }

  if (options.round != null) {
    assert(typeof options.round === 'boolean');
    this.round = options.round;
  }

  if (options.changeAddress) {
    addr = options.changeAddress;
    if (typeof addr === 'string') {
      this.changeAddress = Address.fromBase58(addr);
    } else {
      assert(addr instanceof Address);
      this.changeAddress = addr;
    }
  }

  if (options.m != null) {
    assert(util.isNumber(options.m));
    assert(options.m >= 1);
    this.m = options.m;
  }

  if (options.n != null) {
    assert(util.isNumber(options.n));
    assert(options.n >= 1);
    this.n = options.n;
  }

  if (options.witness != null) {
    assert(typeof options.witness === 'boolean');
    this.witness = options.witness;
  }

  if (options.script) {
    assert(options.script instanceof Script);
    this.script = options.script;
  }

  return this;
};

/**
 * Initialize the selector with coins to select from.
 * @param {Coin[]} coins
 */

CoinSelector.prototype.init = function init(coins) {
  this.coins = coins.slice();
  this.outputValue = this.tx.getOutputValue();
  this.index = 0;
  this.chosen = [];
  this.change = 0;
  this.fee = 0;
  this.tx.inputs.length = 0;

  switch (this.selection) {
    case 'all':
    case 'random':
      this.coins.sort(sortRandom);
      break;
    case 'age':
      this.coins.sort(sortAge);
      break;
    default:
      throw new FundingError('Bad selection type: ' + this.selection);
  }
};

/**
 * Calculate total value required.
 * @returns {Amount}
 */

CoinSelector.prototype.total = function total() {
  if (this.shouldSubtract)
    return this.outputValue;
  return this.outputValue + this.fee;
};

/**
 * Test whether the selector has
 * completely funded the transaction.
 * @returns {Boolean}
 */

CoinSelector.prototype.isFull = function isFull() {
  return this.tx.getInputValue() >= this.total();
};

/**
 * Test whether a coin is spendable
 * with regards to the options.
 * @param {Coin}
 * @returns {Boolean}
 */

CoinSelector.prototype.isSpendable = function isSpendable(coin) {
  var maturity = constants.tx.COINBASE_MATURITY;
  var conf;

  if (this.height === -1)
    return true;

  if (this.confirmations > 0) {
    if (coin.height === -1)
      return this.confirmations <= 0;

    conf = this.height - coin.height;

    if (conf < 0)
      return false;

    conf += 1;

    if (conf < this.confirmations)
      return false;
  }

  if (coin.coinbase) {
    if (this.height + 1 < coin.height + maturity)
      return false;
  }

  return true;
};

/**
 * Get the current fee based on a size.
 * @param {Number} size
 * @returns {Amount}
 */

CoinSelector.prototype.getFee = function getFee(size) {
  var fee;

  if (this.round)
    fee = btcutils.getRoundFee(size, this.rate);
  else
    fee = btcutils.getMinFee(size, this.rate);

  if (fee > constants.tx.MAX_FEE)
    fee = constants.tx.MAX_FEE;

  return fee;
};

/**
 * Fund the transaction with more
 * coins if the `total` was updated.
 */

CoinSelector.prototype.fund = function fund() {
  var coin;

  while (this.index < this.coins.length) {
    coin = this.coins[this.index++];

    if (!this.isSpendable(coin))
      continue;

    // Add new inputs until TX will have enough
    // funds to cover both minimum post cost
    // and fee.
    this.tx.addInput(coin);
    this.chosen.push(coin);

    if (this.selection === 'all')
      continue;

    // Stop once we're full.
    if (this.isFull())
      break;
  }
};

/**
 * Initiate selection from `coins`.
 * @param {Coin[]} coins
 * @returns {CoinSelector}
 */

CoinSelector.prototype.select = function select(coins) {
  this.init(coins);

  if (this.hardFee !== -1)
    this.selectHard(this.hardFee);
  else
    this.selectEstimate(constants.tx.MIN_FEE);

  if (!this.isFull()) {
    // Still failing to get enough funds.
    throw new FundingError(
      'Not enough funds.',
      this.tx.getInputValue(),
      this.total());
  }

  // How much money is left after filling outputs.
  this.change = this.tx.getInputValue() - this.total();

  return this;
};

/**
 * Initialize selection based on size estimate.
 * @param {Amount} fee
 */

CoinSelector.prototype.selectEstimate = function selectEstimate(fee) {
  var size;

  // Initial fee.
  this.fee = fee;

  // Transfer `total` funds maximum.
  this.fund();

  // Add dummy output (for `change`) to
  // calculate maximum TX size.
  this.tx.addOutput({
    // In case we don't have a change address,
    // use a fake p2pkh output to gauge size.
    script: this.changeAddress
      ? Script.fromAddress(this.changeAddress)
      : Script.fromPubkeyhash(constants.ZERO_HASH160),
    value: 0
  });

  if (this.free && this.height !== -1) {
    size = this.tx.maxSize(this);

    // Note that this will only work
    // if the mempool's rolling reject
    // fee is zero (i.e. the mempool is
    // not full).
    if (this.tx.isFree(this.height + 1, size)) {
      this.fee = 0;
      return;
    }
  }

  // Keep recalculating fee and funding
  // until we reach some sort of equilibrium.
  do {
    size = this.tx.maxSize(this);

    this.fee = this.getFee(size);

    if (this.maxFee > 0 && this.fee > this.maxFee) {
      throw new FundingError(
        'Fee is too high.',
        this.tx.getInputValue(),
        this.total());
    }

    // Failed to get enough funds, add more coins.
    if (!this.isFull())
      this.fund();
  } while (!this.isFull() && this.index < this.coins.length);
};

/**
 * Initiate selection based on a hard fee.
 * @param {Amount} fee
 */

CoinSelector.prototype.selectHard = function selectHard(fee) {
  // Initial fee.
  this.fee = fee;

  if (this.fee > constants.tx.MAX_FEE)
    this.fee = constants.tx.MAX_FEE;

  // Transfer `total` funds maximum.
  this.fund();
};

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

function sortInputs(a, b) {
  return util.cmp(a.prevout.toRaw(), b.prevout.toRaw());
}

function sortOutputs(a, b) {
  return util.cmp(a.toRaw(), b.toRaw());
}

/*
 * Expose
 */

module.exports = MTX;

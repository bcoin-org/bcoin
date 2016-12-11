/*!
 * tx.js - transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var btcutils = require('../btc/utils');
var Amount = require('../btc/amount');
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var Script = require('../script/script');
var BufferWriter = require('../utils/writer');
var VerifyResult = require('../btc/errors').VerifyResult;
var Input = require('./input');
var Output = require('./output');
var Outpoint = require('./outpoint');
var InvItem = require('./invitem');
var workerPool = require('../workers/workerpool').pool;
var BufferWriter = require('../utils/writer');
var BufferReader = require('../utils/reader');

/*
 * Constants
 */

var BAD_OKAY = 0;
var BAD_WITNESS = 1;
var BAD_P2SH = 2;
var BAD_NONSTD_P2WSH = 3;

/**
 * A static transaction object.
 * @exports TX
 * @constructor
 * @param {NakedTX} options - Transaction fields.
 * @property {String} type - "tx" (inv type).
 * @property {Number} version - Transaction version. Note that BCoin reads
 * versions as unsigned even though they are signed at the protocol level.
 * This value will never be negative.
 * @property {Number} flag - Flag field for segregated witness.
 * Always non-zero (1 if not present).
 * @property {Input[]} inputs
 * @property {Output[]} outputs
 * @property {Number} locktime - nLockTime
 */

function TX(options) {
  if (!(this instanceof TX))
    return new TX(options);

  this.version = 1;
  this.flag = 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = 0;
  this.mutable = false;

  this._hash = null;
  this._hhash = null;
  this._whash = null;

  this._raw = null;
  this._size = -1;
  this._witnessSize = -1;

  this._outputValue = -1;
  this._inputValue = -1;
  this._hashPrevouts = null;
  this._hashSequence = null;
  this._hashOutputs = null;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {NakedTX} options
 */

TX.prototype.fromOptions = function fromOptions(options) {
  var i;

  assert(options, 'TX data is required.');

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
      this.inputs.push(new Input(options.inputs[i]));
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs));
    for (i = 0; i < options.outputs.length; i++)
      this.outputs.push(new Output(options.outputs[i]));
  }

  if (options.locktime != null) {
    assert(util.isNumber(options.locktime));
    this.locktime = options.locktime;
  }

  return this;
};

/**
 * Instantiate TX from options object.
 * @param {NakedTX} options
 * @returns {TX}
 */

TX.fromOptions = function fromOptions(options) {
  return new TX().fromOptions(options);
};

/**
 * Clone the transaction.
 * @returns {TX}
 */

TX.prototype.clone = function clone() {
  return new TX(this);
};

/**
 * Hash the transaction with the non-witness serialization.
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

TX.prototype.hash = function _hash(enc) {
  var hash = this._hash;
  var hex;

  if (!hash) {
    hash = crypto.hash256(this.toNormal());
    if (!this.mutable)
      this._hash = hash;
  }

  if (enc === 'hex') {
    hex = this._hhash;
    if (!hex) {
      hex = hash.toString('hex');
      if (!this.mutable)
        this._hhash = hex;
    }
    hash = hex;
  }

  return hash;
};

/**
 * Hash the transaction with the witness
 * serialization, return the wtxid (normal
 * hash if no witness is present, all zeroes
 * if coinbase).
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

TX.prototype.witnessHash = function witnessHash(enc) {
  var hash = this._whash;

  if (!this.hasWitness())
    return this.hash(enc);

  if (!hash) {
    hash = crypto.hash256(this.toRaw());
    if (!this.mutable)
      this._whash = hash;
  }

  return enc === 'hex' ? hash.toString('hex') : hash;
};

/**
 * Serialize the transaction. Note
 * that this is cached. This will use
 * the witness serialization if a
 * witness is present.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.toRaw = function toRaw() {
  return this.getRaw().data;
};

/**
 * Serialize the transaction without the
 * witness vector, regardless of whether it
 * is a witness transaction or not.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.toNormal = function toNormal() {
  if (this.hasWitness())
    return this.frameNormal().data;
  return this.toRaw();
};

/**
 * Write the transaction to a buffer writer.
 * @param {BufferWriter} bw
 */

TX.prototype.toWriter = function toWriter(bw) {
  this.writeRaw(bw);
  return bw;
};

/**
 * Write the transaction to a buffer writer.
 * Uses non-witness serialization.
 * @param {BufferWriter} bw
 */

TX.prototype.toNormalWriter = function toNormalWriter(bw) {
  if (this.hasWitness()) {
    this.frameNormalWriter(bw);
    return bw;
  }
  return this.toWriter(bw);
};

/**
 * Serialize the transaction. Note
 * that this is cached. This will use
 * the witness serialization if a
 * witness is present.
 * @private
 * @returns {RawTX}
 */

TX.prototype.getRaw = function getRaw() {
  var raw;

  if (this.mutable) {
    assert(!this._raw);
    if (this.hasWitness())
      return this.frameWitness();
    return this.frameNormal();
  }

  if (this._raw) {
    assert(this._size > 0);
    assert(this._witnessSize >= 0);
    raw = new RawTX(this._size, this._witnessSize);
    raw.data = this._raw;
    return raw;
  }

  if (this.hasWitness())
    raw = this.frameWitness();
  else
    raw = this.frameNormal();

  this._raw = raw.data;
  this._size = raw.total;
  this._witnessSize = raw.witness;

  return raw;
};

/**
 * Write raw transaction to buffer writer.
 * Cache if possible.
 * @returns {RawTX}
 */

TX.prototype.writeRaw = function writeRaw(bw) {
  var raw;

  if (this.mutable) {
    if (this.hasWitness())
      return this.frameWitnessWriter(bw);
    return this.frameNormalWriter(bw);
  }

  raw = this.getRaw();
  bw.writeBytes(raw.data);

  return raw;
};

/**
 * Calculate total size and size of the witness bytes.
 * @returns {Object} Contains `total` and `witness`.
 */

TX.prototype.getSizes = function getSizes() {
  if (this.mutable)
    return this.writeRaw(new BufferWriter());
  return this.getRaw();
};

/**
 * Calculate the virtual size of the transaction.
 * Note that this is cached.
 * @returns {Number} vsize
 */

TX.prototype.getVirtualSize = function getVirtualSize() {
  var scale = constants.WITNESS_SCALE_FACTOR;
  return (this.getWeight() + scale - 1) / scale | 0;
};

/**
 * Calculate the weight of the transaction.
 * Note that this is cached.
 * @returns {Number} weight
 */

TX.prototype.getWeight = function getWeight() {
  var raw = this.getSizes();
  var base = raw.total - raw.witness;
  return base * (constants.WITNESS_SCALE_FACTOR - 1) + raw.total;
};

/**
 * Calculate the real size of the transaction
 * with the witness included.
 * @returns {Number} size
 */

TX.prototype.getSize = function getSize() {
  return this.getSizes().total;
};

/**
 * Calculate the size of the transaction
 * without the witness.
 * with the witness included.
 * @returns {Number} size
 */

TX.prototype.getBaseSize = function getBaseSize() {
  var raw = this.getSizes();
  return raw.total - raw.witness;
};

/**
 * Test whether the transaction has a non-empty witness.
 * @returns {Boolean}
 */

TX.prototype.hasWitness = function hasWitness() {
  var i, input;

  if (this._witnessSize !== -1)
    return this._witnessSize !== 0;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.witness.items.length > 0)
      return true;
  }

  return false;
};

/**
 * Get the signature hash of the transaction for signing verifying.
 * @param {Number} index - Index of input being signed/verified.
 * @param {Script} prev - Previous output script or redeem script
 * (in the case of witnesspubkeyhash, this should be the generated
 * p2pkh script).
 * @param {SighashType} type - Sighash type.
 * @param {Number} version - Sighash version (0=legacy, 1=segwit).
 * @returns {Buffer} Signature hash.
 */

TX.prototype.signatureHash = function signatureHash(index, prev, value, type, version) {
  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  assert(index >= 0 && index < this.inputs.length);
  assert(prev instanceof Script);
  assert(typeof value === 'number');

  // Traditional sighashing
  if (version === 0)
    return this.signatureHashV0(index, prev, type);

  // Segwit sighashing
  if (version === 1)
    return this.signatureHashV1(index, prev, value, type);

  assert(false, 'Unknown sighash version.');
};

/**
 * Legacy sighashing -- O(n^2).
 * @private
 * @param {Number} index
 * @param {Script} prev
 * @param {SighashType} type
 * @returns {Buffer}
 */

TX.prototype.signatureHashV0 = function signatureHashV0(index, prev, type) {
  var i, input, output;
  var bw = new BufferWriter();
  var hashType = type & 0x1f;

  if (hashType === constants.hashType.SINGLE) {
    // Bitcoind used to return 1 as an error code:
    // it ended up being treated like a hash.
    if (index >= this.outputs.length)
      return util.copy(constants.ONE_HASH);
  }

  // Remove all code separators.
  prev = prev.removeSeparators();

  bw.writeU32(this.version);

  if (type & constants.hashType.ANYONECANPAY) {
    bw.writeVarint(1);

    // Serialize only the current
    // input if ANYONECANPAY.
    input = this.inputs[index];

    // Outpoint.
    input.prevout.toWriter(bw);

    // Replace script with previous
    // output script if current index.
    bw.writeVarBytes(prev.toRaw());
    bw.writeU32(input.sequence);
  } else {
    bw.writeVarint(this.inputs.length);
    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];

      // Outpoint.
      input.prevout.toWriter(bw);

      // Replace script with previous
      // output script if current index.
      if (i === index) {
        bw.writeVarBytes(prev.toRaw());
        bw.writeU32(input.sequence);
        continue;
      }

      // Script is null.
      bw.writeVarint(0);

      // Sequences are 0 if NONE or SINGLE.
      if (hashType === constants.hashType.NONE
          || hashType === constants.hashType.SINGLE) {
        bw.writeU32(0);
      } else {
        bw.writeU32(input.sequence);
      }
    }
  }

  if (hashType === constants.hashType.NONE) {
    // No outputs if NONE.
    bw.writeVarint(0);
  } else if (hashType === constants.hashType.SINGLE) {
    // Drop all outputs after the
    // current input index if SINGLE.
    bw.writeVarint(index + 1);

    for (i = 0; i < index + 1; i++) {
      output = this.outputs[i];

      // Regular serialization if
      // at current input index.
      if (i === index) {
        bw.write64(output.value);
        bw.writeVarBytes(output.script.toRaw());
        continue;
      }

      // Null all outputs not at
      // current input index.
      bw.write64(-1);
      bw.writeVarint(0);
    }
  } else {
    // Regular output serialization if ALL.
    bw.writeVarint(this.outputs.length);

    for (i = 0; i < this.outputs.length; i++) {
      output = this.outputs[i];
      bw.write64(output.value);
      bw.writeVarBytes(output.script.toRaw());
    }
  }

  bw.writeU32(this.locktime);

  // Append the hash type.
  bw.writeU32(type);

  return crypto.hash256(bw.render());
};

/**
 * Witness sighashing -- O(n).
 * @private
 * @param {Number} index
 * @param {Script} prev
 * @param {SighashType} type
 * @returns {Buffer}
 */

TX.prototype.signatureHashV1 = function signatureHashV1(index, prev, value, type) {
  var i, bw, input, output, prevouts, sequences, outputs;

  if (!(type & constants.hashType.ANYONECANPAY)) {
    if (this._hashPrevouts) {
      prevouts = this._hashPrevouts;
    } else {
      bw = new BufferWriter();

      for (i = 0; i < this.inputs.length; i++) {
        input = this.inputs[i];
        input.prevout.toWriter(bw);
      }

      prevouts = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashPrevouts = prevouts;
    }
  } else {
    prevouts = util.copy(constants.ZERO_HASH);
  }

  if (!(type & constants.hashType.ANYONECANPAY)
      && (type & 0x1f) !== constants.hashType.SINGLE
      && (type & 0x1f) !== constants.hashType.NONE) {
    if (this._hashSequence) {
      sequences = this._hashSequence;
    } else {
      bw = new BufferWriter();

      for (i = 0; i < this.inputs.length; i++) {
        input = this.inputs[i];
        bw.writeU32(input.sequence);
      }

      sequences = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashSequence = sequences;
    }
  } else {
    sequences = util.copy(constants.ZERO_HASH);
  }

  if ((type & 0x1f) !== constants.hashType.SINGLE
      && (type & 0x1f) !== constants.hashType.NONE) {
    if (this._hashOutputs) {
      outputs = this._hashOutputs;
    } else {
      bw = new BufferWriter();

      for (i = 0; i < this.outputs.length; i++) {
        output = this.outputs[i];
        output.toWriter(bw);
      }

      outputs = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashOutputs = outputs;
    }
  } else if ((type & 0x1f) === constants.hashType.SINGLE && index < this.outputs.length) {
    output = this.outputs[index];
    outputs = crypto.hash256(output.toRaw());
  } else {
    outputs = util.copy(constants.ZERO_HASH);
  }

  input = this.inputs[index];

  bw = new BufferWriter();

  bw.writeU32(this.version);
  bw.writeBytes(prevouts);
  bw.writeBytes(sequences);
  bw.writeHash(input.prevout.hash);
  bw.writeU32(input.prevout.index);
  bw.writeVarBytes(prev.toRaw());
  bw.write64(value);
  bw.writeU32(input.sequence);
  bw.writeBytes(outputs);
  bw.writeU32(this.locktime);
  bw.writeU32(type);

  return crypto.hash256(bw.render());
};

/**
 * Verify all transaction inputs.
 * @param {CoinView} view
 * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the inputs are valid.
 */

TX.prototype.verify = function verify(view, flags) {
  var i, input, coin;

  if (this.inputs.length === 0)
    return false;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      return false;

    if (!this.verifyInput(i, coin, flags))
      return false;
  }

  return true;
};

/**
 * Verify a transaction input.
 * @param {Number} index - Index of output being
 * verified.
 * @param {Coin|Output} coin - Previous output.
 * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the input is valid.
 */

TX.prototype.verifyInput = function verifyInput(index, coin, flags) {
  var input = this.inputs[index];

  assert(input, 'Input does not exist.');
  assert(coin, 'No coin passed.');

  try {
    Script.verify(
      input.script,
      input.witness,
      coin.script,
      this,
      index,
      coin.value,
      flags
    );
  } catch (e) {
    if (e.type === 'ScriptError')
      return false;
    throw e;
  }

  return true;
};

/**
 * Verify the transaction inputs on the worker pool
 * (if workers are enabled).
 * @param {CoinView} view
 * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Promise}
 * @returns {Boolean} Whether the inputs are valid.
 */

TX.prototype.verifyAsync = co(function* verifyAsync(view, flags) {
  if (this.inputs.length === 0)
    return false;

  if (this.isCoinbase())
    return true;

  return yield workerPool.verify(this, view, flags);
});

/**
 * Verify a transaction input asynchronously.
 * @param {Number} index - Index of output being
 * verified.
 * @param {Coin|Output} coin - Previous output.
 * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the input is valid.
 */

TX.prototype.verifyInputAsync = co(function* verifyInputAsync(index, coin, flags) {
  var input = this.inputs[index];
  assert(input, 'Input does not exist.');
  return yield workerPool.verifyInput(this, index, coin, flags);
});

/**
 * Test whether the transaction is a coinbase
 * by examining the inputs.
 * @returns {Boolean}
 */

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1 && this.inputs[0].prevout.isNull();
};

/**
 * Test whether the transaction is replaceable.
 * @returns {Boolean}
 */

TX.prototype.isRBF = function isRBF() {
  var i, input;

  // Core doesn't do this, but it should:
  if (this.version === 2)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (input.isRBF())
      return true;
  }

  return false;
};

/**
 * Calculate the fee for the transaction.
 * @param {CoinView} view
 * @returns {Amount} fee (zero if not all coins are available).
 */

TX.prototype.getFee = function getFee(view) {
  if (!this.hasCoins(view))
    return 0;

  return this.getInputValue(view) - this.getOutputValue();
};

/**
 * Calculate the total input value.
 * @param {CoinView} view
 * @returns {Amount} value
 */

TX.prototype.getInputValue = function getInputValue(view) {
  var total = 0;
  var i, input, coin;

  if (this._inputValue !== -1)
    return this._inputValue;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      return 0;

    total += coin.value;
  }

  if (!this.mutable)
    this._inputValue = total;

  return total;
};

/**
 * Calculate the total output value.
 * @returns {Amount} value
 */

TX.prototype.getOutputValue = function getOutputValue() {
  var total = 0;
  var i, output;

  if (this._outputValue !== -1)
    return this._outputValue;

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    total += output.value;
  }

  if (!this.mutable)
    this._outputValue = total;

  return total;
};

/**
 * Get all input addresses.
 * @private
 * @param {CoinView} view
 * @returns {Array}
 */

TX.prototype._getInputAddresses = function getInputAddresses(view) {
  var table = {};
  var addrs = [];
  var i, address, hash, input, coin;

  if (this.isCoinbase())
    return [addrs, table];

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view ? view.getOutput(input) : null;
    address = input.getAddress(coin);

    if (!address)
      continue;

    hash = address.getHash('hex');

    if (!table[hash]) {
      table[hash] = true;
      addrs.push(address);
    }
  }

  return [addrs, table];
};

/**
 * Get all output addresses.
 * @private
 * @returns {Array}
 */

TX.prototype._getOutputAddresses = function getOutputAddresses() {
  var table = {};
  var addrs = [];
  var i, output, address, hash;

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    address = output.getAddress();

    if (!address)
      continue;

    hash = address.getHash('hex');

    if (!table[hash]) {
      table[hash] = true;
      addrs.push(address);
    }
  }

  return [addrs, table];
};

/**
 * Get all addresses.
 * @private
 * @param {CoinView} view
 * @returns {Array}
 */

TX.prototype._getAddresses = function getAddresses(view) {
  var inputs = this._getInputAddresses(view);
  var output = this.getOutputAddresses();
  var addrs = inputs[0];
  var table = inputs[1];
  var i, hash;

  for (i = 0; i < output.length; i++) {
    hash = output[i].getHash('hex');

    if (!table[hash]) {
      table[hash] = true;
      addrs.push(output[i]);
    }
  }

  return [addrs, table];
};

/**
 * Get all input addresses.
 * @private
 * @param {CoinView} view
 * @returns {Address[]} addresses
 */

TX.prototype.getInputAddresses = function getInputAddresses(view) {
  return this._getInputAddresses(view)[0];
};

/**
 * Get all output addresses.
 * @returns {Address[]} addresses
 */

TX.prototype.getOutputAddresses = function getOutputAddresses() {
  return this._getOutputAddresses()[0];
};

/**
 * Get all addresses.
 * @param {CoinView} view
 * @returns {Address[]} addresses
 */

TX.prototype.getAddresses = function getAddresses(view) {
  return this._getAddresses(view)[0];
};

/**
 * Get all input address hashes.
 * @param {CoinView} view
 * @returns {Hash[]} hashes
 */

TX.prototype.getInputHashes = function getInputHashes(view, enc) {
  var i, input, table;

  if (enc === 'hex') {
    table = this._getInputAddresses(view)[1];
    return Object.keys(table);
  }

  input = this.getInputAddresses(view);

  for (i = 0; i < input.length; i++)
    input[i] = input[i].getHash();

  return input;
};

/**
 * Get all output address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getOutputHashes = function getOutputHashes(enc) {
  var i, output, table;

  if (enc === 'hex') {
    table = this._getOutputAddresses()[1];
    return Object.keys(table);
  }

  output = this.getOutputAddresses();

  for (i = 0; i < output.length; i++)
    output[i] = output[i].getHash();

  return output;
};

/**
 * Get all address hashes.
 * @param {CoinView} view
 * @returns {Hash[]} hashes
 */

TX.prototype.getHashes = function getHashes(view, enc) {
  var i, hashes, table;

  if (enc === 'hex') {
    table = this._getAddresses(view)[1];
    return Object.keys(table);
  }

  hashes = this.getAddresses();

  for (i = 0; i < hashes.length; i++)
    hashes[i] = hashes[i].getHash();

  return hashes;
};

/**
 * Test whether the transaction has
 * all coins available/filled.
 * @param {CoinView} view
 * @returns {Boolean}
 */

TX.prototype.hasCoins = function hasCoins(view) {
  var i, input;

  if (this.inputs.length === 0)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (!view.getOutput(input))
      return false;
  }

  return true;
};

/**
 * Check finality of transaction by examining nLockTime and nSequences.
 * @example
 * tx.isFinal(network.height + 1, util.now());
 * @param {Number} height - Height at which to test. This
 * is usually the chain height, or the chain height + 1
 * when the transaction entered the mempool.
 * @param {Number} ts - Time at which to test. This is
 * usually the chain tip's parent's median time, or the
 * time at which the transaction entered the mempool. If
 * MEDIAN_TIME_PAST is enabled this will be the median
 * time of the chain tip's previous entry's median time.
 * @returns {Boolean}
 */

TX.prototype.isFinal = function isFinal(height, ts) {
  var threshold = constants.LOCKTIME_THRESHOLD;
  var i, input;

  if (this.locktime === 0)
    return true;

  if (this.locktime < (this.locktime < threshold ? height : ts))
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence !== 0xffffffff)
      return false;
  }

  return true;
};

/**
 * Calculate legacy (inaccurate) sigop count.
 * @returns {Number} sigop count
 */

TX.prototype.getLegacySigops = function getLegacySigops() {
  var total = 0;
  var i, input, output;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    total += input.script.getSigops(false);
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    total += output.script.getSigops(false);
  }

  return total;
};

/**
 * Calculate accurate sigop count, taking into account redeem scripts.
 * @param {CoinView} view
 * @returns {Number} sigop count
 */

TX.prototype.getScripthashSigops = function getScripthashSigops(view) {
  var total = 0;
  var i, input, coin;

  if (this.isCoinbase())
    return 0;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    if (coin.script.isScripthash())
      total += coin.script.getScripthashSigops(input.script);
  }

  return total;
};

/**
 * Calculate sigops weight, taking into account witness programs.
 * @param {CoinView} view
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop weight
 */

TX.prototype.getSigopsWeight = function getSigopsWeight(view, flags) {
  var weight = this.getLegacySigops() * constants.WITNESS_SCALE_FACTOR;
  var i, input, coin;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return weight;

  if (flags & constants.flags.VERIFY_P2SH)
    weight += this.getScripthashSigops(view) * constants.WITNESS_SCALE_FACTOR;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    weight += Script.getWitnessSigops(
      input.script,
      coin.script,
      input.witness,
      flags);
  }

  return weight;
};

/**
 * Calculate virtual sigop count.
 * @param {CoinView} view
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop count
 */

TX.prototype.getSigops = function getSigops(view, flags) {
  var scale = constants.WITNESS_SCALE_FACTOR;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  return (this.getSigopsWeight(view, flags) + scale - 1) / scale | 0;
};

/**
 * Non-contextual sanity checks for the transaction.
 * Will mostly verify coin and output values.
 * @see CheckTransaction()
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean} sane
 */

TX.prototype.isSane = function isSane(ret) {
  var prevout = {};
  var total = 0;
  var i, input, output, size, key;

  if (!ret)
    ret = new VerifyResult();

  if (this.inputs.length === 0) {
    ret.reason = 'bad-txns-vin-empty';
    ret.score = 100;
    return false;
  }

  if (this.outputs.length === 0) {
    ret.reason = 'bad-txns-vout-empty';
    ret.score = 100;
    return false;
  }

  if (this.getBaseSize() > constants.block.MAX_SIZE) {
    ret.reason = 'bad-txns-oversize';
    ret.score = 100;
    return false;
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];

    if (output.value < 0) {
      ret.reason = 'bad-txns-vout-negative';
      ret.score = 100;
      return false;
    }

    if (output.value > constants.MAX_MONEY) {
      ret.reason = 'bad-txns-vout-toolarge';
      ret.score = 100;
      return false;
    }

    total += output.value;

    if (total < 0 || total > constants.MAX_MONEY) {
      ret.reason = 'bad-txns-txouttotal-toolarge';
      ret.score = 100;
      return false;
    }
  }

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    key = input.prevout.toKey();
    if (prevout[key]) {
      ret.reason = 'bad-txns-inputs-duplicate';
      ret.score = 100;
      return false;
    }
    prevout[key] = true;
  }

  if (this.isCoinbase()) {
    size = this.inputs[0].script.getSize();
    if (size < 2 || size > 100) {
      ret.reason = 'bad-cb-length';
      ret.score = 100;
      return false;
    }
  } else {
    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];
      if (input.prevout.isNull()) {
        ret.reason = 'bad-txns-prevout-null';
        ret.score = 10;
        return false;
      }
    }
  }

  return true;
};

/**
 * Non-contextual checks to determine whether the
 * transaction has all standard output script
 * types and standard input script size with only
 * pushdatas in the code.
 * Will mostly verify coin and output values.
 * @see IsStandardTx()
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

TX.prototype.isStandard = function isStandard(ret) {
  var i, input, output;
  var nulldata = 0;

  if (!ret)
    ret = new VerifyResult();

  if (this.version < 1 || this.version > constants.tx.MAX_VERSION) {
    ret.reason = 'version';
    ret.score = 0;
    return false;
  }

  if (this.getWeight() >= constants.tx.MAX_WEIGHT) {
    ret.reason = 'tx-size';
    ret.score = 0;
    return false;
  }

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (input.script.getSize() > 1650) {
      ret.reason = 'scriptsig-size';
      ret.score = 0;
      return false;
    }

    if (!input.script.isPushOnly()) {
      ret.reason = 'scriptsig-not-pushonly';
      ret.score = 0;
      return false;
    }
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];

    if (!output.script.isStandard()) {
      ret.reason = 'scriptpubkey';
      ret.score = 0;
      return false;
    }

    if (output.script.isNulldata()) {
      nulldata++;
      continue;
    }

    if (output.script.isMultisig() && !constants.tx.BARE_MULTISIG) {
      ret.reason = 'bare-multisig';
      ret.score = 0;
      return false;
    }

    if (output.isDust(constants.tx.MIN_RELAY)) {
      ret.reason = 'dust';
      ret.score = 0;
      return false;
    }
  }

  if (nulldata > 1) {
    ret.reason = 'multi-op-return';
    ret.score = 0;
    return false;
  }

  return true;
};

/**
 * Perform contextual checks to verify coin and input
 * script standardness (including the redeem script).
 * @see AreInputsStandard()
 * @param {CoinView} view
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 */

TX.prototype.hasStandardInputs = function hasStandardInputs(view) {
  var maxSigops = constants.script.MAX_SCRIPTHASH_SIGOPS;
  var i, input, coin, redeem;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      return false;

    if (coin.script.isPubkeyhash())
      continue;

    if (coin.script.isScripthash()) {
      redeem = input.script.getRedeem();

      if (!redeem)
        return false;

      if (redeem.getSigops(true) > maxSigops)
        return false;

      continue;
    }

    if (coin.script.isUnknown())
      return false;
  }

  return true;
};

/**
 * Perform contextual checks to verify coin and witness standardness.
 * @see IsBadWitness()
 * @param {CoinView} view
 * @returns {Boolean}
 */

TX.prototype.hasStandardWitness = function hasStandardWitness(view, ret) {
  var result;

  if (!ret)
    ret = new VerifyResult();

  result = this.getWitnessStandard(view);

  switch (result) {
    case BAD_WITNESS:
      ret.reason = 'bad-witness';
      ret.score = 100;
      return false;
    case BAD_P2SH:
      ret.reason = 'bad-P2SH-scriptSig';
      ret.score = 100;
      return false;
    case BAD_NONSTD_P2WSH:
      ret.reason = 'bad-witness-nonstandard';
      ret.score = 0;
      return false;
  }

  return true;
};

/**
 * Perform contextual checks to verify coin and witness standardness.
 * @private
 * @see IsBadWitness()
 * @param {CoinView} view
 * @returns {Boolean}
 */

TX.prototype.getWitnessStandard = function getWitnessStandard(view) {
  var ret = BAD_OKAY;
  var i, j, input, prev, hash, redeem, m, n, coin;

  if (!this.hasWitness())
    return ret;

  if (this.isCoinbase())
    return ret;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    if (input.witness.length === 0)
      continue;

    prev = coin.script;

    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      if (!prev)
        return BAD_P2SH;
    }

    if (!prev.isProgram())
      return BAD_WITNESS;

    if (prev.isWitnessPubkeyhash()) {
      if (input.witness.length !== 2)
        return BAD_WITNESS;

      if (input.witness.get(0).length > 73)
        return BAD_WITNESS;

      hash = crypto.hash160(input.witness.get(1));

      if (!util.equal(hash, prev.get(1)))
        return BAD_WITNESS;

      continue;
    }

    if (!prev.isWitnessScripthash()) {
      // Unknown program type,
      // let it through for now.
      continue;
    }

    redeem = input.witness.get(input.witness.length - 1);

    if (redeem.length > constants.script.MAX_SIZE)
      return BAD_WITNESS;

    if (redeem.length > constants.script.MAX_P2WSH_SIZE)
      ret = BAD_NONSTD_P2WSH;

    hash = crypto.sha256(redeem);

    if (!util.equal(hash, prev.get(1)))
      return BAD_WITNESS;

    // Based on Johnson Lau's calculations:
    if (input.witness.length - 1 > 604)
      return BAD_WITNESS;

    if (input.witness.length - 1 > constants.script.MAX_P2WSH_STACK)
      ret = BAD_NONSTD_P2WSH;

    for (j = 0; j < input.witness.length; j++) {
      if (input.witness.get(j).length > constants.script.MAX_PUSH)
        return BAD_WITNESS;

      if (input.witness.get(j).length > constants.script.MAX_P2WSH_PUSH)
        ret = BAD_NONSTD_P2WSH;
    }

    redeem = new Script(redeem);

    if (redeem.isPubkey()) {
      if (input.witness.length - 1 !== 1)
        return BAD_WITNESS;

      if (input.witness.get(0).length > 73)
        return BAD_WITNESS;

      continue;
    }

    if (redeem.isPubkeyhash()) {
      if (input.witness.length - 1 !== 2)
        return BAD_WITNESS;

      if (input.witness.get(0).length > 73)
        return BAD_WITNESS;

      continue;
    }

    if (redeem.isMultisig()) {
      m = redeem.getSmall(0);
      n = redeem.getSmall(redeem.length - 2);

      if (input.witness.length - 1 !== m + 1)
        return BAD_WITNESS;

      if (input.witness.get(0).length !== 0)
        return BAD_WITNESS;

      for (j = 1; j < input.witness.length - 1; j++) {
        if (input.witness.get(i).length > 73)
          return BAD_WITNESS;
      }
    }
  }

  return ret;
};

/**
 * Perform contextual checks to verify input, output,
 * and fee values, as well as coinbase spend maturity
 * (coinbases can only be spent 100 blocks or more
 * after they're created). Note that this function is
 * consensus critical.
 * @param {CoinView} view
 * @param {Number} spendHeight - Height at which the
 * transaction is being spent. In the mempool this is
 * the chain height plus one at the time it entered the pool.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

TX.prototype.checkInputs = function checkInputs(view, spendHeight, ret) {
  var total = 0;
  var i, input, coins, coin, fee, value;

  if (!ret)
    ret = new VerifyResult();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coins = view.get(input.prevout.hash);

    if (!coins) {
      // Note: don't trigger dos score here.
      ret.reason = 'bad-txns-inputs-missingorspent';
      ret.score = 0;
      return false;
    }

    if (coins.coinbase && spendHeight != null) {
      if (spendHeight - coins.height < constants.tx.COINBASE_MATURITY) {
        ret.reason = 'bad-txns-premature-spend-of-coinbase';
        ret.score = 0;
        return false;
      }
    }

    coin = view.getOutput(input);

    if (coin.value < 0 || coin.value > constants.MAX_MONEY) {
      ret.reason = 'bad-txns-inputvalues-outofrange';
      ret.score = 100;
      return false;
    }

    total += coin.value;

    if (total < 0 || total > constants.MAX_MONEY) {
      ret.reason = 'bad-txns-inputvalues-outofrange';
      ret.score = 100;
      return false;
    }
  }

  // Overflows already checked in `isSane()`.
  value = this.getOutputValue();

  if (total < value) {
    ret.reason = 'bad-txns-in-belowout';
    ret.score = 100;
    return false;
  }

  fee = total - value;

  if (fee < 0) {
    ret.reason = 'bad-txns-fee-negative';
    ret.score = 100;
    return false;
  }

  if (fee > constants.MAX_MONEY) {
    ret.reason = 'bad-txns-fee-outofrange';
    ret.score = 100;
    return false;
  }

  return true;
};

/**
 * Calculate the modified size of the transaction. This
 * is used in the mempool for calculating priority.
 * @param {Number?} size - The size to modify. If not present,
 * virtual size will be used.
 * @returns {Number} Modified size.
 */

TX.prototype.getModifiedSize = function getModifiedSize(size) {
  var i, input, offset;

  if (size == null)
    size = this.getVirtualSize();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    offset = 41 + Math.min(110, input.script.getSize());
    if (size > offset)
      size -= offset;
  }

  return size;
};

/**
 * Calculate the transaction priority.
 * @param {CoinView} view
 * @param {Number?} height - If not present, tx height
 * or network height will be used.
 * @param {Number?} size - Size to calculate priority
 * based on. If not present, virtual size will be used.
 * @returns {Number}
 */

TX.prototype.getPriority = function getPriority(view, height, size) {
  var sum = 0;
  var i, input, age, coin, coinHeight;

  assert(typeof height === 'number', 'Must pass in height.');

  if (this.isCoinbase())
    return sum;

  if (size == null)
    size = this.getVirtualSize();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    coinHeight = view.getHeight(input);

    if (coinHeight === -1)
      continue;

    if (coinHeight <= height) {
      age = height - coinHeight;
      sum += coin.value * age;
    }
  }

  return Math.floor(sum / size);
};

/**
 * Calculate the transaction's on-chain value.
 * @param {CoinView} view
 * @param {Number?} height
 * @returns {Number}
 */

TX.prototype.getChainValue = function getChainValue(view, height) {
  var value = 0;
  var i, input, coin, coinHeight;

  if (this.isCoinbase())
    return value;

  if (height == null)
    height = Infinity;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    coinHeight = view.getHeight(input);

    if (coinHeight === -1)
      continue;

    if (coinHeight <= height)
      value += coin.value;
  }

  return value;
};

/**
 * Determine whether the transaction is above the
 * free threshold in priority. A transaction which
 * passed this test is most likely relayable
 * without a fee.
 * @param {CoinView} view
 * @param {Number?} height - If not present, tx
 * height or network height will be used.
 * @param {Number?} size - If not present, modified
 * size will be calculated and used.
 * @returns {Boolean}
 */

TX.prototype.isFree = function isFree(view, height, size) {
  var priority = this.getPriority(view, height, size);
  return priority > constants.tx.FREE_THRESHOLD;
};

/**
 * Calculate minimum fee in order for the transaction
 * to be relayable (not the constant min relay fee).
 * @param {Number?} size - If not present, max size
 * estimation will be calculated and used.
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

TX.prototype.getMinFee = function getMinFee(size, rate) {
  if (size == null)
    size = this.getVirtualSize();

  return btcutils.getMinFee(size, rate);
};

/**
 * Calculate the minimum fee in order for the transaction
 * to be relayable, but _round to the nearest kilobyte
 * when taking into account size.
 * @param {Number?} size - If not present, max size
 * estimation will be calculated and used.
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

TX.prototype.getRoundFee = function getRoundFee(size, rate) {
  if (size == null)
    size = this.getVirtualSize();

  return btcutils.getRoundFee(size, rate);
};

/**
 * Calculate the transaction's rate based on size
 * and fees. Size will be calculated if not present.
 * @param {CoinView} view
 * @param {Number?} size
 * @returns {Rate}
 */

TX.prototype.getRate = function getRate(view, size) {
  if (size == null)
    size = this.getVirtualSize();

  return btcutils.getRate(size, this.getFee(view));
};

/**
 * Get all unique outpoint hashes.
 * @returns {Hash[]} Outpoint hashes.
 */

TX.prototype.getPrevout = function getPrevout() {
  var prevout = {};
  var i, input;

  if (this.isCoinbase())
    return [];

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    prevout[input.prevout.hash] = true;
  }

  return Object.keys(prevout);
};

/**
 * Test a transaction against a bloom filter using
 * the BIP37 matching algorithm. Note that this may
 * update the filter depending on what the `update`
 * value is.
 * @see "Filter matching algorithm":
 * @see https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki
 * @param {Bloom} filter
 * @returns {Boolean} True if the transaction matched.
 */

TX.prototype.isWatched = function isWatched(filter) {
  var found = false;
  var i, input, output, prevout;

  // 1. Test the tx hash
  if (filter.test(this.hash()))
    found = true;

  // 2. Test data elements in output scripts
  //    (may need to update filter on match)
  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    // Test the output script
    if (output.script.test(filter)) {
      if (filter.update === constants.filterFlags.ALL) {
        prevout = Outpoint.fromTX(this, i);
        filter.add(prevout.toRaw());
      } else if (filter.update === constants.filterFlags.PUBKEY_ONLY) {
        if (output.script.isPubkey() || output.script.isMultisig()) {
          prevout = Outpoint.fromTX(this, i);
          filter.add(prevout.toRaw());
        }
      }
      found = true;
    }
  }

  if (found)
    return found;

  // 3. Test prev_out structure
  // 4. Test data elements in input scripts
  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    prevout = input.prevout;

    // Test the COutPoint structure
    if (filter.test(prevout.toRaw()))
      return true;

    // Test the input script
    if (input.script.test(filter))
      return true;

    // Test the witness
    if (input.witness.test(filter))
      return true;
  }

  // 5. No match
  return false;
};

/**
 * Get little-endian tx hash.
 * @returns {Hash}
 */

TX.prototype.rhash = function() {
  return util.revHex(this.hash('hex'));
};

/**
 * Get little-endian wtx hash.
 * @returns {Hash}
 */

TX.prototype.rwhash = function() {
  return util.revHex(this.witnessHash('hex'));
};

/**
 * Get little-endian tx hash.
 * @returns {Hash}
 */

TX.prototype.txid = function() {
  return this.rhash();
};

/**
 * Get little-endian wtx hash.
 * @returns {Hash}
 */

TX.prototype.wtxid = function() {
  return this.rwhash();
};

/**
 * Convert the tx to an inv item.
 * @returns {InvItem}
 */

TX.prototype.toInv = function toInv() {
  return new InvItem(constants.inv.TX, this.hash('hex'));
};

/**
 * Inspect the transaction and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

TX.prototype.inspect = function inspect() {
  return this.format();
};

/**
 * Inspect the transaction and return a more
 * user-friendly representation of the data.
 * @param {CoinView} view
 * @param {ChainEntry} entry
 * @param {Number} index
 * @returns {Object}
 */

TX.prototype.format = function format(view, entry, index) {
  var rate = 0;
  var fee = 0;
  var height = -1;
  var block = null;
  var ts = 0;
  var date = null;

  if (view) {
    fee = this.getFee(view);
    rate = this.getRate(view);

    // Rate can exceed 53 bits in testing.
    if (!util.isSafeInteger(rate))
      rate = 0;
  }

  if (entry) {
    height = entry.height;
    block = util.revHex(entry.hash);
    ts = entry.ts;
    date = util.date(ts);
  }

  if (index == null)
    index = -1;

  return {
    hash: this.txid(),
    witnessHash: this.wtxid(),
    size: this.getSize(),
    virtualSize: this.getVirtualSize(),
    value: Amount.btc(this.getOutputValue()),
    fee: Amount.btc(fee),
    rate: Amount.btc(rate),
    minFee: Amount.btc(this.getMinFee()),
    height: height,
    block: block,
    ts: ts,
    date: date,
    index: index,
    version: this.version,
    flag: this.flag,
    inputs: this.inputs.map(function(input) {
      var coin = view ? view.getOutput(input) : null;
      return input.format(coin);
    }),
    outputs: this.outputs,
    locktime: this.locktime
  };
};

/**
 * Convert the transaction to an object suitable
 * for JSON serialization.
 * @returns {Object}
 */

TX.prototype.toJSON = function toJSON() {
  return this.getJSON();
};

/**
 * Convert the transaction to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @param {Network} network
 * @param {CoinView} view
 * @param {ChainEntry} entry
 * @param {Number} index
 * @returns {Object}
 */

TX.prototype.getJSON = function getJSON(network, view, entry, index) {
  var rate, fee, height, block, ts, date;

  if (view) {
    fee = this.getFee(view);
    rate = this.getRate(view);

    // Rate can exceed 53 bits in testing.
    if (!util.isSafeInteger(rate))
      rate = 0;

    fee = Amount.btc(fee);
    rate = Amount.btc(rate);
  }

  if (entry) {
    height = entry.height;
    block = util.revHex(entry.hash);
    ts = entry.ts;
    date = util.date(ts);
  }

  network = Network.get(network);

  return {
    hash: this.txid(),
    witnessHash: this.wtxid(),
    fee: fee,
    rate: rate,
    ps: util.now(),
    height: height,
    block: block,
    ts: ts,
    date: date,
    index: index,
    version: this.version,
    flag: this.flag,
    inputs: this.inputs.map(function(input) {
      var coin = view ? view.getCoin(input) : null;
      return input.getJSON(network, coin);
    }),
    outputs: this.outputs.map(function(output) {
      return output.getJSON(network);
    }),
    locktime: this.locktime
  };
};

/**
 * Inject properties from a json object.
 * @private
 * @param {Object} json
 */

TX.prototype.fromJSON = function fromJSON(json) {
  var i, input, output;

  assert(json, 'TX data is required.');
  assert(util.isNumber(json.version));
  assert(util.isNumber(json.flag));
  assert(Array.isArray(json.inputs));
  assert(Array.isArray(json.outputs));
  assert(util.isNumber(json.locktime));

  this.version = json.version;

  this.flag = json.flag;

  for (i = 0; i < json.inputs.length; i++) {
    input = json.inputs[i];
    this.inputs.push(Input.fromJSON(input));
  }

  for (i = 0; i < json.outputs.length; i++) {
    output = json.outputs[i];
    this.outputs.push(Output.fromJSON(output));
  }

  this.locktime = json.locktime;

  return this;
};

/**
 * Instantiate a transaction from a
 * jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {TX}
 */

TX.fromJSON = function fromJSON(json) {
  return new TX().fromJSON(json);
};

/**
 * Instantiate a transaction from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {TX}
 */

TX.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = new Buffer(data, enc);
  return new TX().fromRaw(data);
};

/**
 * Instantiate a transaction from a buffer reader.
 * @param {BufferReader} br
 * @returns {TX}
 */

TX.fromReader = function fromReader(br) {
  return new TX().fromReader(br);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

TX.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

TX.prototype.fromReader = function fromReader(br) {
  var i, count;

  if (TX.isWitness(br))
    return this.fromWitnessReader(br);

  br.start();

  this.version = br.readU32();

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.inputs.push(Input.fromReader(br));

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.outputs.push(Output.fromReader(br));

  this.locktime = br.readU32();

  if (!this.mutable) {
    this._raw = br.endData();
    this._size = this._raw.length;
    this._witnessSize = 0;
  } else {
    br.end();
  }

  return this;
};

/**
 * Inject properties from serialized
 * buffer reader (witness serialization).
 * @private
 * @param {BufferReader} br
 */

TX.prototype.fromWitnessReader = function fromWitnessReader(br) {
  var flag = 0;
  var witnessSize = 0;
  var hasWitness = false;
  var i, count, input;

  br.start();

  this.version = br.readU32();

  assert(br.readU8() === 0, 'Non-zero marker.');

  flag = br.readU8();

  assert(flag !== 0, 'Flag byte is zero.');

  this.flag = flag;

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.inputs.push(Input.fromReader(br));

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.outputs.push(Output.fromReader(br));

  if (flag & 1) {
    flag ^= 1;

    br.start();

    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];
      input.witness.fromReader(br);
      if (input.witness.items.length > 0)
        hasWitness = true;
    }

    witnessSize = br.end() + 2;
  }

  if (flag !== 0)
    throw new Error('Unknown witness flag.');

  // We'll never be able to reserialize
  // this to get the regular txid, and
  // there's no way it's valid anyway.
  if (this.inputs.length === 0 && this.outputs.length !== 0)
    throw new Error('Zero input witness tx.');

  this.locktime = br.readU32();

  if (!this.mutable && hasWitness) {
    this._raw = br.endData();
    this._size = this._raw.length;
    this._witnessSize = witnessSize;
  } else {
    br.end();
  }

  return this;
};

/**
 * Serialize transaction without witness.
 * @private
 * @returns {RawTX}
 */

TX.prototype.frameNormal = function frameNormal() {
  var bw = new BufferWriter();
  var raw = this.frameNormalWriter(bw);
  raw.data = bw.render();
  return raw;
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `witness`).
 * @private
 * @returns {RawTX}
 */

TX.prototype.frameWitness = function frameWitness() {
  var bw = new BufferWriter();
  var raw = this.frameWitnessWriter(bw);
  raw.data = bw.render();
  return raw;
};

/**
 * Serialize transaction without witness.
 * @private
 * @param {BufferWriter} writer
 * @returns {RawTX}
 */

TX.prototype.frameNormalWriter = function frameNormalWriter(bw) {
  var offset = bw.written;
  var i, input, output;

  if (this.inputs.length === 0 && this.outputs.length !== 0)
    throw new Error('Cannot serialize zero-input tx.');

  bw.writeU32(this.version);

  bw.writeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.toWriter(bw);
  }

  bw.writeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    output.toWriter(bw);
  }

  bw.writeU32(this.locktime);

  return new RawTX(bw.written - offset, 0);
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `witness`).
 * @private
 * @param {BufferWriter} bw
 * @returns {RawTX}
 */

TX.prototype.frameWitnessWriter = function frameWitnessWriter(bw) {
  var offset = bw.written;
  var witnessSize = 0;
  var i, start, input, output;

  if (this.inputs.length === 0 && this.outputs.length !== 0)
    throw new Error('Cannot serialize zero-input tx.');

  bw.writeU32(this.version);
  bw.writeU8(0);
  bw.writeU8(this.flag);

  bw.writeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.toWriter(bw);
  }

  bw.writeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    output.toWriter(bw);
  }

  start = bw.written;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.witness.toWriter(bw);
  }

  witnessSize += bw.written - start;

  bw.writeU32(this.locktime);

  if (witnessSize === this.inputs.length)
    throw new Error('Cannot serialize empty-witness tx.');

  return new RawTX(bw.written - offset, witnessSize + 2);
};

/**
 * Test whether data is a witness transaction.
 * @param {Buffer|BufferReader} data
 * @returns {Boolean}
 */

TX.isWitness = function isWitness(br) {
  if (br.left() < 6)
    return false;

  return br.data[br.offset + 4] === 0
    && br.data[br.offset + 5] !== 0;
};

/**
 * Test whether an object is a TX.
 * @param {Object} obj
 * @returns {Boolean}
 */

TX.isTX = function isTX(obj) {
  return obj
    && Array.isArray(obj.inputs)
    && typeof obj.locktime === 'number'
    && typeof obj.witnessHash === 'function';
};

/*
 * Helpers
 */

function RawTX(total, witness) {
  this.data = null;
  this.total = total;
  this.witness = witness;
}

/*
 * Expose
 */

module.exports = TX;

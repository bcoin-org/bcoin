/*!
 * tx.js - transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var crypto = require('../crypto/crypto');
var btcutils = require('../btc/utils');
var Amount = require('../btc/amount');
var constants = require('../protocol/constants');
var Network = require('../protocol/network');
var Script = require('../script/script');
var Stack = require('../script/stack');
var BufferWriter = require('../utils/writer');
var VerifyResult = require('../btc/errors').VerifyResult;
var Input = require('./input');
var Output = require('./output');
var Outpoint = require('./outpoint');
var Coin = require('./coin');
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
 * @property {Number} ts - Timestamp of the block the transaction
 * was included in (unix time).
 * @property {Hash|null} block - Hash of the block the transaction
 * was included in.
 * @property {Number} index - Transaction's index in the block tx vector.
 * @property {Number} ps - "Pending Since": The time at which the transaction
 * was first seen. Only non-zero on unconfirmed transactions.
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

function TX(options) {
  if (!(this instanceof TX))
    return new TX(options);

  this.version = 1;
  this.flag = 1;
  this.inputs = [];
  this.outputs = [];
  this.locktime = 0;

  this.ts = 0;
  this.block = null;
  this.index = -1;
  this.ps = util.now();
  this.height = -1;
  this.mutable = false;

  this._hash = null;
  this._hhash = null;
  this._whash = null;

  this._raw = null;
  this._size = -1;
  this._witnessSize = -1;
  this._lastWitnessSize = 0;

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

  if (options.ts != null)
    assert(util.isNumber(options.locktime));
    this.ts = options.ts;

  if (options.block !== undefined) {
    assert(options.block === null || typeof options.block === 'string');
    this.block = options.block;
  }

  if (options.index != null) {
    assert(util.isNumber(options.index));
    this.index = options.index;
  }

  if (options.ps != null) {
    assert(util.isNumber(options.ps));
    this.ps = options.ps;
  }

  if (options.height != null) {
    assert(util.isNumber(options.height));
    this.height = options.height;
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
 * Set the block the transaction was included in.
 * @param {Block|MerkleBlock} block
 * @param {Number} index
 */

TX.prototype.setBlock = function setBlock(block, index) {
  this.ts = block.ts;
  this.block = block.hash('hex');
  this.height = block.height;
  this.index = index == null ? -1 : index;
};

/**
 * Remove all relevant block data from the transaction.
 */

TX.prototype.unsetBlock = function unsetBlock() {
  this.ts = 0;
  this.block = null;
  this.height = -1;
  this.index = -1;
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

  if (this.isCoinbase()) {
    return enc === 'hex'
      ? constants.NULL_HASH
      : util.copy(constants.ZERO_HASH);
  }

  if (!this.hasWitness())
    return this.hash(enc);

  if (!hash) {
    hash = crypto.hash256(this.toWitness());
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

TX.prototype.toRaw = function toRaw(writer) {
  var raw = this.getRaw();
  if (writer) {
    writer.writeBytes(raw);
    return writer;
  }
  return raw;
};

/**
 * Serialize the transaction without the
 * witness vector, regardless of whether it
 * is a witness transaction or not.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.toNormal = function toNormal(writer) {
  var raw = this.getRaw();
  if (!TX.isWitness(raw)) {
    if (writer) {
      writer.writeBytes(raw);
      return writer;
    }
    return raw;
  }
  return this.frameNormal(writer);
};

/**
 * Serialize the transaction with the
 * witness vector. Will use normal
 * serialization if witness vector is empty.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.toWitness = function toWitness(writer) {
  return this.toRaw(writer);
};

/**
 * Serialize the transaction. Note
 * that this is cached. This will use
 * the witness serialization if a
 * witness is present.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.getRaw = function getRaw() {
  var raw;

  if (this._raw) {
    assert(this._size > 0);
    assert(this._witnessSize >= 0);
    this._lastWitnessSize = this._witnessSize;
    return this._raw;
  }

  if (this.hasWitness())
    raw = this.frameWitness();
  else
    raw = this.frameNormal();

  if (!this.mutable) {
    this._raw = raw;
    this._size = raw.length;
    this._witnessSize = this._lastWitnessSize;
  }

  return raw;
};

/**
 * Calculate real size and size of the witness bytes.
 * @returns {Object} Contains `size` and `witnessSize`.
 */

TX.prototype.getSizes = function getSizes() {
  var sizes = new TXSizes();
  var writer;

  if (this.mutable) {
    assert(!this._raw);
    writer = new BufferWriter();
    this.toRaw(writer);
    sizes.total = writer.written;
    sizes.witness = this._lastWitnessSize;
    return sizes;
  }

  this.getRaw();

  sizes.total = this._size;
  sizes.witness = this._witnessSize;

  return sizes;
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
  var sizes = this.getSizes();
  var base = sizes.total - sizes.witness;
  return base * (constants.WITNESS_SCALE_FACTOR - 1) + sizes.total;
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
  var sizes = this.getSizes();
  return sizes.total - sizes.witness;
};

/**
 * Test whether the transaction has a non-empty witness.
 * @returns {Boolean}
 */

TX.prototype.hasWitness = function hasWitness() {
  var i;

  if (this._witnessSize !== -1)
    return this._witnessSize !== 0;

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].witness.items.length > 0)
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

TX.prototype.signatureHash = function signatureHash(index, prev, type, version) {
  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  assert(index >= 0 && index < this.inputs.length);
  assert(prev instanceof Script);

  // Traditional sighashing
  if (version === 0)
    return this.signatureHashV0(index, prev, type);

  // Segwit sighashing
  if (version === 1)
    return this.signatureHashV1(index, prev, type);

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
    bw.writeHash(input.prevout.hash);
    bw.writeU32(input.prevout.index);

    // Replace script with previous
    // output script if current index.
    bw.writeVarBytes(prev.toRaw());
    bw.writeU32(input.sequence);
  } else {
    bw.writeVarint(this.inputs.length);
    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];

      // Outpoint.
      bw.writeHash(input.prevout.hash);
      bw.writeU32(input.prevout.index);

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

TX.prototype.signatureHashV1 = function signatureHashV1(index, prev, type) {
  var i, bw, input, output, prevouts, sequences, outputs;

  if (!(type & constants.hashType.ANYONECANPAY)) {
    if (this._hashPrevouts) {
      prevouts = this._hashPrevouts;
    } else {
      bw = new BufferWriter();

      for (i = 0; i < this.inputs.length; i++) {
        input = this.inputs[i];
        input.prevout.toRaw(bw);
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
        output.toRaw(bw);
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
  bw.write64(input.coin.value);
  bw.writeU32(input.sequence);
  bw.writeBytes(outputs);
  bw.writeU32(this.locktime);
  bw.writeU32(type);

  return crypto.hash256(bw.render());
};

/**
 * Verify all transaction inputs.
 * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the inputs are valid.
 */

TX.prototype.verify = function verify(flags) {
  var i;

  if (this.inputs.length === 0)
    return false;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    if (!this.verifyInput(i, flags))
      return false;
  }

  return true;
};

/**
 * Verify a transaction input.
 * @param {Number} index - Index of output being
 * verified.
 * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the input is valid.
 */

TX.prototype.verifyInput = function verifyInput(index, flags) {
  var input;

  if (typeof index === 'object')
    index = this.inputs.indexOf(index);

  input = this.inputs[index];

  assert(input, 'Input does not exist.');

  if (!input.coin)
    return false;

  try {
    Script.verify(
      input.script,
      input.witness,
      input.coin.script,
      this,
      index,
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
 * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Promise}
 * @returns {Boolean} Whether the inputs are valid.
 */

TX.prototype.verifyAsync = function verifyAsync(flags) {
  if (this.inputs.length === 0)
    return Promise.resolve(false);

  if (this.isCoinbase())
    return Promise.resolve(true);

  return workerPool.verify(this, flags);
};

/**
 * Verify a transaction input asynchronously.
 * @param {Number} index - Index of output being
 * verified.
 * @param {VerifyFlags} [flags=STANDARD_VERIFY_FLAGS]
 * @returns {Boolean} Whether the input is valid.
 */

TX.prototype.verifyInputAsync = function verifyInputAsync(index, flags) {
  var input;

  if (typeof index === 'object')
    index = this.inputs.indexOf(index);

  input = this.inputs[index];

  assert(input, 'Input does not exist.');

  return workerPool.verifyInput(this, index, flags);
};

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
 * @returns {Amount} fee (zero if not all coins are available).
 */

TX.prototype.getFee = function getFee() {
  if (!this.hasCoins())
    return 0;

  return this.getInputValue() - this.getOutputValue();
};

/**
 * Calculate the total input value.
 * @returns {Amount} value
 */

TX.prototype.getInputValue = function getInputValue() {
  var total = 0;
  var i;

  if (this._inputValue !== -1)
    return this._inputValue;

  if (!this.hasCoins())
    return total;

  for (i = 0; i < this.inputs.length; i++)
    total += this.inputs[i].coin.value;

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
  var i;

  if (this._outputValue !== -1)
    return this._outputValue;

  for (i = 0; i < this.outputs.length; i++)
    total += this.outputs[i].value;

  if (!this.mutable)
    this._outputValue = total;

  return total;
};

/**
 * Get all input addresses.
 * @private
 * @returns {Array}
 */

TX.prototype._getInputAddresses = function getInputAddresses() {
  var table = {};
  var addrs = [];
  var i, address, hash;

  if (this.isCoinbase())
    return [addrs, table];

  for (i = 0; i < this.inputs.length; i++) {
    address = this.inputs[i].getAddress();

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
  var i, address, hash;

  for (i = 0; i < this.outputs.length; i++) {
    address = this.outputs[i].getAddress();

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
 * @returns {Array}
 */

TX.prototype._getAddresses = function getAddresses() {
  var inputs = this._getInputAddresses();
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
 * @returns {Address[]} addresses
 */

TX.prototype.getInputAddresses = function getInputAddresses() {
  return this._getInputAddresses()[0];
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
 * @returns {Address[]} addresses
 */

TX.prototype.getAddresses = function getAddresses() {
  return this._getAddresses()[0];
};

/**
 * Get all input address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getInputHashes = function getInputHashes(enc) {
  var i, input, table;

  if (enc === 'hex') {
    table = this._getInputAddresses()[1];
    return Object.keys(table);
  }

  input = this.getInputAddresses();

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
 * @returns {Hash[]} hashes
 */

TX.prototype.getHashes = function getHashes(enc) {
  var i, hashes, table;

  if (enc === 'hex') {
    table = this._getAddresses()[1];
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
 * @returns {Boolean}
 */

TX.prototype.hasCoins = function hasCoins() {
  var i;

  if (this.inputs.length === 0)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    if (!this.inputs[i].coin)
      return false;
  }

  return true;
};

/**
 * Attempt to connect coins to prevouts.
 * @param {Coin|TX|Coin[]|TX[]} coins
 * @returns {Boolean} Whether the transaction is now completely filled.
 */

TX.prototype.fillCoins = function fillCoins(coins) {
  var result = true;
  var i, input, hash, index, map, tx, coin;

  if ((coins instanceof Coin)
      || (coins instanceof TX)) {
    coins = [coins];
  }

  if (Array.isArray(coins)) {
    map = {};
    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      if (coin instanceof TX)
        map[coin.hash('hex')] = coin;
      else if (coin instanceof Coin)
        map[coin.hash + coin.index] = coin;
      else
        assert(false, 'Non-coin object passed to fillCoins.');
    }
    coins = map;
  }

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    hash = input.prevout.hash;
    index = input.prevout.index;

    if (input.coin)
      continue;

    tx = coins[hash];

    if (tx) {
      if (index < tx.outputs.length) {
        input.coin = Coin.fromTX(tx, index);
        continue;
      }
      result = false;
      continue;
    }

    coin = coins[hash + index];

    if (coin) {
      input.coin = coin;
      continue;
    }

    result = false;
  }

  return result;
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
  var i;

  if (this.locktime === 0)
    return true;

  if (this.locktime < (this.locktime < threshold ? height : ts))
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].sequence !== 0xffffffff)
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
  var i;

  for (i = 0; i < this.inputs.length; i++)
    total += this.inputs[i].script.getSigops(false);

  for (i = 0; i < this.outputs.length; i++)
    total += this.outputs[i].script.getSigops(false);

  return total;
};

/**
 * Calculate accurate sigop count, taking into account redeem scripts.
 * @returns {Number} sigop count
 */

TX.prototype.getScripthashSigops = function getScripthashSigops() {
  var total = 0;
  var i, input;

  if (this.isCoinbase())
    return 0;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    if (input.coin.script.isScripthash())
      total += input.coin.script.getScripthashSigops(input.script);
  }

  return total;
};

/**
 * Calculate sigops weight, taking into account witness programs.
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop weight
 */

TX.prototype.getSigopsWeight = function getSigopsWeight(flags) {
  var weight = this.getLegacySigops() * constants.WITNESS_SCALE_FACTOR;
  var input, i;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return weight;

  if (flags & constants.flags.VERIFY_P2SH)
    weight += this.getScripthashSigops() * constants.WITNESS_SCALE_FACTOR;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    weight += Script.getWitnessSigops(
      input.script,
      input.coin.script,
      input.witness,
      flags);
  }

  return weight;
};

/**
 * Calculate virtual sigop count.
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop count
 */

TX.prototype.getSigops = function getSigops(flags) {
  var scale = constants.WITNESS_SCALE_FACTOR;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  return (this.getSigopsWeight(flags) + scale - 1) / scale | 0;
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
    key = input.prevout.hash + input.prevout.index;
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
 * @param {VerifyFlags?} flags
 * @returns {Boolean}
 */

TX.prototype.hasStandardInputs = function hasStandardInputs() {
  var maxSigops = constants.script.MAX_SCRIPTHASH_SIGOPS;
  var VERIFY_NONE = constants.flags.VERIFY_NONE;
  var i, input, stack, redeem;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      return false;

    if (input.coin.script.isUnknown())
      return false;

    if (input.coin.script.isScripthash()) {
      stack = new Stack();

      try {
        input.script.execute(stack, VERIFY_NONE, this, i, 0);
      } catch (e) {
        return false;
      }

      if (stack.length === 0)
        return false;

      redeem = Script.fromRaw(stack.top(-1));

      if (redeem.getSigops(true) > maxSigops)
        return false;
    }
  }

  return true;
};

/**
 * Perform contextual checks to verify coin and witness standardness.
 * @see IsBadWitness()
 * @returns {Boolean}
 */

TX.prototype.hasStandardWitness = function hasStandardWitness(ret) {
  var result;

  if (!ret)
    ret = new VerifyResult();

  result = this.getWitnessStandard();

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
 * @returns {Boolean}
 */

TX.prototype.getWitnessStandard = function getWitnessStandard() {
  var ret = BAD_OKAY;
  var i, j, input, prev, hash, redeem, m, n;

  if (!this.hasWitness())
    return ret;

  if (this.isCoinbase())
    return ret;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    if (input.witness.length === 0)
      continue;

    prev = input.coin.script;

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
 * @param {Number} spendHeight - Height at which the
 * transaction is being spent. In the mempool this is
 * the chain height plus one at the time it entered the pool.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

TX.prototype.checkInputs = function checkInputs(spendHeight, ret) {
  var total = 0;
  var i, input, coin, fee, value;

  if (!ret)
    ret = new VerifyResult();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = input.coin;

    if (!coin) {
      // Note: don't trigger dos score here.
      ret.reason = 'bad-txns-inputs-missingorspent';
      ret.score = 0;
      return false;
    }

    if (coin.coinbase && spendHeight != null) {
      if (spendHeight - coin.height < constants.tx.COINBASE_MATURITY) {
        ret.reason = 'bad-txns-premature-spend-of-coinbase';
        ret.score = 0;
        return false;
      }
    }

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
 * Estimate the max possible size of transaction once the
 * inputs are scripted. If the transaction is non-mutable,
 * this will just return the virtual size.
 * @returns {Number} size
 */

TX.prototype.maxSize = function maxSize() {
  return this.getVirtualSize();
};

/**
 * Calculate the modified size of the transaction. This
 * is used in the mempool for calculating priority.
 * @param {Number?} size - The size to modify. If not present,
 * virtual size will be used.
 * @returns {Number} Modified size.
 */

TX.prototype.getModifiedSize = function getModifiedSize(size) {
  var i, offset;

  if (size == null)
    size = this.maxSize();

  for (i = 0; i < this.inputs.length; i++) {
    offset = 41 + Math.min(110, this.inputs[i].script.getSize());
    if (size > offset)
      size -= offset;
  }

  return size;
};

/**
 * Calculate the transaction priority.
 * @param {Number?} height - If not present, tx height
 * or network height will be used.
 * @param {Number?} size - Size to calculate priority
 * based on. If not present, virtual size will be used.
 * @returns {Number}
 */

TX.prototype.getPriority = function getPriority(height, size) {
  var sum = 0;
  var i, input, age;

  assert(typeof height === 'number', 'Must pass in height.');

  if (this.isCoinbase())
    return sum;

  if (size == null)
    size = this.maxSize();

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    if (input.coin.height === -1)
      continue;

    if (input.coin.height <= height) {
      age = height - input.coin.height;
      sum += input.coin.value * age;
    }
  }

  return Math.floor(sum / size);
};

/**
 * Calculate the transaction's on-chain value.
 * @param {Number?} height
 * @returns {Number}
 */

TX.prototype.getChainValue = function getChainValue(height) {
  var value = 0;
  var i, input;

  if (this.isCoinbase())
    return value;

  if (height == null)
    height = Infinity;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    if (input.coin.height === -1)
      continue;

    if (input.coin.height <= height)
      value += input.coin.value;
  }

  return value;
};

/**
 * Determine whether the transaction is above the
 * free threshold in priority. A transaction which
 * passed this test is most likely relayable
 * without a fee.
 * @param {Number?} height - If not present, tx
 * height or network height will be used.
 * @param {Number?} size - If not present, modified
 * size will be calculated and used.
 * @returns {Boolean}
 */

TX.prototype.isFree = function isFree(height, size) {
  var priority = this.getPriority(height, size);
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
    size = this.maxSize();

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
    size = this.maxSize();

  return btcutils.getRoundFee(size, rate);
};

/**
 * Calculate the transaction's rate based on size
 * and fees. Size will be calculated if not present.
 * @param {Number?} size
 * @returns {Rate}
 */

TX.prototype.getRate = function getRate(size) {
  if (size == null)
    size = this.maxSize();

  return btcutils.getRate(size, this.getFee());
};

/**
 * Calculate current number of transaction confirmations.
 * @param {Number?} height - Current chain height. If not
 * present, network chain height will be used.
 * @returns {Number} confirmations
 */

TX.prototype.getConfirmations = function getConfirmations(height) {
  assert(typeof height === 'number', 'Must pass in height.');

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 0;

  return height - this.height + 1;
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

  if (!filter)
    return false;

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

TX.prototype.__defineGetter__('rblock', function() {
  return this.block
    ? util.revHex(this.block)
    : null;
});

TX.prototype.__defineGetter__('rhash', function() {
  return util.revHex(this.hash('hex'));
});

TX.prototype.__defineGetter__('rwhash', function() {
  return util.revHex(this.witnessHash('hex'));
});

TX.prototype.__defineGetter__('txid', function() {
  return this.rhash;
});

TX.prototype.__defineGetter__('wtxid', function() {
  return this.rwhash;
});

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
  var rate = this.getRate();

  // Rate can exceed 53 bits in testing.
  if (!util.isSafeInteger(rate))
    rate = 0;

  return {
    hash: this.rhash,
    witnessHash: this.rwhash,
    size: this.getSize(),
    virtualSize: this.maxSize(),
    height: this.height,
    value: Amount.btc(this.getOutputValue()),
    fee: Amount.btc(this.getFee()),
    minFee: Amount.btc(this.getMinFee()),
    rate: Amount.btc(rate),
    date: util.date(this.ts || this.ps),
    block: this.block ? util.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    version: this.version,
    flag: this.flag,
    inputs: this.inputs,
    outputs: this.outputs,
    locktime: this.locktime
  };
};

/**
 * Convert the transaction to an object suitable
 * for JSON serialization. Note that the hashes
 * will be reversed to abide by bitcoind's legacy
 * of little-endian uint256s.
 * @returns {Object}
 */

TX.prototype.toJSON = function toJSON(network) {
  var rate = this.getRate();

  // Rate can exceed 53 bits in testing.
  if (!util.isSafeInteger(rate))
    rate = 0;

  network = Network.get(network);

  return {
    hash: util.revHex(this.hash('hex')),
    witnessHash: util.revHex(this.witnessHash('hex')),
    height: this.height,
    block: this.block ? util.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    date: util.date(this.ts || this.ps),
    index: this.index,
    fee: Amount.btc(this.getFee()),
    rate: Amount.btc(rate),
    version: this.version,
    flag: this.flag,
    inputs: this.inputs.map(function(input) {
      return input.toJSON(network);
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON(network);
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
  assert.equal(json.type, 'tx');
  assert(util.isNumber(json.version));
  assert(util.isNumber(json.flag));
  assert(Array.isArray(json.inputs));
  assert(Array.isArray(json.outputs));
  assert(util.isNumber(json.locktime));
  assert(!json.block || typeof json.block === 'string');
  assert(util.isNumber(json.height));
  assert(util.isNumber(json.ts));
  assert(util.isNumber(json.ps));
  assert(util.isNumber(json.index));

  this.block = json.block ? util.revHex(json.block) : null;
  this.height = json.height;
  this.ts = json.ts;
  this.ps = json.ps;
  this.index = json.index;

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
 * Inject properties from serialized data.
 * @private
 * @param {Buffer|BufferReader} data
 */

TX.prototype.fromRaw = function fromRaw(data) {
  var br, i, count;

  if (TX.isWitness(data))
    return this.fromWitness(data);

  br = BufferReader(data);
  br.start();

  this.version = br.readU32(); // Technically signed

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.inputs.push(Input.fromRaw(br));

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.outputs.push(Output.fromRaw(br));

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
 * data (witness serialization).
 * @private
 * @param {Buffer|BufferReader} data
 */

TX.prototype.fromWitness = function fromWitness(data) {
  var br = BufferReader(data);
  var flag = 0;
  var witnessSize = 0;
  var hasWitness = false;
  var i, count, input;

  br.start();

  this.version = br.readU32(); // Technically signed

  assert(br.readU8() === 0, 'Non-zero marker.');

  flag = br.readU8();

  assert(flag !== 0, 'Flag byte is zero.');

  this.flag = flag;

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.inputs.push(Input.fromRaw(br));

  count = br.readVarint();

  for (i = 0; i < count; i++)
    this.outputs.push(Output.fromRaw(br));

  if (flag & 1) {
    flag ^= 1;

    br.start();

    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];
      input.witness.fromRaw(br);
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
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

TX.prototype.frameNormal = function frameNormal(writer) {
  var bw = BufferWriter(writer);
  var i;

  if (this.inputs.length === 0 && this.outputs.length !== 0)
    throw new Error('Cannot serialize zero-input tx.');

  bw.writeU32(this.version);

  bw.writeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].toRaw(bw);

  bw.writeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++)
    this.outputs[i].toRaw(bw);

  bw.writeU32(this.locktime);

  if (!writer)
    bw = bw.render();

  this._lastWitnessSize = 0;

  return bw;
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `_witnessSize`).
 * @private
 * @param {BufferWriter?} writer - A buffer writer to continue writing from.
 * @returns {Buffer} Returns a BufferWriter if `writer` was passed in.
 */

TX.prototype.frameWitness = function frameWitness(writer) {
  var bw = BufferWriter(writer);
  var witnessSize = 0;
  var i, start;

  if (this.inputs.length === 0 && this.outputs.length !== 0)
    throw new Error('Cannot serialize zero-input tx.');

  bw.writeU32(this.version);
  bw.writeU8(0);
  bw.writeU8(this.flag);

  bw.writeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].toRaw(bw);

  bw.writeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++)
    this.outputs[i].toRaw(bw);

  start = bw.written;

  for (i = 0; i < this.inputs.length; i++)
    this.inputs[i].witness.toRaw(bw);

  witnessSize += bw.written - start;

  bw.writeU32(this.locktime);

  if (witnessSize === this.inputs.length)
    throw new Error('Cannot serialize empty-witness tx.');

  this._lastWitnessSize = witnessSize + 2;

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Test whether data is a witness transaction.
 * @param {Buffer|BufferReader} data
 * @returns {Boolean}
 */

TX.isWitness = function isWitness(data) {
  if (Buffer.isBuffer(data)) {
    if (data.length < 6)
      return false;

    return data[4] === 0 && data[5] !== 0;
  }

  if (data.left() < 6)
    return false;

  return data.data[data.offset + 4] === 0
    && data.data[data.offset + 5] !== 0;
};

/**
 * Serialize a transaction to BCoin "extended format".
 * This is the serialization format BCoin uses internally
 * to store transactions in the database. The extended
 * serialization includes the height, block hash, index,
 * timestamp, pending-since time, and optionally a vector
 * for the serialized coins.
 * @param {Boolean?} saveCoins - Whether to serialize the coins.
 * @returns {Buffer}
 */

TX.prototype.toExtended = function toExtended(saveCoins, writer) {
  var bw = BufferWriter(writer);
  var height = this.height;
  var index = this.index;
  var i, input, field, bit, oct;

  this.toRaw(bw);

  bw.writeU32(this.ps);

  if (this.block) {
    bw.writeU8(1);
    bw.writeHash(this.block);
  } else {
    bw.writeU8(0);
  }

  if (height === -1)
    height = 0x7fffffff;

  if (index === -1)
    index = 0x7fffffff;

  bw.writeU32(height);
  bw.writeU32(this.ts);
  bw.writeU32(index);

  if (saveCoins) {
    field = new Buffer(Math.ceil(this.inputs.length / 8));
    field.fill(0);

    bw.writeBytes(field);

    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];

      if (!input.coin) {
        bit = i % 8;
        oct = (i - bit) / 8;
        field[oct] |= 1 << (7 - bit);
        continue;
      }

      input.coin.toRaw(bw);
    }
  }

  if (!writer)
    bw = bw.render();

  return bw;
};

/**
 * Inject properties from "extended" serialization format.
 * @param {Buffer} data
 * @param {Boolean?} saveCoins - If true, the function will
 * attempt to parse the coins.
 */

TX.prototype.fromExtended = function fromExtended(data, saveCoins) {
  var br = BufferReader(data);
  var i, input, coin, field, bit, oct, spent;

  this.fromRaw(br);

  this.ps = br.readU32();

  if (br.readU8() === 1)
    this.block = br.readHash('hex');

  this.height = br.readU32();
  this.ts = br.readU32();
  this.index = br.readU32();

  if (this.height === 0x7fffffff)
    this.height = -1;

  if (this.index === 0x7fffffff)
    this.index = -1;

  if (saveCoins) {
    field = br.readBytes(Math.ceil(this.inputs.length / 8), true);

    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];

      bit = i % 8;
      oct = (i - bit) / 8;
      spent = (field[oct] >>> (7 - bit)) & 1;

      if (spent)
        continue;

      coin = Coin.fromRaw(br);
      coin.hash = input.prevout.hash;
      coin.index = input.prevout.index;

      input.coin = coin;
    }
  }

  return this;
};

/**
 * Instantiate a transaction from a Buffer
 * in "extended" serialization format.
 * @param {Buffer} data
 * @param {Boolean?} saveCoins - If true, the function will
 * attempt to parse the coins.
 * @param {String?} enc - One of `"hex"` or `null`.
 * @returns {TX}
 */

TX.fromExtended = function fromExtended(data, saveCoins, enc) {
  if (typeof saveCoins === 'string') {
    enc = saveCoins;
    saveCoins = false;
  }

  if (typeof data === 'string')
    data = new Buffer(data, enc);

  return new TX().fromExtended(data, saveCoins);
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

function TXSizes() {
  this.total = 0;
  this.witness = 0;
}

/*
 * Expose
 */

module.exports = TX;

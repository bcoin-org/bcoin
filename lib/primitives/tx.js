/*!
 * tx.js - transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var encoding = require('../utils/encoding');
var co = require('../utils/co');
var crypto = require('../crypto/crypto');
var Amount = require('../btc/amount');
var Network = require('../protocol/network');
var Script = require('../script/script');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var VerifyResult = require('../protocol/errors').VerifyResult;
var Input = require('./input');
var Output = require('./output');
var Outpoint = require('./outpoint');
var InvItem = require('./invitem');
var workerPool = require('../workers/workerpool').pool;
var Bloom = require('../utils/bloom');
var consensus = require('../protocol/consensus');
var policy = require('../protocol/policy');

/**
 * A static transaction object.
 * @alias module:primitives.TX
 * @constructor
 * @param {Object} options - Transaction fields.
 * @property {Number} version - Transaction version. Note that Bcoin reads
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
  this._witness = -1;

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
    assert(util.isUInt32(options.version), 'Version must be a uint32.');
    this.version = options.version;
  }

  if (options.flag != null) {
    assert(util.isUInt8(options.flag), 'Flag must be a uint8.');
    this.flag = options.flag;
  }

  if (options.inputs) {
    assert(Array.isArray(options.inputs), 'Inputs must be an array.');
    for (i = 0; i < options.inputs.length; i++)
      this.inputs.push(new Input(options.inputs[i]));
  }

  if (options.outputs) {
    assert(Array.isArray(options.outputs), 'Outputs must be an array.');
    for (i = 0; i < options.outputs.length; i++)
      this.outputs.push(new Output(options.outputs[i]));
  }

  if (options.locktime != null) {
    assert(util.isUInt32(options.locktime), 'Locktime must be a uint32.');
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
  return new TX().inject(this);
};

/**
 * Inject properties from tx.
 * Used for cloning.
 * @private
 * @param {TX} tx
 * @returns {TX}
 */

TX.prototype.inject = function inject(tx) {
  var i, input, output;

  this.version = tx.version;
  this.flag = tx.flag;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    this.inputs.push(input.clone());
  }

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];
    this.outputs.push(output.clone());
  }

  this.locktime = tx.locktime;

  return this;
};

/**
 * Clear any cached values.
 */

TX.prototype.refresh = function refresh() {
  this._hash = null;
  this._hhash = null;
  this._whash = null;

  this._raw = null;
  this._size = -1;
  this._witness = -1;

  this._hashPrevouts = null;
  this._hashSequence = null;
  this._hashOutputs = null;
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
  return this.frame().data;
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
  if (this.mutable) {
    if (this.hasWitness())
      return this.writeWitness(bw);
    return this.writeNormal(bw);
  }

  bw.writeBytes(this.toRaw());

  return bw;
};

/**
 * Write the transaction to a buffer writer.
 * Uses non-witness serialization.
 * @param {BufferWriter} bw
 */

TX.prototype.toNormalWriter = function toNormalWriter(bw) {
  if (this.hasWitness()) {
    this.writeNormal(bw);
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

TX.prototype.frame = function frame() {
  var raw;

  if (this.mutable) {
    assert(!this._raw);
    if (this.hasWitness())
      return this.frameWitness();
    return this.frameNormal();
  }

  if (this._raw) {
    assert(this._size > 0);
    assert(this._witness >= 0);
    raw = new RawTX(this._size, this._witness);
    raw.data = this._raw;
    return raw;
  }

  if (this.hasWitness())
    raw = this.frameWitness();
  else
    raw = this.frameNormal();

  this._raw = raw.data;
  this._size = raw.total;
  this._witness = raw.witness;

  return raw;
};

/**
 * Calculate total size and size of the witness bytes.
 * @returns {Object} Contains `total` and `witness`.
 */

TX.prototype.getSizes = function getSizes() {
  if (this.mutable) {
    if (this.hasWitness())
      return this.getWitnessSizes();
    return this.getNormalSizes();
  }
  return this.frame();
};

/**
 * Calculate the virtual size of the transaction.
 * Note that this is cached.
 * @returns {Number} vsize
 */

TX.prototype.getVirtualSize = function getVirtualSize() {
  var scale = consensus.WITNESS_SCALE_FACTOR;
  return (this.getWeight() + scale - 1) / scale | 0;
};

/**
 * Calculate the virtual size of the transaction
 * (weighted against bytes per sigop cost).
 * @param {Number} sigops - Sigops cost.
 * @returns {Number} vsize
 */

TX.prototype.getSigopsSize = function getSigopsSize(sigops) {
  var scale = consensus.WITNESS_SCALE_FACTOR;
  var bytes = policy.BYTES_PER_SIGOP;
  var weight = Math.max(this.getWeight(), sigops * bytes);
  return (weight + scale - 1) / scale | 0;
};

/**
 * Calculate the weight of the transaction.
 * Note that this is cached.
 * @returns {Number} weight
 */

TX.prototype.getWeight = function getWeight() {
  var raw = this.getSizes();
  var base = raw.total - raw.witness;
  return base * (consensus.WITNESS_SCALE_FACTOR - 1) + raw.total;
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

  if (this._witness !== -1)
    return this._witness !== 0;

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
 * @param {Amount} value - Previous output value.
 * @param {SighashType} type - Sighash type.
 * @param {Number} version - Sighash version (0=legacy, 1=segwit).
 * @returns {Buffer} Signature hash.
 */

TX.prototype.signatureHash = function signatureHash(index, prev, value, type, version) {
  if (typeof type === 'string') {
    type = Script.hashType[type.toUpperCase()];
    assert(type != null, 'Unknown sighash type.');
  }

  assert(index >= 0 && index < this.inputs.length);
  assert(prev instanceof Script);
  assert(typeof value === 'number');
  assert(typeof type === 'number');

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
  var i, size, bw, input, output;
  var hashType = type & 0x1f;

  if (hashType === Script.hashType.SINGLE) {
    // Bitcoind used to return 1 as an error code:
    // it ended up being treated like a hash.
    if (index >= this.outputs.length)
      return util.copy(encoding.ONE_HASH);
  }

  // Remove all code separators.
  prev = prev.removeSeparators();

  // Calculate buffer size.
  size = this.hashSize(index, prev, type);

  bw = new StaticWriter(size);

  bw.writeU32(this.version);

  // Serialize inputs.
  if (type & Script.hashType.ANYONECANPAY) {
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
      switch (hashType) {
        case Script.hashType.NONE:
        case Script.hashType.SINGLE:
          bw.writeU32(0);
          break;
        default:
          bw.writeU32(input.sequence);
          break;
      }
    }
  }

  // Serialize outputs.
  switch (hashType) {
    case Script.hashType.NONE:
      // No outputs if NONE.
      bw.writeVarint(0);
      break;
    case Script.hashType.SINGLE:
      // Drop all outputs after the
      // current input index if SINGLE.
      bw.writeVarint(index + 1);

      for (i = 0; i < index; i++) {
        // Null all outputs not at
        // current input index.
        bw.write64(-1);
        bw.writeVarint(0);
      }

      // Regular serialization
      // at current input index.
      output = this.outputs[index];
      output.toWriter(bw);

      break;
    default:
      // Regular output serialization if ALL.
      bw.writeVarint(this.outputs.length);
      for (i = 0; i < this.outputs.length; i++) {
        output = this.outputs[i];
        output.toWriter(bw);
      }
      break;
  }

  bw.writeU32(this.locktime);

  // Append the hash type.
  bw.writeU32(type);

  return crypto.hash256(bw.render());
};

/**
 * Calculate sighash size.
 * @private
 * @param {Number} index
 * @param {Script} prev
 * @param {Number} type
 * @returns {Number}
 */

TX.prototype.hashSize = function hashSize(index, prev, type) {
  var size = 0;
  var i, output;

  size += 4;

  if (type & Script.hashType.ANYONECANPAY) {
    size += 1;
    size += 36;
    size += prev.getVarSize();
    size += 4;
  } else {
    size += encoding.sizeVarint(this.inputs.length);
    size += 41 * (this.inputs.length - 1);
    size += 36;
    size += prev.getVarSize();
    size += 4;
  }

  switch (type & 0x1f) {
    case Script.hashType.NONE:
      size += 1;
      break;
    case Script.hashType.SINGLE:
      size += encoding.sizeVarint(index + 1);
      size += 9 * index;
      size += this.outputs[index].getSize();
      break;
    default:
      size += encoding.sizeVarint(this.outputs.length);
      for (i = 0; i < this.outputs.length; i++) {
        output = this.outputs[i];
        size += output.getSize();
      }
      break;
  }

  size += 8;

  return size;
};

/**
 * Witness sighashing -- O(n).
 * @private
 * @param {Number} index
 * @param {Script} prev
 * @param {Amount} value
 * @param {SighashType} type
 * @returns {Buffer}
 */

TX.prototype.signatureHashV1 = function signatureHashV1(index, prev, value, type) {
  var prevouts = encoding.ZERO_HASH;
  var sequences = encoding.ZERO_HASH;
  var outputs = encoding.ZERO_HASH;
  var i, bw, size, input, output;

  if (!(type & Script.hashType.ANYONECANPAY)) {
    if (this._hashPrevouts) {
      prevouts = this._hashPrevouts;
    } else {
      bw = new StaticWriter(this.inputs.length * 36);

      for (i = 0; i < this.inputs.length; i++) {
        input = this.inputs[i];
        input.prevout.toWriter(bw);
      }

      prevouts = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashPrevouts = prevouts;
    }
  }

  if (!(type & Script.hashType.ANYONECANPAY)
      && (type & 0x1f) !== Script.hashType.SINGLE
      && (type & 0x1f) !== Script.hashType.NONE) {
    if (this._hashSequence) {
      sequences = this._hashSequence;
    } else {
      bw = new StaticWriter(this.inputs.length * 4);

      for (i = 0; i < this.inputs.length; i++) {
        input = this.inputs[i];
        bw.writeU32(input.sequence);
      }

      sequences = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashSequence = sequences;
    }
  }

  if ((type & 0x1f) !== Script.hashType.SINGLE
      && (type & 0x1f) !== Script.hashType.NONE) {
    if (this._hashOutputs) {
      outputs = this._hashOutputs;
    } else {
      size = 0;

      for (i = 0; i < this.outputs.length; i++) {
        output = this.outputs[i];
        size += output.getSize();
      }

      bw = new StaticWriter(size);

      for (i = 0; i < this.outputs.length; i++) {
        output = this.outputs[i];
        output.toWriter(bw);
      }

      outputs = crypto.hash256(bw.render());

      if (!this.mutable)
        this._hashOutputs = outputs;
    }
  } else if ((type & 0x1f) === Script.hashType.SINGLE && index < this.outputs.length) {
    output = this.outputs[index];
    outputs = crypto.hash256(output.toRaw());
  }

  input = this.inputs[index];

  size = 156 + prev.getVarSize();
  bw = new StaticWriter(size);

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
 * @returns {Promise}
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

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      return 0;

    total += coin.value;
  }

  return total;
};

/**
 * Calculate the total output value.
 * @returns {Amount} value
 */

TX.prototype.getOutputValue = function getOutputValue() {
  var total = 0;
  var i, output;

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    total += output.value;
  }

  return total;
};

/**
 * Get all input addresses.
 * @private
 * @param {CoinView} view
 * @returns {Object}
 */

TX.prototype._getInputAddresses = function getInputAddresses(view) {
  var table = {};
  var addrs = [];
  var i, address, hash, input, coin;

  if (this.isCoinbase())
    return new AddrResult(addrs, table);

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

  return new AddrResult(addrs, table);
};

/**
 * Get all output addresses.
 * @private
 * @returns {Object}
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

  return new AddrResult(addrs, table);
};

/**
 * Get all addresses.
 * @private
 * @param {CoinView} view
 * @returns {Object}
 */

TX.prototype._getAddresses = function getAddresses(view) {
  var input = this._getInputAddresses(view);
  var output = this.getOutputAddresses();
  var addrs = input.addrs;
  var table = input.table;
  var i, address, hash;

  for (i = 0; i < output.length; i++) {
    address = output[i];
    hash = address.getHash('hex');

    if (!table[hash]) {
      table[hash] = true;
      addrs.push(address);
    }
  }

  return input;
};

/**
 * Get all input addresses.
 * @param {CoinView|null} view
 * @returns {Address[]} addresses
 */

TX.prototype.getInputAddresses = function getInputAddresses(view) {
  return this._getInputAddresses(view).addrs;
};

/**
 * Get all output addresses.
 * @returns {Address[]} addresses
 */

TX.prototype.getOutputAddresses = function getOutputAddresses() {
  return this._getOutputAddresses().addrs;
};

/**
 * Get all addresses.
 * @param {CoinView|null} view
 * @returns {Address[]} addresses
 */

TX.prototype.getAddresses = function getAddresses(view) {
  return this._getAddresses(view).addrs;
};

/**
 * Get all input address hashes.
 * @param {CoinView|null} view
 * @returns {Hash[]} hashes
 */

TX.prototype.getInputHashes = function getInputHashes(view, enc) {
  var hashes = [];
  var i, input, address;

  if (enc === 'hex') {
    input = this._getInputAddresses(view);
    return Object.keys(input.table);
  }

  input = this.getInputAddresses(view);

  for (i = 0; i < input.length; i++) {
    address = input[i];
    hashes.push(address.getHash());
  }

  return hashes;
};

/**
 * Get all output address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getOutputHashes = function getOutputHashes(enc) {
  var hashes = [];
  var i, output, address;

  if (enc === 'hex') {
    output = this._getOutputAddresses();
    return Object.keys(output.table);
  }

  output = this.getOutputAddresses();

  for (i = 0; i < output.length; i++) {
    address = output[i];
    hashes.push(address.getHash());
  }

  return hashes;
};

/**
 * Get all address hashes.
 * @param {CoinView|null} view
 * @returns {Hash[]} hashes
 */

TX.prototype.getHashes = function getHashes(view, enc) {
  var hashes = [];
  var i, result, address;

  if (enc === 'hex') {
    result = this._getAddresses(view);
    return Object.keys(result.table);
  }

  result = this.getAddresses(view);

  for (i = 0; i < result.length; i++) {
    address = result[i];
    hashes.push(address.getHash());
  }

  return hashes;
};

/**
 * Test whether the transaction has
 * all coins available.
 * @param {CoinView} view
 * @returns {Boolean}
 */

TX.prototype.hasCoins = function hasCoins(view) {
  var i, input;

  if (this.inputs.length === 0)
    return false;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (!view.hasEntry(input))
      return false;
  }

  return true;
};

/**
 * Check finality of transaction by examining
 * nLocktime and nSequence values.
 * @example
 * tx.isFinal(chain.height + 1, network.now());
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
  var THRESHOLD = consensus.LOCKTIME_THRESHOLD;
  var i, input;

  if (this.locktime === 0)
    return true;

  if (this.locktime < (this.locktime < THRESHOLD ? height : ts))
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    if (input.sequence !== 0xffffffff)
      return false;
  }

  return true;
};

/**
 * Verify the absolute locktime of a transaction.
 * Called by OP_CHECKLOCKTIMEVERIFY.
 * @param {Number} index - Index of input being verified.
 * @param {Number} locktime - Locktime to verify against.
 * @returns {Boolean}
 */

TX.prototype.verifyLocktime = function verifyLocktime(index, locktime) {
  var THRESHOLD = consensus.LOCKTIME_THRESHOLD;
  var input = this.inputs[index];

  assert(input, 'Input does not exist.');
  assert(locktime >= 0, 'Locktime must be non-negative.');

  if (!((this.locktime < THRESHOLD && locktime < THRESHOLD)
      || (this.locktime >= THRESHOLD && locktime >= THRESHOLD))) {
    return false;
  }

  if (locktime > this.locktime)
    return false;

  if (input.sequence === 0xffffffff)
    return false;

  return true;
};

/**
 * Verify the relative locktime of an input.
 * Called by OP_CHECKSEQUENCEVERIFY.
 * @param {Number} index - Index of input being verified.
 * @param {Number} locktime - Sequence locktime to verify against.
 * @returns {Boolean}
 */

TX.prototype.verifySequence = function verifySequence(index, locktime) {
  var DISABLE_FLAG = consensus.SEQUENCE_DISABLE_FLAG;
  var TYPE_FLAG = consensus.SEQUENCE_TYPE_FLAG;
  var SEQUENCE_MASK = consensus.SEQUENCE_MASK;
  var input = this.inputs[index];
  var mask, sequence, predicate;

  assert(input, 'Input does not exist.');
  assert(locktime >= 0, 'Locktime must be non-negative.');

  if ((locktime & DISABLE_FLAG) !== 0)
    return true;

  if (this.version < 2)
    return false;

  if ((input.sequence & DISABLE_FLAG) !== 0)
    return false;

  mask = TYPE_FLAG | SEQUENCE_MASK;
  sequence = input.sequence & mask;
  predicate = locktime & mask;

  if (!((sequence < TYPE_FLAG && predicate < TYPE_FLAG)
      || (sequence >= TYPE_FLAG && predicate >= TYPE_FLAG))) {
    return false;
  }

  if (predicate > sequence)
    return false;

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

    if (!coin.script.isScripthash())
      continue;

    total += coin.script.getScripthashSigops(input.script);
  }

  return total;
};

/**
 * Calculate sigops cost, taking into account witness programs.
 * @param {CoinView} view
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop weight
 */

TX.prototype.getSigopsCost = function getSigopsCost(view, flags) {
  var scale = consensus.WITNESS_SCALE_FACTOR;
  var cost = this.getLegacySigops() * scale;
  var i, input, coin;

  if (flags == null)
    flags = Script.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return cost;

  if (flags & Script.flags.VERIFY_P2SH)
    cost += this.getScripthashSigops(view) * scale;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    cost += Script.getWitnessSigops(
      input.script,
      coin.script,
      input.witness,
      flags);
  }

  return cost;
};

/**
 * Calculate virtual sigop count.
 * @param {CoinView} view
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop count
 */

TX.prototype.getSigops = function getSigops(view, flags) {
  var scale = consensus.WITNESS_SCALE_FACTOR;

  if (flags == null)
    flags = Script.flags.STANDARD_VERIFY_FLAGS;

  return (this.getSigopsCost(view, flags) + scale - 1) / scale | 0;
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

  if (this.getBaseSize() > consensus.MAX_BLOCK_SIZE) {
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

    if (output.value > consensus.MAX_MONEY) {
      ret.reason = 'bad-txns-vout-toolarge';
      ret.score = 100;
      return false;
    }

    total += output.value;

    if (total < 0 || total > consensus.MAX_MONEY) {
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

  if (this.version < 1 || this.version > policy.MAX_TX_VERSION) {
    ret.reason = 'version';
    ret.score = 0;
    return false;
  }

  if (this.getWeight() >= policy.MAX_TX_WEIGHT) {
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

    if (output.script.isMultisig() && !policy.BARE_MULTISIG) {
      ret.reason = 'bare-multisig';
      ret.score = 0;
      return false;
    }

    if (output.isDust(policy.MIN_RELAY)) {
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

      if (redeem.getSigops(true) > policy.MAX_P2SH_SIGOPS)
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

TX.prototype.hasStandardWitness = function hasStandardWitness(view) {
  var i, j, input, witness, coin, prev, redeem, m;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    witness = input.witness;
    coin = view.getOutput(input);

    if (!coin)
      continue;

    if (witness.items.length === 0)
      continue;

    prev = coin.script;

    if (prev.isScripthash()) {
      prev = input.script.getRedeem();
      if (!prev)
        return false;
    }

    if (!prev.isProgram())
      return false;

    if (prev.isWitnessPubkeyhash()) {
      if (witness.items.length !== 2)
        return false;

      if (witness.items[0].length > 73)
        return false;

      if (witness.items[1].length > 65)
        return false;

      continue;
    }

    if (prev.isWitnessScripthash()) {
      if (witness.items.length - 1 > policy.MAX_P2WSH_STACK)
        return false;

      for (j = 0; j < witness.items.length - 1; j++) {
        if (witness.items[j].length > policy.MAX_P2WSH_PUSH)
          return false;
      }

      redeem = witness.items[witness.items.length - 1];

      if (redeem.length > policy.MAX_P2WSH_SIZE)
        return false;

      prev = new Script(redeem);

      if (prev.isPubkey()) {
        if (witness.items.length - 1 !== 1)
          return false;

        if (witness.items[0].length > 73)
          return false;

        continue;
      }

      if (prev.isPubkeyhash()) {
        if (input.witness.length - 1 !== 2)
          return false;

        if (witness.items[0].length > 73)
          return false;

        if (witness.items[1].length > 65)
          return false;

        continue;
      }

      if (prev.isMultisig()) {
        m = prev.getSmall(0);

        if (witness.items.length - 1 !== m + 1)
          return false;

        if (witness.items[0].length !== 0)
          return false;

        for (j = 1; j < witness.items.length - 1; j++) {
          if (witness.items[j].length > 73)
            return false;
        }
      }

      continue;
    }

    if (witness.items.length > policy.MAX_P2WSH_STACK)
      return false;

    for (j = 0; j < witness.items.length; j++) {
      if (witness.items[j].length > policy.MAX_P2WSH_PUSH)
        return false;
    }
  }

  return true;
};

/**
 * Perform contextual checks to verify input, output,
 * and fee values, as well as coinbase spend maturity
 * (coinbases can only be spent 100 blocks or more
 * after they're created). Note that this function is
 * consensus critical.
 * @param {CoinView} view
 * @param {Number} height - Height at which the
 * transaction is being spent. In the mempool this is
 * the chain height plus one at the time it entered the pool.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Boolean}
 */

TX.prototype.checkInputs = function checkInputs(view, height, ret) {
  return this.checkContext(view, height, ret) !== -1;
};

/**
 * Perform contextual checks to verify input, output,
 * and fee values, as well as coinbase spend maturity
 * (coinbases can only be spent 100 blocks or more
 * after they're created). Note that this function is
 * consensus critical.
 * @param {CoinView} view
 * @param {Number} height - Height at which the
 * transaction is being spent. In the mempool this is
 * the chain height plus one at the time it entered the pool.
 * @param {Object?} ret - Return object, may be
 * set with properties `reason` and `score`.
 * @returns {Amount}
 */

TX.prototype.checkContext = function checkContext(view, height, ret) {
  var total = 0;
  var i, input, coins, coin, fee, value;

  if (!ret)
    ret = new VerifyResult();

  assert(typeof height === 'number');

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coins = view.get(input.prevout.hash);

    if (!coins) {
      ret.reason = 'bad-txns-inputs-missingorspent';
      ret.score = 0;
      return -1;
    }

    if (coins.coinbase) {
      if (height - coins.height < consensus.COINBASE_MATURITY) {
        ret.reason = 'bad-txns-premature-spend-of-coinbase';
        ret.score = 0;
        return -1;
      }
    }

    coin = coins.getOutput(input.prevout.index);

    if (!coin) {
      ret.reason = 'bad-txns-inputs-missingorspent';
      ret.score = 0;
      return -1;
    }

    if (coin.value < 0 || coin.value > consensus.MAX_MONEY) {
      ret.reason = 'bad-txns-inputvalues-outofrange';
      ret.score = 100;
      return -1;
    }

    total += coin.value;

    if (total < 0 || total > consensus.MAX_MONEY) {
      ret.reason = 'bad-txns-inputvalues-outofrange';
      ret.score = 100;
      return -1;
    }
  }

  // Overflows already checked in `isSane()`.
  value = this.getOutputValue();

  if (total < value) {
    ret.reason = 'bad-txns-in-belowout';
    ret.score = 100;
    return -1;
  }

  fee = total - value;

  if (fee < 0) {
    ret.reason = 'bad-txns-fee-negative';
    ret.score = 100;
    return -1;
  }

  if (fee > consensus.MAX_MONEY) {
    ret.reason = 'bad-txns-fee-outofrange';
    ret.score = 100;
    return -1;
  }

  return fee;
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
 * @param {Number} height
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
 * @returns {Number}
 */

TX.prototype.getChainValue = function getChainValue(view) {
  var value = 0;
  var i, input, coin, coinHeight;

  if (this.isCoinbase())
    return value;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = view.getOutput(input);

    if (!coin)
      continue;

    coinHeight = view.getHeight(input);

    if (coinHeight === -1)
      continue;

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
  return priority > policy.FREE_THRESHOLD;
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

  return policy.getMinFee(size, rate);
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

  return policy.getRoundFee(size, rate);
};

/**
 * Calculate the transaction's rate based on size
 * and fees. Size will be calculated if not present.
 * @param {CoinView} view
 * @param {Number?} size
 * @returns {Rate}
 */

TX.prototype.getRate = function getRate(view, size) {
  var fee = this.getFee(view);

  if (fee < 0)
    return 0;

  if (size == null)
    size = this.getVirtualSize();

  return policy.getRate(size, fee);
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
      if (filter.update === Bloom.flags.ALL) {
        prevout = Outpoint.fromTX(this, i);
        filter.add(prevout.toRaw());
      } else if (filter.update === Bloom.flags.PUBKEY_ONLY) {
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
  return new InvItem(InvItem.types.TX, this.hash('hex'));
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
  assert(util.isUInt32(json.version), 'Version must be a uint32.');
  assert(util.isUInt8(json.flag), 'Flag must be a uint8.');
  assert(Array.isArray(json.inputs), 'Inputs must be an array.');
  assert(Array.isArray(json.outputs), 'Outputs must be an array.');
  assert(util.isUInt32(json.locktime), 'Locktime must be a uint32.');

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
    this._witness = 0;
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
  var witness = 0;
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

    witness = br.offset;

    for (i = 0; i < this.inputs.length; i++) {
      input = this.inputs[i];
      input.witness.fromReader(br);
      if (input.witness.items.length > 0)
        hasWitness = true;
    }

    witness = (br.offset - witness) + 2;
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
    this._witness = witness;
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
  var sizes = this.getNormalSizes();
  var bw = new StaticWriter(sizes.total);
  this.writeNormal(bw);
  sizes.data = bw.render();
  return sizes;
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `witness`).
 * @private
 * @returns {RawTX}
 */

TX.prototype.frameWitness = function frameWitness() {
  var sizes = this.getWitnessSizes();
  var bw = new StaticWriter(sizes.total);
  this.writeWitness(bw);
  sizes.data = bw.render();
  return sizes;
};

/**
 * Serialize transaction without witness.
 * @private
 * @param {BufferWriter} bw
 * @returns {RawTX}
 */

TX.prototype.writeNormal = function writeNormal(bw) {
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

  return bw;
};

/**
 * Serialize transaction with witness. Calculates the witness
 * size as it is framing (exposed on return value as `witness`).
 * @private
 * @param {BufferWriter} bw
 * @returns {RawTX}
 */

TX.prototype.writeWitness = function writeWitness(bw) {
  var i, witness, input, output;

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

  witness = bw.written;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    input.witness.toWriter(bw);
  }

  witness = bw.written - witness;

  bw.writeU32(this.locktime);

  if (witness === this.inputs.length)
    throw new Error('Cannot serialize empty-witness tx.');

  return bw;
};

/**
 * Calculate the real size of the transaction
 * without the witness vector.
 * @returns {RawTX}
 */

TX.prototype.getNormalSizes = function getNormalSizes() {
  var base = 0;
  var i, input, output;

  base += 4;

  base += encoding.sizeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    base += input.getSize();
  }

  base += encoding.sizeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    base += output.getSize();
  }

  base += 4;

  return new RawTX(base, 0);
};

/**
 * Calculate the real size of the transaction
 * with the witness included.
 * @returns {RawTX}
 */

TX.prototype.getWitnessSizes = function getWitnessSizes() {
  var base = 0;
  var witness = 0;
  var i, input, output;

  base += 4;
  witness += 2;

  base += encoding.sizeVarint(this.inputs.length);

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    base += input.getSize();
    witness += input.witness.getVarSize();
  }

  base += encoding.sizeVarint(this.outputs.length);

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    base += output.getSize();
  }

  base += 4;

  return new RawTX(base + witness, witness);
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

function AddrResult(addrs, table) {
  this.addrs = addrs;
  this.table = table;
}

/*
 * Expose
 */

module.exports = TX;

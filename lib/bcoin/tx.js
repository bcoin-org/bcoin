/*!
 * tx.js - transaction object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var Script = bcoin.script;
var Stack = bcoin.stack;
var BufferWriter = require('./writer');

/**
 * A static transaction object.
 * @exports TX
 * @constructor
 * @param {NakedTX} data - Transaction fields.
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

function TX(data) {
  var i;

  if (!(this instanceof TX))
    return new TX(data);

  assert(data, 'TX data is required.');
  assert(typeof data.version === 'number');
  assert(typeof data.flag === 'number');
  assert(Array.isArray(data.inputs));
  assert(Array.isArray(data.outputs));
  assert(typeof data.locktime === 'number');

  this.version = data.version;
  this.flag = data.flag;
  this.inputs = [];
  this.outputs = [];
  this.locktime = data.locktime;
  this.ts = data.ts || 0;
  this.block = data.block || null;
  this.index = data.index != null ? data.index : -1;
  this.ps = this.ts === 0 ? (data.ps != null ? data.ps : utils.now()) : 0;
  this.height = data.height != null ? data.height : -1;
  this.mutable = false;

  this._hash = null;
  this._whash = null;

  this._raw = data._raw || null;
  this._size = data._size || null;
  this._witnessSize = data._witnessSize != null ? data._witnessSize : null;

  this._outputValue = null;
  this._inputValue = null;
  this._hashPrevouts = null;
  this._hashSequence = null;
  this._hashOutputs = null;

  for (i = 0; i < data.inputs.length; i++)
    this.inputs.push(new bcoin.input(data.inputs[i]));

  for (i = 0; i < data.outputs.length; i++)
    this.outputs.push(new bcoin.output(data.outputs[i]));
}

/**
 * Clone the transaction.
 * @returns {TX}
 */

TX.prototype.clone = function clone() {
  var copy, i;

  copy = {
    version: this.version,
    flag: this.flag,
    inputs: [],
    outputs: [],
    locktime: this.locktime,
    ts: this.ts,
    block: this.block,
    index: this.index,
    height: this.height
  };

  for (i = 0; i < this.inputs.length; i++) {
    copy.inputs.push({
      prevout: {
        hash: this.inputs[i].prevout.hash,
        index: this.inputs[i].prevout.index
      },
      coin: this.inputs[i].coin,
      script: {
        code: this.inputs[i].script.code.slice(),
        raw: this.inputs[i].script.raw
      },
      witness: {
        items: this.inputs[i].witness.items.slice()
      },
      sequence: this.inputs[i].sequence
    });
  }

  for (i = 0; i < this.outputs.length; i++) {
    copy.outputs.push({
      value: this.outputs[i].value,
      script: {
        code: this.outputs[i].script.code.slice(),
        raw: this.outputs[i].script.raw
      }
    });
  }

  return new TX(copy);
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
  this.ps = 0;
};

/**
 * Remove all relevant block data from the transaction.
 */

TX.prototype.unsetBlock = function unsetBlock() {
  this.ts = 0;
  this.block = null;
  this.height = -1;
  this.index = -1;
  this.ps = utils.now();
};

/**
 * Hash the transaction with the non-witness serialization.
 * @param {String?} enc - Can be `'hex'` or `null`.
 * @returns {Hash|Buffer} hash
 */

TX.prototype.hash = function _hash(enc) {
  var hash = this._hash;

  if (!hash) {
    hash = utils.dsha256(this.renderNormal());
    if (!this.mutable)
      this._hash = hash;
  }

  return enc === 'hex' ? hash.toString('hex') : hash;
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
      : utils.copy(constants.ZERO_HASH);
  }

  if (!this.hasWitness())
    return this.hash(enc);

  if (!hash) {
    hash = utils.dsha256(this.renderWitness());
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

TX.prototype.render = function render() {
  return this.getRaw();
};

/**
 * Serialize the transaction without the
 * witness vector, regardless of whether it
 * is a witness transaction or not.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.renderNormal = function renderNormal() {
  var raw = this.getRaw();
  if (!bcoin.protocol.parser.isWitnessTX(raw))
    return raw;
  return bcoin.protocol.framer.tx(this);
};

/**
 * Serialize the transaction with the
 * witness vector, regardless of whether it
 * is a witness transaction or not.
 * @returns {Buffer} Serialized transaction.
 */

TX.prototype.renderWitness = function renderWitness() {
  var raw = this.getRaw();
  if (bcoin.protocol.parser.isWitnessTX(raw))
    return raw;
  return bcoin.protocol.framer.witnessTX(this);
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
    return this._raw;
  }

  if (this.hasWitness())
    raw = bcoin.protocol.framer.witnessTX(this);
  else
    raw = bcoin.protocol.framer.tx(this);

  if (!this.mutable) {
    this._raw = raw;
    this._size = raw.length;
    this._witnessSize = raw._witnessSize;
  }

  return raw;
};

/**
 * Calculate real size and size of the witness bytes.
 * @returns {Object} Contains `size` and `witnessSize`.
 */

TX.prototype.getSizes = function getSizes() {
  if (this.mutable)
    return bcoin.protocol.framer.tx.sizes(this);

  this.getRaw();

  return {
    size: this._size,
    witnessSize: this._witnessSize
  };
};

/**
 * Calculate the virtual size of the transaction.
 * Note that this is cached.
 * @returns {Number} vsize
 */

TX.prototype.getVirtualSize = function getVirtualSize() {
  var scale = constants.WITNESS_SCALE_FACTOR;
  return (this.getCost() + scale - 1) / scale | 0;
};

/**
 * Calculate the cost of the transaction.
 * Note that this is cached.
 * @returns {Number} cost
 */

TX.prototype.getCost = function getCost() {
  var sizes = this.getSizes();
  var base = sizes.size - sizes.witnessSize;
  return base * (constants.WITNESS_SCALE_FACTOR - 1) + sizes.size;
};

/**
 * Calculate the real size of the transaction
 * with the witness included.
 * @returns {Number} size
 */

TX.prototype.getSize = function getSize() {
  return this.getSizes().size;
};

/**
 * Calculate the size of the transaction
 * without the witness.
 * with the witness included.
 * @returns {Number} size
 */

TX.prototype.getBaseSize = function getBaseSize() {
  var sizes = this.getSizes();
  return sizes.size - sizes.witnessSize;
};

/**
 * Test whether the transaction has a non-empty witness.
 * @returns {Boolean}
 */

TX.prototype.hasWitness = function hasWitness() {
  var i;

  if (this._witnessSize > 0)
    return true;

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
  // Traditional sighashing
  if (version === 0)
    return this.signatureHashV0(index, prev, type);

  // Segwit sighashing
  if (version === 1)
    return this.signatureHashV1(index, prev, type);

  assert(false, 'Unknown sighash version.');
};

TX.prototype.signatureHashV0 = function signatureHashV0(index, prev, type) {
  var p = new BufferWriter();
  var i, copy;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  assert(index >= 0 && index < this.inputs.length);
  assert(prev instanceof Script);

  // Clone the transaction.
  copy = {
    version: this.version,
    inputs: [],
    outputs: [],
    locktime: this.locktime
  };

  for (i = 0; i < this.inputs.length; i++) {
    copy.inputs.push({
      prevout: this.inputs[i].prevout,
      script: this.inputs[i].script,
      witness: this.inputs[i].witness,
      sequence: this.inputs[i].sequence
    });
  }

  for (i = 0; i < this.outputs.length; i++) {
    copy.outputs.push({
      value: this.outputs[i].value,
      script: this.outputs[i].script
    });
  }

  // Remove all signatures.
  for (i = 0; i < copy.inputs.length; i++)
    copy.inputs[i].script = new Script();

  // Remove all code separators.
  prev = prev.removeSeparators();

  // Set our input to previous output's script
  copy.inputs[index].script = prev;

  if ((type & 0x1f) === constants.hashType.NONE) {
    // Drop all outputs. We don't want to sign them.
    copy.outputs.length = 0;

    // Allow input sequence updates for other inputs.
    for (i = 0; i < copy.inputs.length; i++) {
      if (i !== index)
        copy.inputs[i].sequence = 0;
    }
  } else if ((type & 0x1f) === constants.hashType.SINGLE) {
    // Bitcoind used to return 1 as an error code:
    // it ended up being treated like a hash.
    if (index >= copy.outputs.length)
      return utils.copy(constants.ONE_HASH);

    // Drop all the outputs after the input index.
    copy.outputs.length = index + 1;

    // Null outputs that are not the at current input index.
    for (i = 0; i < copy.outputs.length; i++) {
      if (i !== index) {
        copy.outputs[i].script = new Script();
        copy.outputs[i].value = -1;
      }
    }

    // Allow input sequence updates for other inputs.
    for (i = 0; i < copy.inputs.length; i++) {
      if (i !== index)
        copy.inputs[i].sequence = 0;
    }
  }

  // Only sign our input. Allows anyone to add inputs.
  if (type & constants.hashType.ANYONECANPAY) {
    copy.inputs[0] = copy.inputs[index];
    copy.inputs.length = 1;
  }

  // Render the copy and append the hashtype.
  bcoin.protocol.framer.tx(copy, p);
  p.writeU32(type);

  return utils.dsha256(p.render());
};

TX.prototype.signatureHashV1 = function signatureHashV1(index, prev, type) {
  var p = new BufferWriter();
  var i, prevout, hashPrevouts, hashSequence, hashOutputs;

  if (typeof index !== 'number')
    index = this.inputs.indexOf(index);

  if (typeof type === 'string')
    type = constants.hashType[type.toUpperCase()];

  assert(index >= 0 && index < this.inputs.length);
  assert(prev instanceof Script);

  if (!(type & constants.hashType.ANYONECANPAY)) {
    if (this._hashPrevouts) {
      hashPrevouts = this._hashPrevouts;
    } else {
      hashPrevouts = new BufferWriter();
      for (i = 0; i < this.inputs.length; i++) {
        prevout = this.inputs[i].prevout;
        hashPrevouts.writeHash(prevout.hash);
        hashPrevouts.writeU32(prevout.index);
      }
      hashPrevouts = utils.dsha256(hashPrevouts.render());
      if (!this.mutable)
        this._hashPrevouts = hashPrevouts;
    }
  } else {
    hashPrevouts = utils.copy(constants.ZERO_HASH);
  }

  if (!(type & constants.hashType.ANYONECANPAY)
      && (type & 0x1f) !== constants.hashType.SINGLE
      && (type & 0x1f) !== constants.hashType.NONE) {
    if (this._hashSequence) {
      hashSequence = this._hashSequence;
    } else {
      hashSequence = new BufferWriter();
      for (i = 0; i < this.inputs.length; i++)
        hashSequence.writeU32(this.inputs[i].sequence);
      hashSequence = utils.dsha256(hashSequence.render());
      if (!this.mutable)
        this._hashSequence = hashSequence;
    }
  } else {
    hashSequence = utils.copy(constants.ZERO_HASH);
  }

  if ((type & 0x1f) !== constants.hashType.SINGLE
      && (type & 0x1f) !== constants.hashType.NONE) {
    if (this._hashOutputs) {
      hashOutputs = this._hashOutputs;
    } else {
      hashOutputs = new BufferWriter();
      for (i = 0; i < this.outputs.length; i++)
        bcoin.protocol.framer.output(this.outputs[i], hashOutputs);
      hashOutputs = utils.dsha256(hashOutputs.render());
      if (!this.mutable)
        this._hashOutputs = hashOutputs;
    }
  } else if ((type & 0x1f) === constants.hashType.SINGLE && index < this.outputs.length) {
    hashOutputs = bcoin.protocol.framer.output(this.outputs[index]);
    hashOutputs = utils.dsha256(hashOutputs);
  } else {
    hashOutputs = utils.copy(constants.ZERO_HASH);
  }

  p.write32(this.version);
  p.writeBytes(hashPrevouts);
  p.writeBytes(hashSequence);
  p.writeHash(this.inputs[index].prevout.hash);
  p.writeU32(this.inputs[index].prevout.index);
  p.writeVarBytes(prev.encode());
  p.write64(this.inputs[index].coin.value);
  p.writeU32(this.inputs[index].sequence);
  p.writeBytes(hashOutputs);
  p.writeU32(this.locktime);
  p.writeU32(type);

  return utils.dsha256(p.render());
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

  if (!input.coin) {
    bcoin.debug('Coin is not available for verification.');
    return false;
  }

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
      bcoin.debug('Script verification error: %s', e.message);
    else
      bcoin.error(e);

    return false;
  }

  return true;
};

/**
 * Verify the transaction inputs on the worker pool
 * (if workers are enabled).
 * @param {VerifyFlags?} [flags=STANDARD_VERIFY_FLAGS]
 * @param {Function} callback
 * @returns {Boolean} Whether the inputs are valid.
 */

TX.prototype.verifyAsync = function verifyAsync(flags, callback) {
  var result;

  if (typeof flags === 'function') {
    callback = flags;
    flags = null;
  }

  if (!bcoin.workerPool) {
    callback = utils.asyncify(callback);
    try {
      result = this.verify(flags);
    } catch (e) {
      return callback(e);
    }
    return callback(null, result);
  }

  if (this.inputs.length === 0) {
    callback = utils.asyncify(callback);
    return callback(null, false);
  }

  if (this.isCoinbase()) {
    callback = utils.asyncify(callback);
    return callback(null, true);
  }

  bcoin.workerPool.verify(this, flags, callback);
};

/**
 * Test whether the transaction is a coinbase
 * by examining the inputs.
 * @returns {Boolean}
 */

TX.prototype.isCoinbase = function isCoinbase() {
  return this.inputs.length === 1
    && this.inputs[0].prevout.hash === constants.NULL_HASH;
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

  if (this._inputValue != null)
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

  if (this._outputValue != null)
    return this._outputValue;

  for (i = 0; i < this.outputs.length; i++)
    total += this.outputs[i].value;

  if (!this.mutable)
    this._outputValue = total;

  return total;
};

/**
 * Get all input addresses.
 * @returns {Base58Address[]} addresses
 */

TX.prototype.getInputAddresses = function getInputAddresses() {
  var table = {};
  var addresses = [];
  var i, address, hash;

  for (i = 0; i < this.inputs.length; i++) {
    address = this.inputs[i].getAddress();
    if (address) {
      hash = address.getHash('hex');
      if (!table[hash]) {
        table[hash] = true;
        addresses.push(address);
      }
    }
  }

  addresses.table = table;

  return addresses;
};

/**
 * Get all output addresses.
 * @returns {Base58Address[]} addresses
 */

TX.prototype.getOutputAddresses = function getOutputAddresses() {
  var table = {};
  var addresses = [];
  var i, address, hash;

  for (i = 0; i < this.outputs.length; i++) {
    address = this.outputs[i].getAddress();
    if (address) {
      hash = address.getHash('hex');
      if (!table[hash]) {
        table[hash] = true;
        addresses.push(address);
      }
    }
  }

  addresses.table = table;

  return addresses;
};

/**
 * Get all addresses.
 * @returns {Base58Address[]} addresses
 */

TX.prototype.getAddresses = function getAddresses() {
  var input = this.getInputAddresses();
  var output = this.getOutputAddresses();
  var i, hash;

  for (i = 0; i < output.length; i++) {
    hash = output[i].getHash('hex');
    if (!input.table[hash]) {
      input.table[hash] = true;
      input.push(output[i]);
    }
  }

  return input;
};

/**
 * Get all input address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getInputHashes = function getInputHashes(enc) {
  var input = this.getInputAddresses();
  var i;

  if (enc === 'hex')
    return Object.keys(input.table);

  for (i = 0; i < input.length; i++)
    input[i] = input[i].getHash();

  return input;
};

/**
 * Get all output address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getOutputHashes = function getOutputHashes(enc) {
  var output = this.getOutputAddresses();
  var i;

  if (enc === 'hex')
    return Object.keys(output.table);

  for (i = 0; i < output.length; i++)
    output[i] = output[i].getHash();

  return output;
};

/**
 * Get all address hashes.
 * @returns {Hash[]} hashes
 */

TX.prototype.getHashes = function getHashes(enc) {
  var hashes = this.getAddresses();
  var i;

  if (enc === 'hex')
    return Object.keys(hashes.table);

  for (i = 0; i < hashes.length; i++)
    hashes[i] = hashes[i].getHash();

  return hashes;
};

/**
 * Test the inputs against an address, an
 * array of address hashes, or a map of address hashes.
 * @param {Hash|Hash[]|AddressHashMap} addressMap
 * @param {Number?} index
 * @returns {Boolean} Whether the transaction matched.
 */

TX.prototype.testInputs = function testInputs(addressMap, index) {
  var i;

  if (typeof addressMap === 'string')
    addressMap = [addressMap];

  if (Array.isArray(addressMap))
    addressMap = utils.toMap(addressMap);

  if (index && typeof index === 'object')
    index = this.inputs.indexOf(index);

  if (index != null)
    return this.inputs[index].test(addressMap);

  for (i = 0; i < this.inputs.length; i++) {
    if (this.inputs[i].test(addressMap))
      return true;
  }

  return false;
};

/**
 * Test the outputs against an address, an
 * array of address hashes, or a map of address hashes.
 * @param {Hash|Hash[]|AddressHashMap} addressMap
 * @param {Number?} index
 * @returns {Boolean} Whether the transaction matched.
 */

TX.prototype.testOutputs = function testOutputs(addressMap, index) {
  var i;

  if (typeof addressMap === 'string')
    addressMap = [addressMap];

  if (Array.isArray(addressMap))
    addressMap = utils.toMap(addressMap);

  if (index && typeof index === 'object')
    index = this.outputs.indexOf(index);

  if (index != null)
    return this.outputs[index].test(addressMap);

  for (i = 0; i < this.outputs.length; i++) {
    if (this.outputs[i].test(addressMap))
      return true;
  }

  return false;
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
  var total = 0;
  var key, i, input, prevout, map, coin;

  if ((coins instanceof bcoin.coin) || (coins instanceof TX))
    coins = [coins];

  if (Array.isArray(coins)) {
    map = {};
    for (i = 0; i < coins.length; i++) {
      coin = coins[i];
      if (coin instanceof TX) {
        map[coin.hash('hex')] = coin;
      } else if (coin instanceof bcoin.coin) {
        assert(typeof coin.hash === 'string');
        assert(typeof coin.index === 'number');
        map[coin.hash + '/' + coin.index] = coin;
      } else {
        assert(false, 'Non-coin object passed to fillCoins.');
      }
    }
    coins = map;
  }

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    prevout = input.prevout;

    if (!input.coin) {
      if (coins[prevout.hash]) {
        input.coin = bcoin.coin.fromTX(coins[prevout.hash], prevout.index);
      } else {
        key = prevout.hash + '/' + prevout.index;
        if (coins[key])
          input.coin = coins[key];
      }
    }

    if (input.coin)
      total++;
  }

  return total === this.inputs.length;
};

/**
 * Check finality of transaction by examining nLockTime and nSequences.
 * @example
 * tx.isFinal(network.height + 1, utils.now());
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
 * Calculate sigops cost, taking into account witness programs.
 * @param {VerifyFlags?} flags
 * @returns {Number} sigop cost
 */

TX.prototype.getSigopsCost = function getSigopsCost(flags) {
  var cost = this.getLegacySigops() * constants.WITNESS_SCALE_FACTOR;
  var input, i;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return cost;

  if (flags & constants.flags.VERIFY_P2SH)
    cost += this.getScripthashSigops() * constants.WITNESS_SCALE_FACTOR;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    cost += Script.getWitnessSigops(
      input.script,
      input.coin.script,
      input.witness,
      flags);
  }

  return cost;
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

  return (this.getSigopsCost(flags) + scale - 1) / scale | 0;
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
    ret = {};

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
    key = input.prevout.hash + '/' + input.prevout.index;
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
      if (input.prevout.hash === constants.NULL_HASH
          && input.prevout.index === 0xffffffff) {
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

TX.prototype.isStandard = function isStandard(flags, ret) {
  var i, input, output;
  var nulldata = 0;

  if (!ret)
    ret = {};

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.version < 1 || this.version > constants.tx.MAX_VERSION) {
    ret.reason = 'version';
    return false;
  }

  if (this.getCost() > constants.tx.MAX_COST) {
    ret.reason = 'tx-size';
    return false;
  }

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (input.script.getSize() > 1650) {
      ret.reason = 'scriptsig-size';
      return false;
    }

    if (flags & constants.flags.VERIFY_SIGPUSHONLY) {
      if (!input.script.isPushOnly()) {
        ret.reason = 'scriptsig-not-pushonly';
        return false;
      }
    }
  }

  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];

    if (!output.script.isStandard()) {
      ret.reason = 'scriptpubkey';
      return false;
    }

    if (output.script.isNulldata()) {
      nulldata++;
      continue;
    }

    if (output.script.isMultisig() && !constants.tx.BARE_MULTISIG) {
      ret.reason = 'bare-multisig';
      return false;
    }

    if (output.isDust(constants.tx.MIN_RELAY)) {
      ret.reason = 'dust';
      return false;
    }
  }

  if (nulldata > 1) {
    ret.reason = 'multi-op-return';
    return false;
  }

  return true;
};

/**
 * Perform contextual checks to verify coin and input
 * script standardness (including the redeem script).
 * @see AreInputsStandard()
 * @param {VerifyFlags?}
 * @returns {Boolean}
 */

TX.prototype.hasStandardInputs = function hasStandardInputs(flags) {
  var maxSigops = constants.script.MAX_SCRIPTHASH_SIGOPS;
  var VERIFY_NONE = constants.flags.VERIFY_NONE;
  var i, input, stack, redeem;

  if (flags == null)
    flags = constants.flags.STANDARD_VERIFY_FLAGS;

  if (this.isCoinbase())
    return true;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      return false;

    if (input.coin.script.isUnknown())
      return false;

    if ((flags & constants.flags.VERIFY_P2SH)
        && input.coin.script.isScripthash()) {
      stack = new Stack();

      try {
        input.script.execute(stack, VERIFY_NONE, this, i, 0);
      } catch (e) {
        return false;
      }

      if (stack.length === 0)
        return false;

      redeem = stack.getRedeem(false);

      if (!redeem)
        return false;

      if (redeem.getSigops(true) > maxSigops)
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
    ret = {};

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];
    coin = input.coin;

    if (coin.coinbase) {
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
  }

  if (total < 0 || total > constants.MAX_MONEY) {
    ret.reason = 'bad-txns-inputvalues-outofrange';
    ret.score = 100;
    return false;
  }

  value = this.getOutputValue();

  if (value > total) {
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
 * or mempool height will be used.
 * @param {Number?} size - Size to calculate priority
 * based on. If not present, modified size will be
 * calculated and used.
 * @returns {Object} data - Object containing
 * `priority` and `value`.
 */

TX.prototype.getPriority = function getPriority(height, size) {
  var sum, i, input, age, value;

  if (this.isCoinbase())
    return { value: 0, priority: 0 };

  if (height == null) {
    height = this.height;
    if (height === -1)
      height = bcoin.network.get().height + 1;
  }

  if (size == null)
    size = this.maxSize();

  sum = 0;
  value = 0;

  for (i = 0; i < this.inputs.length; i++) {
    input = this.inputs[i];

    if (!input.coin)
      continue;

    if (input.coin.height === -1)
      continue;

    if (input.coin.height <= height) {
      age = height - input.coin.height;
      sum += input.coin.value * age;
      value += input.coin.value;
    }
  }

  return {
    value: value,
    priority: Math.floor(sum / size)
  };
};

/**
 * Determine whether the transaction is above the
 * free threshold in priority. A transaction which
 * passed this test is most likely relayable
 * without a fee.
 * @param {Number?} height - If not present, tx
 * height or mempool height will be used.
 * @param {Number?} size - If not present, modified
 * size will be calculated and used.
 * @returns {Boolean}
 */

TX.prototype.isFree = function isFree(height, size) {
  var data;

  if (height == null) {
    height = this.height;
    if (height === -1)
      height = bcoin.network.get().height + 1;
  }

  data = this.getPriority(height, size);

  return data.priority > constants.tx.FREE_THRESHOLD;
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

  return TX.getMinFee(size, rate);
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

  return TX.getRate(size, this.getFee());
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
  var fee;

  if (size == null)
    size = this.maxSize();

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  fee = rate * Math.ceil(size / 1000);

  if (fee === 0 && rate > 0)
    fee = rate;

  return fee;
};

/**
 * Calculate current number of transaction confirmations.
 * @param {Number?} height - Current chain height. If not
 * present, network chain height will be used.
 * @returns {Number} confirmations
 */

TX.prototype.getConfirmations = function getConfirmations(height) {
  if (height == null)
    height = bcoin.network.get().height;

  if (this.height === -1)
    return 0;

  if (height < this.height)
    return 1;

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
  var i, input, output, hash, index, outpoint;

  if (!filter)
    return false;

  function testScript(code) {
    var i, chunk;

    for (i = 0; i < code.length; i++) {
      chunk = code[i];
      if (Script.isBadPush(chunk))
        break;
      if (!Buffer.isBuffer(chunk) || chunk.length === 0)
        continue;
      if (filter.test(chunk))
        return true;
    }

    return false;
  }

  // 1. Test the tx hash
  if (filter.test(this.hash()))
    found = true;

  // 2. Test data elements in output scripts
  //    (may need to update filter on match)
  for (i = 0; i < this.outputs.length; i++) {
    output = this.outputs[i];
    // Test the output script
    if (testScript(output.script.code)) {
      if (filter.update === constants.filterFlags.ALL) {
        outpoint = bcoin.protocol.framer.outpoint(this.hash(), i);
        filter.add(outpoint);
      } else if (filter.update === constants.filterFlags.PUBKEY_ONLY) {
        if (output.script.isPubkey() || output.script.isMultisig()) {
          outpoint = bcoin.protocol.framer.outpoint(this.hash(), i);
          filter.add(outpoint);
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
    hash = input.prevout.hash;
    index = input.prevout.index;
    outpoint = bcoin.protocol.framer.outpoint(hash, index);

    // Test the COutPoint structure
    if (filter.test(outpoint))
      return true;

    // Test the input script
    if (testScript(input.script.code))
      return true;

    // Test the witness
    // if (testScript(input.witness.items))
    //   return true;
  }

  // 5. No match
  return false;
};

TX.prototype.__defineGetter__('rblock', function() {
  return this.block
    ? utils.revHex(this.block)
    : null;
});

TX.prototype.__defineGetter__('rhash', function() {
  return utils.revHex(this.hash('hex'));
});

TX.prototype.__defineGetter__('rwhash', function() {
  return utils.revHex(this.witnessHash('hex'));
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
  return {
    type: constants.inv.TX,
    hash: this.hash('hex')
  };
};

/**
 * Calculate minimum fee based on rate and size.
 * @param {Number?} size
 * @param {Rate?} rate - Rate of satoshi per kB.
 * @returns {Amount} fee
 */

TX.getMinFee = function getMinFee(size, rate) {
  var fee;

  if (rate == null)
    rate = constants.tx.MIN_RELAY;

  fee = Math.floor(rate * size / 1000);

  if (fee === 0 && rate > 0)
    fee = rate;

  return fee;
};

/**
 * Calculate a fee rate based on size and fees.
 * @param {Number} size
 * @param {Amount} fee
 * @returns {Rate}
 */

TX.getRate = function getRate(size, fee) {
  return Math.floor(fee * 1000 / size);
};

/**
 * Inspect the transaction and return a more
 * user-friendly representation of the data.
 * @returns {Object}
 */

TX.prototype.inspect = function inspect() {
  return {
    type: 'tx',
    hash: this.rhash,
    witnessHash: this.rwhash,
    size: this.getSize(),
    virtualSize: this.maxSize(),
    height: this.height,
    value: utils.btc(this.getOutputValue()),
    fee: utils.btc(this.getFee()),
    minFee: utils.btc(this.getMinFee()),
    rate: utils.btc(this.getRate()),
    confirmations: this.getConfirmations(),
    priority: this.getPriority().priority.toString(10),
    date: utils.date(this.ts || this.ps),
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    changeIndex: this.changeIndex || -1,
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

TX.prototype.toJSON = function toJSON() {
  return {
    type: 'tx',
    hash: utils.revHex(this.hash('hex')),
    witnessHash: utils.revHex(this.witnessHash('hex')),
    height: this.height,
    block: this.block ? utils.revHex(this.block) : null,
    ts: this.ts,
    ps: this.ps,
    index: this.index,
    changeIndex: this.changeIndex || -1,
    version: this.version,
    flag: this.flag,
    inputs: this.inputs.map(function(input) {
      return input.toJSON();
    }),
    outputs: this.outputs.map(function(output) {
      return output.toJSON();
    }),
    locktime: this.locktime
  };
};

/**
 * Handle a deserialized JSON transaction object.
 * @param {Object} json
 * @returns {NakedTX} A "naked" transaction (a
 * plain javascript object which is suitable
 * for passing to the TX constructor).
 */

TX.parseJSON = function fromJSON(json) {
  assert.equal(json.type, 'tx');
  return {
    block: json.block ? utils.revHex(json.block) : null,
    height: json.height,
    ts: json.ts,
    ps: json.ps,
    index: json.index,
    changeIndex: json.changeIndex || -1,
    version: json.version,
    flag: json.flag,
    inputs: json.inputs.map(function(input) {
      return bcoin.input.parseJSON(input);
    }),
    outputs: json.outputs.map(function(output) {
      return bcoin.output.parseJSON(output);
    }),
    locktime: json.locktime
  };
};

/**
 * Instantiate a transaction from a
 * jsonified transaction object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {TX}
 */

TX.fromJSON = function fromJSON(json) {
  assert.equal(json.type, 'tx');
  return new TX(TX.parseJSON(json));
};

/**
 * Serialize the transaction.
 * @see {TX#render}
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {Buffer|String}
 */

TX.prototype.toRaw = function toRaw(enc) {
  var data = this.render();

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a serialized transaction.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {NakedTX} A "naked" transaction object.
 */

TX.parseRaw = function parseRaw(data, enc) {
  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseTX(data);
};

/**
 * Instantiate a transaction from a serialized Buffer.
 * @param {Buffer} data
 * @param {String?} enc - Encoding, can be `'hex'` or null.
 * @returns {TX}
 */

TX.fromRaw = function fromRaw(data, enc) {
  return new bcoin.tx(TX.parseRaw(data, enc));
};

/**
 * Serialize a transaction to BCoin "extended format".
 * This is the serialization format BCoin uses internally
 * to store transactions in the database. The extended
 * serialization includes the height, block hash, index,
 * timestamp, pending-since time, and optionally a vector
 * for the serialized coins.
 * @param {Boolean?} saveCoins - Whether to serialize the coins.
 * @param {String?} enc - One of `"hex"` or `null`.
 * @returns {Buffer}
 */

TX.prototype.toExtended = function toExtended(saveCoins, enc) {
  var data, tmp;

  if (typeof saveCoins === 'string') {
    tmp = saveCoins;
    saveCoins = enc;
    enc = tmp;
  }

  data = bcoin.protocol.framer.extendedTX(this, saveCoins);

  if (enc === 'hex')
    data = data.toString('hex');

  return data;
};

/**
 * Parse a transaction in "extended" serialization format.
 * @param {Buffer} data
 * @param {Boolean?} saveCoins - If true, the function will
 * attempt to parse the coins.
 * @param {String?} enc - One of `"hex"` or `null`.
 * @returns {NakedTX} - A "naked" transaction object.
 */

TX.parseExtended = function parseExtended(data, saveCoins, enc) {
  var tmp;

  if (typeof saveCoins === 'string') {
    tmp = saveCoins;
    saveCoins = enc;
    enc = tmp;
  }

  if (enc === 'hex')
    data = new Buffer(data, 'hex');

  return bcoin.protocol.parser.parseExtendedTX(data, saveCoins);
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
  return new TX(TX.parseExtended(data, saveCoins, enc));
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
 * Expose
 */


module.exports = TX;

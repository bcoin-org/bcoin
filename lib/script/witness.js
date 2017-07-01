/*!
 * witness.js - witness object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const BN = require('../crypto/bn');
const util = require('../utils/util');
const Script = require('./script');
const common = require('./common');
const encoding = require('../utils/encoding');
const Opcode = require('./opcode');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const Address = require('../primitives/address');
const Stack = require('./stack');
const opcodes = common.opcodes;
const scriptTypes = common.types;
const STACK_FALSE = common.STACK_FALSE;
const STACK_NEGATE = common.STACK_NEGATE;

/**
 * Refers to the witness field of segregated witness transactions.
 * @alias module:script.Witness
 * @constructor
 * @param {Buffer[]|NakedWitness} items - Array of
 * stack items.
 * @property {Buffer[]} items
 * @property {Script?} redeem
 * @property {Number} length
 */

function Witness(options) {
  if (!(this instanceof Witness))
    return new Witness(options);

  this.items = [];

  if (options)
    this.fromOptions(options);
}

/**
 * Getter to retrieve witness vector length.
 * @name module:script.Witness#length_getter
 * @method
 * @private
 * @returns {Number}
 */

Witness.prototype.__defineGetter__('length', function() {
  return this.items.length;
});

/**
 * Setter to set witness vector length.
 * @name module:script.Witness#length_setter
 * @method
 * @private
 * @param {Number} value
 * @returns {Number}
 */

Witness.prototype.__defineSetter__('length', function(length) {
  return this.items.length = length;
});

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Witness.prototype.fromOptions = function fromOptions(options) {
  let items;

  assert(options, 'Witness data is required.');

  items = options.items;

  if (!items)
    items = options;

  if (items)
    this.fromArray(items);

  return this;
};

/**
 * Instantiate witness from options.
 * @param {Object} options
 * @returns {Witness}
 */

Witness.fromOptions = function fromOptions(options) {
  return new Witness().fromOptions(options);
};

/**
 * Convert witness to an array of buffers.
 * @returns {Buffer[]}
 */

Witness.prototype.toArray = function toArray() {
  return this.items.slice();
};

/**
 * Inject properties from an array of buffers.
 * @private
 * @param {Buffer[]} items
 */

Witness.prototype.fromArray = function fromArray(items) {
  assert(Array.isArray(items));
  this.items = items;
  return this;
};

/**
 * Insantiate witness from an array of buffers.
 * @param {Buffer[]} items
 * @returns {Witness}
 */

Witness.fromArray = function fromArray(items) {
  return new Witness().fromArray(items);
};

/**
 * Inspect a Witness object.
 * @returns {String} Human-readable script.
 */

Witness.prototype.inspect = function inspect() {
  return `<Witness: ${this.toString()}>`;
};

/**
 * Convert a Witness object to a String.
 * @returns {String} Human-readable script.
 */

Witness.prototype.toString = function toString() {
  return common.formatStack(this.items);
};

/**
 * Format the witness object as bitcoind asm.
 * @param {Boolean?} decode - Attempt to decode hash types.
 * @returns {String} Human-readable script.
 */

Witness.prototype.toASM = function toASM(decode) {
  return common.formatStackASM(this.items, decode);
};

/**
 * Clone the witness object.
 * @returns {Witness} A clone of the current witness object.
 */

Witness.prototype.clone = function clone() {
  return new Witness().inject(this);
};

/**
 * Inject properties from witness.
 * Used for cloning.
 * @private
 * @param {Witness} witness
 * @returns {Witness}
 */

Witness.prototype.inject = function inject(witness) {
  this.items = witness.items.slice();
  return this;
};

/**
 * Convert the Witness to a Stack object.
 * This is usually done before executing
 * a witness program.
 * @returns {Stack}
 */

Witness.prototype.toStack = function toStack() {
  return new Stack(this.items.slice());
};

/**
 * "Guess" the type of the witness.
 * This method is not 100% reliable.
 * @returns {ScriptType}
 */

Witness.prototype.getInputType = function getInputType() {
  if (this.isPubkeyhashInput())
    return scriptTypes.WITNESSPUBKEYHASH;

  if (this.isScripthashInput())
    return scriptTypes.WITNESSSCRIPTHASH;

  return scriptTypes.NONSTANDARD;
};

/**
 * "Guess" the address of the witness.
 * This method is not 100% reliable.
 * @returns {Address|null}
 */

Witness.prototype.getInputAddress = function getInputAddress() {
  return Address.fromWitness(this);
};

/**
 * "Test" whether the witness is a pubkey input.
 * Always returns false.
 * @returns {Boolean}
 */

Witness.prototype.isPubkeyInput = function isPubkeyInput() {
  return false;
};

/**
 * "Guess" whether the witness is a pubkeyhash input.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isPubkeyhashInput = function isPubkeyhashInput() {
  return this.items.length === 2
    && common.isSignatureEncoding(this.items[0])
    && common.isKeyEncoding(this.items[1]);
};

/**
 * "Test" whether the witness is a multisig input.
 * Always returns false.
 * @returns {Boolean}
 */

Witness.prototype.isMultisigInput = function isMultisigInput() {
  return false;
};

/**
 * "Guess" whether the witness is a scripthash input.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isScripthashInput = function isScripthashInput() {
  return this.items.length > 0 && !this.isPubkeyhashInput();
};

/**
 * "Guess" whether the witness is an unknown/non-standard type.
 * This method is not 100% reliable.
 * @returns {Boolean}
 */

Witness.prototype.isUnknownInput = function isUnknownInput() {
  return this.getInputType() === scriptTypes.NONSTANDARD;
};

/**
 * Test the witness against a bloom filter.
 * @param {Bloom} filter
 * @returns {Boolean}
 */

Witness.prototype.test = function test(filter) {
  for (let item of this.items) {
    if (item.length === 0)
      continue;

    if (filter.test(item))
      return true;
  }

  return false;
};

/**
 * Grab and deserialize the redeem script from the witness.
 * @returns {Script} Redeem script.
 */

Witness.prototype.getRedeem = function getRedeem() {
  let redeem;

  if (this.items.length === 0)
    return;

  redeem = this.items[this.items.length - 1];

  if (!redeem)
    return;

  return Script.fromRaw(redeem);
};

/**
 * Does nothing currently.
 */

Witness.prototype.compile = function compile() {
  // NOP
};

/**
 * Find a data element in a witness.
 * @param {Buffer} data - Data element to match against.
 * @returns {Number} Index (`-1` if not present).
 */

Witness.prototype.indexOf = function indexOf(data) {
  return util.indexOf(this.items, data);
};

/**
 * Calculate size of the witness
 * excluding the varint size bytes.
 * @returns {Number}
 */

Witness.prototype.getSize = function getSize() {
  let size = 0;

  for (let item of this.items)
    size += encoding.sizeVarBytes(item);

  return size;
};

/**
 * Calculate size of the witness
 * including the varint size bytes.
 * @returns {Number}
 */

Witness.prototype.getVarSize = function getVarSize() {
  return encoding.sizeVarint(this.items.length) + this.getSize();
};

/**
 * Write witness to a buffer writer.
 * @param {BufferWriter} bw
 */

Witness.prototype.toWriter = function toWriter(bw) {
  let item;

  bw.writeVarint(this.items.length);

  for (item of this.items)
    bw.writeVarBytes(item);

  return bw;
};

/**
 * Encode the witness to a Buffer.
 * @param {String} enc - Encoding, either `'hex'` or `null`.
 * @returns {Buffer|String} Serialized script.
 */

Witness.prototype.toRaw = function toRaw() {
  let size = this.getVarSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Convert witness to a hex string.
 * @returns {String}
 */

Witness.prototype.toJSON = function toJSON() {
  return this.toRaw().toString('hex');
};

/**
 * Inject properties from json object.
 * @private
 * @param {String} json
 */

Witness.prototype.fromJSON = function fromJSON(json) {
  assert(typeof json === 'string', 'Witness must be a string.');
  return this.fromRaw(Buffer.from(json, 'hex'));
};

/**
 * Insantiate witness from a hex string.
 * @param {String} json
 * @returns {Witness}
 */

Witness.fromJSON = function fromJSON(json) {
  return new Witness().fromJSON(json);
};

/**
 * Unshift an item onto the witness vector.
 * @param {Number|String|Buffer|BN} data
 * @returns {Number}
 */

Witness.prototype.unshift = function unshift(data) {
  return this.items.unshift(Witness.encodeItem(data));
};

/**
 * Push an item onto the witness vector.
 * @param {Number|String|Buffer|BN} data
 * @returns {Number}
 */

Witness.prototype.push = function push(data) {
  return this.items.push(Witness.encodeItem(data));
};

/**
 * Shift an item off the witness vector.
 * @returns {Buffer}
 */

Witness.prototype.shift = function shift() {
  return this.items.shift();
};

/**
 * Shift an item off the witness vector.
 * @returns {Buffer}
 */

Witness.prototype.pop = function push(data) {
  return this.items.pop();
};

/**
 * Remove an item from the witness vector.
 * @param {Number} index
 * @returns {Buffer}
 */

Witness.prototype.remove = function remove(i) {
  return this.items.splice(i, 1)[0];
};

/**
 * Insert an item into the witness vector.
 * @param {Number} index
 * @param {Number|String|Buffer|BN} data
 */

Witness.prototype.insert = function insert(i, data) {
  assert(i <= this.items.length, 'Index out of bounds.');
  this.items.splice(i, 0, Witness.encodeItem(data))[0];
};

/**
 * Get an item from the witness vector.
 * @param {Number} index
 * @returns {Buffer}
 */

Witness.prototype.get = function get(i) {
  return this.items[i];
};

/**
 * Get a small int (0-16) from the witness vector.
 * @param {Number} index
 * @returns {Number} `-1` on non-existent.
 */

Witness.prototype.getSmall = function getSmall(i) {
  let item = this.items[i];
  if (!item || item.length > 1)
    return -1;
  if (item.length === 0)
    return 0;
  if (!(item[0] >= 1 && item[1] <= 16))
    return -1;
  return item[0];
};

/**
 * Get a number from the witness vector.
 * @param {Number} index
 * @returns {BN}
 */

Witness.prototype.getNumber = function getNumber(i) {
  let item = this.items[i];
  if (!item || item.length > 5)
    return;
  return common.num(item, false, 5);
};

/**
 * Get a string from the witness vector.
 * @param {Number} index
 * @returns {String}
 */

Witness.prototype.getString = function getString(i) {
  let item = this.items[i];
  if (!item)
    return;
  return item.toString('utf8');
};

/**
 * Clear the witness items.
 */

Witness.prototype.clear = function clear() {
  this.items.length = 0;
};

/**
 * Set an item in the witness vector.
 * @param {Number} index
 * @param {Number|String|Buffer|BN} data
 */

Witness.prototype.set = function set(i, data) {
  assert(i <= this.items.length, 'Index out of bounds.');
  this.items[i] = Witness.encodeItem(data);
};

/**
 * Encode a witness item.
 * @param {Number|String|Buffer|BN} data
 * @returns {Buffer}
 */

Witness.encodeItem = function encodeItem(data) {
  if (data instanceof Opcode)
    data = data.data || data.value;

  if (typeof data === 'number') {
    if (data === opcodes.OP_1NEGATE)
      return STACK_NEGATE;

    if (data === opcodes.OP_0)
      return STACK_FALSE;

    if (data >= opcodes.OP_1 && data <= opcodes.OP_16)
      return Buffer.from([data - 0x50]);

    throw new Error('Non-push opcode in witness.');
  }

  if (BN.isBN(data))
    return common.array(data);

  if (typeof data === 'string')
    return Buffer.from(data, 'utf8');

  return data;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Witness.prototype.fromReader = function fromReader(br) {
  let count = br.readVarint();

  for (let i = 0; i < count; i++)
    this.items.push(br.readVarBytes());

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

Witness.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Create a witness from a buffer reader.
 * @param {BufferReader} br
 */

Witness.fromReader = function fromReader(br) {
  return new Witness().fromReader(br);
};

/**
 * Create a witness from a serialized buffer.
 * @param {Buffer|String} data - Serialized witness.
 * @param {String?} enc - Either `"hex"` or `null`.
 * @returns {Witness}
 */

Witness.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new Witness().fromRaw(data);
};

/**
 * Inject items from string.
 * @private
 * @param {String|String[]} items
 */

Witness.prototype.fromString = function fromString(items) {
  if (!Array.isArray(items)) {
    assert(typeof items === 'string');

    items = items.trim();

    if (items.length === 0)
      return this;

    items = items.split(/\s+/);
  }

  for (let item of items)
    this.items.push(Buffer.from(item, 'hex'));

  return this;
};

/**
 * Parse a test script/array
 * string into a witness object. _Must_
 * contain only stack items (no non-push
 * opcodes).
 * @param {String|String[]} items - Script string.
 * @returns {Witness}
 * @throws Parse error.
 */

Witness.fromString = function fromString(items) {
  return new Witness().fromString(items);
};

/**
 * Test an object to see if it is a Witness.
 * @param {Object} obj
 * @returns {Boolean}
 */

Witness.isWitness = function isWitness(obj) {
  return obj
    && Array.isArray(obj.items)
    && typeof obj.toStack === 'function';
};

/*
 * Expose
 */

module.exports = Witness;

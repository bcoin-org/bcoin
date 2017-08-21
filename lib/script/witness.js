/*!
 * witness.js - witness object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const util = require('../utils/util');
const Script = require('./script');
const common = require('./common');
const encoding = require('../utils/encoding');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const Address = require('../primitives/address');
const Stack = require('./stack');
const scriptTypes = common.types;

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

  Stack.call(this, []);

  if (options)
    this.fromOptions(options);
}

Object.setPrototypeOf(Witness.prototype, Stack.prototype);

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

Witness.prototype.fromOptions = function fromOptions(options) {
  assert(options, 'Witness data is required.');

  if (Array.isArray(options))
    return this.fromArray(options);

  if (options.items)
    return this.fromArray(options.items);

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
 * Convert witness to an array of buffers.
 * @returns {Buffer[]}
 */

Witness.prototype.toItems = function toItems() {
  return this.items.slice();
};

/**
 * Inject properties from an array of buffers.
 * @private
 * @param {Buffer[]} items
 */

Witness.prototype.fromItems = function fromItems(items) {
  assert(Array.isArray(items));
  this.items = items;
  return this;
};

/**
 * Insantiate witness from an array of buffers.
 * @param {Buffer[]} items
 * @returns {Witness}
 */

Witness.fromItems = function fromItems(items) {
  return new Witness().fromItems(items);
};

/**
 * Convert witness to a stack.
 * @returns {Stack}
 */

Witness.prototype.toStack = function toStack() {
  return new Stack(this.toArray());
};

/**
 * Inject properties from a stack.
 * @private
 * @param {Stack} stack
 */

Witness.prototype.fromStack = function fromStack(stack) {
  return this.fromArray(stack.items);
};

/**
 * Insantiate witness from a stack.
 * @param {Stack} stack
 * @returns {Witness}
 */

Witness.fromStack = function fromStack(stack) {
  return new Witness().fromStack(stack);
};

/**
 * Inspect a Witness object.
 * @returns {String} Human-readable script.
 */

Witness.prototype.inspect = function inspect() {
  return `<Witness: ${this.toString()}>`;
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
 * Compile witness (NOP).
 * @returns {Witness}
 */

Witness.prototype.compile = function compile() {
  return this;
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
 * Get P2PK signature if present.
 * Always returns null.
 * @returns {Buffer|null}
 */

Witness.prototype.getPubkeyInput = function getPubkeyInput() {
  return null;
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
 * Get P2PKH signature and key if present.
 * @returns {Array} [sig, key]
 */

Witness.prototype.getPubkeyhashInput = function getPubkeyhashInput() {
  if (!this.isPubkeyhashInput())
    return [null, null];
  return [this.items[0], this.items[1]];
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
 * Get multisig signatures key if present.
 * Always returns null.
 * @returns {Buffer[]|null}
 */

Witness.prototype.getMultisigInput = function getMultisigInput() {
  return null;
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
 * Get P2SH redeem script if present.
 * @returns {Buffer|null}
 */

Witness.prototype.getScripthashInput = function getScripthashInput() {
  if (!this.isScripthashInput())
    return null;
  return this.items[this.items.length - 1];
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
  for (const item of this.items) {
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
  if (this.items.length === 0)
    return null;

  const redeem = this.items[this.items.length - 1];

  if (!redeem)
    return null;

  return Script.fromRaw(redeem);
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

  for (const item of this.items)
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
  bw.writeVarint(this.items.length);

  for (const item of this.items)
    bw.writeVarBytes(item);

  return bw;
};

/**
 * Encode the witness to a Buffer.
 * @param {String} enc - Encoding, either `'hex'` or `null`.
 * @returns {Buffer|String} Serialized script.
 */

Witness.prototype.toRaw = function toRaw() {
  const size = this.getVarSize();
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
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

Witness.prototype.fromReader = function fromReader(br) {
  const count = br.readVarint();

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

  for (const item of items)
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
  return obj instanceof Witness;
};

/*
 * Expose
 */

module.exports = Witness;

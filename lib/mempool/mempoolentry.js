/*!
 * mempoolentry.js - mempool entry object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var policy = require('../protocol/policy');
var util = require('../utils/util');
var Script = require('../script/script');
var BufferReader = require('../utils/reader');
var StaticWriter = require('../utils/staticwriter');
var TX = require('../primitives/tx');

/**
 * Represents a mempool entry.
 * @alias module:mempool.MempoolEntry
 * @constructor
 * @param {Object} options
 * @param {TX} options.tx - Transaction in mempool.
 * @param {Number} options.height - Entry height.
 * @param {Number} options.priority - Entry priority.
 * @param {Number} options.ts - Entry time.
 * @param {Amount} options.value - Value of on-chain coins.
 * @property {TX} tx
 * @property {Number} height
 * @property {Number} priority
 * @property {Number} ts
 * @property {Amount} value
 */

function MempoolEntry(options) {
  if (!(this instanceof MempoolEntry))
    return new MempoolEntry(options);

  this.tx = null;
  this.height = -1;
  this.size = 0;
  this.sigops = 0;
  this.priority = 0;
  this.fee = 0;
  this.deltaFee = 0;
  this.ts = 0;
  this.value = 0;
  this.dependencies = false;
  this.descFee = 0;
  this.descSize = 0;

  if (options)
    this.fromOptions(options);
}

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

MempoolEntry.prototype.fromOptions = function fromOptions(options) {
  this.tx = options.tx;
  this.height = options.height;
  this.size = options.size;
  this.sigops = options.sigops;
  this.priority = options.priority;
  this.fee = options.fee;
  this.deltaFee = options.deltaFee;
  this.ts = options.ts;
  this.value = options.value;
  this.dependencies = options.dependencies;
  this.descFee = options.descFee;
  this.descSize = options.descSize;
  return this;
};

/**
 * Instantiate mempool entry from options.
 * @param {Object} options
 * @returns {MempoolEntry}
 */

MempoolEntry.fromOptions = function fromOptions(options) {
  return new MempoolEntry().fromOptions(options);
};

/**
 * Inject properties from transaction.
 * @private
 * @param {TX} tx
 * @param {Number} height
 */

MempoolEntry.prototype.fromTX = function fromTX(tx, view, height) {
  var flags = Script.flags.STANDARD_VERIFY_FLAGS;
  var value = tx.getChainValue(view);
  var sigops = tx.getSigopsCost(view, flags);
  var size = tx.getSigopsSize(sigops);
  var priority = tx.getPriority(view, height, size);
  var fee = tx.getFee(view);
  var dependencies = false;
  var i, input;

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];
    if (view.getHeight(input) === -1) {
      dependencies = true;
      break;
    }
  }

  this.tx = tx;
  this.height = height;
  this.size = size;
  this.sigops = sigops;
  this.priority = priority;
  this.fee = fee;
  this.deltaFee = fee;
  this.ts = util.now();
  this.value = value;
  this.dependencies = dependencies;
  this.descFee = fee;
  this.descSize = size;

  return this;
};

/**
 * Create a mempool entry from a TX.
 * @param {TX} tx
 * @param {Number} height - Entry height.
 * @returns {MempoolEntry}
 */

MempoolEntry.fromTX = function fromTX(tx, view, height) {
  return new MempoolEntry().fromTX(tx, view, height);
};

/**
 * Calculate transaction hash.
 * @param {String?} enc
 * @returns {Hash}
 */

MempoolEntry.prototype.hash = function hash(enc) {
  return this.tx.hash(enc);
};

/**
 * Calculate reverse transaction hash.
 * @returns {Hash}
 */

MempoolEntry.prototype.txid = function txid() {
  return this.tx.txid();
};

/**
 * Calculate priority, taking into account
 * the entry height delta, modified size,
 * and chain value.
 * @param {Number} height
 * @returns {Number} Priority.
 */

MempoolEntry.prototype.getPriority = function getPriority(height) {
  var delta = height - this.height;
  var priority = (delta * this.value) / this.size;
  var result = this.priority + Math.floor(priority);
  if (result < 0)
    result = 0;
  return result;
};

/**
 * Get fee.
 * @returns {Amount}
 */

MempoolEntry.prototype.getFee = function getFee() {
  return this.fee;
};

/**
 * Get delta fee.
 * @returns {Amount}
 */

MempoolEntry.prototype.getDeltaFee = function getDeltaFee() {
  return this.deltaFee;
};

/**
 * Calculate fee rate.
 * @returns {Rate}
 */

MempoolEntry.prototype.getRate = function getRate() {
  return policy.getRate(this.size, this.fee);
};

/**
 * Calculate delta fee rate.
 * @returns {Rate}
 */

MempoolEntry.prototype.getDeltaRate = function getDeltaRate() {
  return policy.getRate(this.size, this.deltaFee);
};

/**
 * Calculate fee cumulative descendant rate.
 * @returns {Rate}
 */

MempoolEntry.prototype.getDescRate = function getDescRate() {
  return policy.getRate(this.descSize, this.descFee);
};

/**
 * Calculate the memory usage of a transaction.
 * Note that this only calculates the JS heap
 * size. Sizes of buffers are ignored (the v8
 * heap is what we care most about). All numbers
 * are based on the output of v8 heap snapshots
 * of TX objects.
 * @returns {Number} Usage in bytes.
 */

MempoolEntry.prototype.memUsage = function memUsage() {
  var tx = this.tx;
  var total = 0;
  var i, j, input, output, op;

  total += 176; // mempool entry
  total += 48; // dependencies

  total += 208; // tx
  total += 80; // _hash
  total += 88; // _hhash
  total += 80; // _raw
  total += 80; // _whash
  total += 48; // mutable

  total += 32; // input array

  for (i = 0; i < tx.inputs.length; i++) {
    input = tx.inputs[i];

    total += 120; // input
    total += 104; // prevout
    total += 88; // prevout hash

    total += 40; // script
    total += 80; // script raw buffer
    total += 32; // script code array
    total += input.script.code.length * 40; // opcodes

    for (j = 0; j < input.script.code.length; j++) {
      op = input.script.code[j];
      if (op.data)
        total += 80; // op buffers
    }

    total += 96; // witness
    total += 32; // witness items
    total += input.witness.items.length * 80; // witness buffers
  }

  total += 32; // output array

  for (i = 0; i < tx.outputs.length; i++) {
    output = tx.outputs[i];

    total += 104; // output
    total += 40; // script
    total += 80; // script raw buffer
    total += 32; // script code array
    total += output.script.code.length * 40; // opcodes

    for (j = 0; j < output.script.code.length; j++) {
      op = output.script.code[j];
      if (op.data)
        total += 80; // op buffers
    }
  }

  return total;
};

/**
 * Test whether the entry is free with
 * the current priority (calculated by
 * current height).
 * @param {Number} height
 * @returns {Boolean}
 */

MempoolEntry.prototype.isFree = function isFree(height) {
  var priority = this.getPriority(height);
  return priority > policy.FREE_THRESHOLD;
};

/**
 * Get entry serialization size.
 * @returns {Number}
 */

MempoolEntry.prototype.getSize = function getSize() {
  return this.tx.getSize() + 41;
};

/**
 * Serialize entry to a buffer.
 * @returns {Buffer}
 */

MempoolEntry.prototype.toRaw = function toRaw() {
  var bw = new StaticWriter(this.getSize());
  bw.writeBytes(this.tx.toRaw());
  bw.writeU32(this.height);
  bw.writeU32(this.size);
  bw.writeU32(this.sigops);
  bw.writeDouble(this.priority);
  bw.writeU64(this.fee);
  bw.writeU32(this.ts);
  bw.writeU64(this.value);
  bw.writeU8(this.dependencies ? 1 : 0);
  return bw.render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 * @returns {MempoolEntry}
 */

MempoolEntry.prototype.fromRaw = function fromRaw(data) {
  var br = new BufferReader(data);
  this.tx = TX.fromReader(br);
  this.height = br.readU32();
  this.size = br.readU32();
  this.sigops = br.readU32();
  this.priority = br.readDouble();
  this.fee = br.readU64();
  this.deltaFee = this.fee;
  this.ts = br.readU32();
  this.value = br.readU64();
  this.dependencies = br.readU8() === 1;
  this.descFee = this.fee;
  this.descSize = this.size;
  return this;
};

/**
 * Instantiate entry from serialized data.
 * @param {Buffer} data
 * @returns {MempoolEntry}
 */

MempoolEntry.fromRaw = function fromRaw(data) {
  return new MempoolEntry().fromRaw(data);
};

/*
 * Expose
 */

module.exports = MempoolEntry;

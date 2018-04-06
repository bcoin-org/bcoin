/*!
 * mempoolentry.js - mempool entry object for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const bio = require('bufio');
const policy = require('../protocol/policy');
const util = require('../utils/util');
const Script = require('../script/script');
const TX = require('../primitives/tx');

/**
 * Mempool Entry
 * Represents a mempool entry.
 * @alias module:mempool.MempoolEntry
 * @property {TX} tx
 * @property {Number} height
 * @property {Number} priority
 * @property {Number} time
 * @property {Amount} value
 */

class MempoolEntry {
  /**
   * Create a mempool entry.
   * @constructor
   * @param {Object} options
   * @param {TX} options.tx - Transaction in mempool.
   * @param {Number} options.height - Entry height.
   * @param {Number} options.priority - Entry priority.
   * @param {Number} options.time - Entry time.
   * @param {Amount} options.value - Value of on-chain coins.
   */

  constructor(options) {
    this.tx = null;
    this.height = -1;
    this.size = 0;
    this.sigops = 0;
    this.priority = 0;
    this.fee = 0;
    this.deltaFee = 0;
    this.time = 0;
    this.value = 0;
    this.coinbase = false;
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

  fromOptions(options) {
    this.tx = options.tx;
    this.height = options.height;
    this.size = options.size;
    this.sigops = options.sigops;
    this.priority = options.priority;
    this.fee = options.fee;
    this.deltaFee = options.deltaFee;
    this.time = options.time;
    this.value = options.value;
    this.coinbase = options.coinbase;
    this.dependencies = options.dependencies;
    this.descFee = options.descFee;
    this.descSize = options.descSize;
    return this;
  }

  /**
   * Instantiate mempool entry from options.
   * @param {Object} options
   * @returns {MempoolEntry}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Inject properties from transaction.
   * @private
   * @param {TX} tx
   * @param {Number} height
   */

  fromTX(tx, view, height) {
    const flags = Script.flags.STANDARD_VERIFY_FLAGS;
    const value = tx.getChainValue(view);
    const sigops = tx.getSigopsCost(view, flags);
    const size = tx.getSigopsSize(sigops);
    const priority = tx.getPriority(view, height, size);
    const fee = tx.getFee(view);

    let dependencies = false;
    let coinbase = false;

    for (const {prevout} of tx.inputs) {
      if (view.isCoinbase(prevout))
        coinbase = true;

      if (view.getHeight(prevout) === -1)
        dependencies = true;
    }

    this.tx = tx;
    this.height = height;
    this.size = size;
    this.sigops = sigops;
    this.priority = priority;
    this.fee = fee;
    this.deltaFee = fee;
    this.time = util.now();
    this.value = value;
    this.coinbase = coinbase;
    this.dependencies = dependencies;
    this.descFee = fee;
    this.descSize = size;

    return this;
  }

  /**
   * Create a mempool entry from a TX.
   * @param {TX} tx
   * @param {Number} height - Entry height.
   * @returns {MempoolEntry}
   */

  static fromTX(tx, view, height) {
    return new this().fromTX(tx, view, height);
  }

  /**
   * Calculate transaction hash.
   * @param {String?} enc
   * @returns {Hash}
   */

  hash(enc) {
    return this.tx.hash(enc);
  }

  /**
   * Calculate reverse transaction hash.
   * @returns {Hash}
   */

  txid() {
    return this.tx.txid();
  }

  /**
   * Calculate priority, taking into account
   * the entry height delta, modified size,
   * and chain value.
   * @param {Number} height
   * @returns {Number} Priority.
   */

  getPriority(height) {
    const delta = height - this.height;
    const priority = (delta * this.value) / this.size;

    let result = this.priority + Math.floor(priority);

    if (result < 0)
      result = 0;

    return result;
  }

  /**
   * Get fee.
   * @returns {Amount}
   */

  getFee() {
    return this.fee;
  }

  /**
   * Get delta fee.
   * @returns {Amount}
   */

  getDeltaFee() {
    return this.deltaFee;
  }

  /**
   * Calculate fee rate.
   * @returns {Rate}
   */

  getRate() {
    return policy.getRate(this.size, this.fee);
  }

  /**
   * Calculate delta fee rate.
   * @returns {Rate}
   */

  getDeltaRate() {
    return policy.getRate(this.size, this.deltaFee);
  }

  /**
   * Calculate fee cumulative descendant rate.
   * @returns {Rate}
   */

  getDescRate() {
    return policy.getRate(this.descSize, this.descFee);
  }

  /**
   * Calculate the memory usage of a transaction.
   * Note that this only calculates the JS heap
   * size. Sizes of buffers are ignored (the v8
   * heap is what we care most about). All numbers
   * are based on the output of v8 heap snapshots
   * of TX objects.
   * @returns {Number} Usage in bytes.
   */

  memUsage() {
    const tx = this.tx;
    let total = 0;

    total += 176; // mempool entry
    total += 48; // coinbase
    total += 48; // dependencies

    total += 208; // tx
    total += 80; // _hash
    total += 88; // _hhash
    total += 80; // _raw
    total += 80; // _whash
    total += 48; // mutable

    total += 32; // input array

    for (const input of tx.inputs) {
      total += 120; // input
      total += 104; // prevout
      total += 88; // prevout hash

      total += 40; // script
      total += 80; // script raw buffer
      total += 32; // script code array
      total += input.script.code.length * 40; // opcodes

      for (const op of input.script.code) {
        if (op.data)
          total += 80; // op buffers
      }

      total += 96; // witness
      total += 32; // witness items
      total += input.witness.items.length * 80; // witness buffers
    }

    total += 32; // output array

    for (const output of tx.outputs) {
      total += 104; // output
      total += 40; // script
      total += 80; // script raw buffer
      total += 32; // script code array
      total += output.script.code.length * 40; // opcodes

      for (const op of output.script.code) {
        if (op.data)
          total += 80; // op buffers
      }
    }

    return total;
  }

  /**
   * Test whether the entry is free with
   * the current priority (calculated by
   * current height).
   * @param {Number} height
   * @returns {Boolean}
   */

  isFree(height) {
    const priority = this.getPriority(height);
    return priority > policy.FREE_THRESHOLD;
  }

  /**
   * Get entry serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.tx.getSize() + 42;
  }

  /**
   * Serialize entry to a buffer.
   * @returns {Buffer}
   */

  toRaw() {
    const bw = bio.write(this.getSize());
    bw.writeBytes(this.tx.toRaw());
    bw.writeU32(this.height);
    bw.writeU32(this.size);
    bw.writeU32(this.sigops);
    bw.writeDouble(this.priority);
    bw.writeU64(this.fee);
    bw.writeU32(this.time);
    bw.writeU64(this.value);
    bw.writeU8(this.coinbase ? 1 : 0);
    bw.writeU8(this.dependencies ? 1 : 0);
    return bw.render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   * @returns {MempoolEntry}
   */

  fromRaw(data) {
    const br = bio.read(data);
    this.tx = TX.fromReader(br);
    this.height = br.readU32();
    this.size = br.readU32();
    this.sigops = br.readU32();
    this.priority = br.readDouble();
    this.fee = br.readU64();
    this.deltaFee = this.fee;
    this.time = br.readU32();
    this.value = br.readU64();
    this.coinbase = br.readU8() === 1;
    this.dependencies = br.readU8() === 1;
    this.descFee = this.fee;
    this.descSize = this.size;
    return this;
  }

  /**
   * Instantiate entry from serialized data.
   * @param {Buffer} data
   * @returns {MempoolEntry}
   */

  static fromRaw(data) {
    return new this().fromRaw(data);
  }
}

/*
 * Expose
 */

module.exports = MempoolEntry;

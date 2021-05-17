/*!
 * struct.js - struct object for bcoin
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const enforce = require('./enforce');
const BufferReader = require('./reader');
const BufferWriter = require('./writer');
const StaticWriter = require('./staticwriter');
const {custom} = require('./custom');

/**
 * Struct
 */

class Struct {
  constructor() {}

  inject(obj) {
    enforce(obj instanceof this.constructor, 'obj', 'struct');
    return this.decode(obj.encode());
  }

  clone() {
    const copy = new this.constructor();
    return copy.inject(this);
  }

  /*
   * Bindable
   */

  getSize(extra) {
    return -1;
  }

  write(bw, extra) {
    return bw;
  }

  read(br, extra) {
    return this;
  }

  toString() {
    return Object.prototype.toString.call(this);
  }

  fromString(str, extra) {
    return this;
  }

  getJSON() {
    return this;
  }

  fromJSON(json, extra) {
    return this;
  }

  fromOptions(options, extra) {
    return this;
  }

  from(options, extra) {
    return this.fromOptions(options, extra);
  }

  format() {
    return this.getJSON();
  }

  /*
   * API
   */

  encode(extra) {
    const size = this.getSize(extra);
    const bw = size === -1
      ? new BufferWriter()
      : new StaticWriter(size);

    this.write(bw, extra);

    return bw.render();
  }

  decode(data, extra) {
    const br = new BufferReader(data);

    this.read(br, extra);

    return this;
  }

  toHex(extra) {
    return this.encode(extra).toString('hex');
  }

  fromHex(str, extra) {
    enforce(typeof str === 'string', 'str', 'string');

    const size = str.length >>> 1;
    const data = Buffer.from(str, 'hex');

    if (data.length !== size)
      throw new Error('Invalid hex string.');

    return this.decode(data, extra);
  }

  toBase64(extra) {
    return this.encode(extra).toString('base64');
  }

  fromBase64(str, extra) {
    enforce(typeof str === 'string', 'str', 'string');

    const data = Buffer.from(str, 'base64');

    if (str.length > size64(data.length))
      throw new Error('Invalid base64 string.');

    return this.decode(data, extra);
  }

  toJSON() {
    return this.getJSON();
  }

  [custom]() {
    return this.format();
  }

  /*
   * Static API
   */

  static read(br, extra) {
    return new this().read(br, extra);
  }

  static decode(data, extra) {
    return new this().decode(data, extra);
  }

  static fromHex(str, extra) {
    return new this().fromHex(str, extra);
  }

  static fromBase64(str, extra) {
    return new this().fromBase64(str, extra);
  }

  static fromString(str, extra) {
    return new this().fromString(str, extra);
  }

  static fromJSON(json, extra) {
    return new this().fromJSON(json, extra);
  }

  static fromOptions(options, extra) {
    return new this().fromOptions(options, extra);
  }

  static from(options, extra) {
    return new this().from(options, extra);
  }

  /*
   * Aliases
   */

  toWriter(bw, extra) {
    return this.write(bw, extra);
  }

  fromReader(br, extra) {
    return this.read(br, extra);
  }

  toRaw(extra) {
    return this.encode(extra);
  }

  fromRaw(data, extra) {
    return this.decode(data, extra);
  }

  /*
   * Static Aliases
   */

  static fromReader(br, extra) {
    return this.read(br, extra);
  }

  static fromRaw(data, extra) {
    return this.decode(data, extra);
  }
}

/*
 * Helpers
 */

function size64(size) {
  const expect = ((4 * size / 3) + 3) & ~3;
  return expect >>> 0;
}

/*
 * Expose
 */

module.exports = Struct;

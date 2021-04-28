'use strict';

const assert = require('bsert');

const types = {
  CONNECT: 0,
  DISCONNECT: 1,
  EVENT: 2,
  ACK: 3,
  ERROR: 4,
  BINARY_EVENT: 5,
  BINARY_ACK: 6
};

class Packet {
  constructor(type) {
    this.type = type || 0;
    this.attachments = 0;
    this.nsp = '/';
    this.id = -1;
    this.data = '';
    this.buffers = [];
  }

  setData(data) {
    assert(data !== undefined);
    assert(typeof data !== 'number');
    assert(typeof data !== 'function');

    const [str, buffers] = deconstruct(data);

    this.data = str;
    this.buffers = buffers;
    this.attachments = buffers.length;

    if (this.attachments > 0) {
      switch (this.type) {
        case types.EVENT:
          this.type = types.BINARY_EVENT;
          break;
        case types.ACK:
          this.type = types.BINARY_ACK;
          break;
      }
    }

    return this;
  }

  getData() {
    if (this.data.length === 0)
      return null;
    return reconstruct(this.data, this.buffers);
  }

  toString() {
    let str = this.type.toString(10);

    switch (this.type) {
      case types.BINARY_EVENT:
      case types.BINARY_ACK:
        str += this.attachments.toString(10) + '-';
        break;
    }

    if (this.nsp !== '/')
      str += this.nsp + ',';

    if (this.id !== -1)
      str += this.id.toString(10);

    str += this.data;

    return str;
  }

  static fromString(str) {
    assert(typeof str === 'string');
    assert(str.length > 0);

    let i = 0;
    let type = 0;
    let attachments = 0;
    let nsp = '/';
    let id = -1;
    let data = '';

    [i, type] = readChar(str, i);

    assert(type !== -1);
    assert(type <= types.BINARY_ACK);

    switch (type) {
      case types.BINARY_EVENT:
      case types.BINARY_ACK: {
        [i, attachments] = readInt(str, i);
        assert(attachments !== -1);
        assert(i < str.length);
        assert(str[i] === '-');
        i += 1;
        break;
      }
    }

    if (i < str.length && str[i] === '/')
      [i, nsp] = readTo(str, i, ',');

    [i, id] = readInt(str, i);

    if (i < str.length)
      data = str.substring(i);

    const packet = new this();

    packet.type = type;
    packet.attachments = attachments;
    packet.nsp = nsp;
    packet.id = id;
    packet.data = data;

    return packet;
  }
}

Packet.types = types;

function isPlaceholder(obj) {
  return obj !== null
    && typeof obj === 'object'
    && obj._placeholder === true
    && (obj.num >>> 0) === obj.num;
}

function deconstruct(obj) {
  const buffers = [];
  const out = replace('', obj, buffers, new Map());
  const str = JSON.stringify(out);
  return [str, buffers];
}

function replace(key, value, buffers, seen) {
  if (value === null || typeof value !== 'object')
    return value;

  if (Buffer.isBuffer(value)) {
    const placeholder = seen.get(value);

    // De-duplicate.
    if (placeholder != null)
      return placeholder;

    const out = { _placeholder: true, num: buffers.length };

    seen.set(value, out);
    buffers.push(value);

    return out;
  }

  if (seen.has(value))
    throw new TypeError('Converting circular structure to JSON.');

  if (Array.isArray(value)) {
    const out = [];

    seen.set(value, null);

    for (let i = 0; i < value.length; i++)
      out.push(replace(i, value[i], buffers, seen));

    seen.delete(value);

    return out;
  }

  const out = Object.create(null);

  const json = typeof value.toJSON === 'function'
    ? value.toJSON(key)
    : value;

  seen.set(value, null);

  for (const key of Object.keys(json))
    out[key] = replace(key, json[key], buffers, seen);

  seen.delete(value);

  return out;
}

function reconstruct(str, buffers) {
  return JSON.parse(str, (key, value) => {
    if (isPlaceholder(value)) {
      if (value.num < buffers.length)
        return buffers[value.num];
    }
    return value;
  });
}

function readChar(str, i) {
  const ch = str.charCodeAt(i) - 0x30;

  if (ch < 0 || ch > 9)
    return -1;

  return [i + 1, ch];
}

function readInt(str, i) {
  let len = 0;
  let num = 0;

  for (; i < str.length; i++) {
    const ch = str.charCodeAt(i) - 0x30;

    if (ch < 0 || ch > 9)
      break;

    num *= 10;
    num += ch;
    len += 1;

    assert(len <= 10);
  }

  assert(num <= 0xffffffff);

  if (len === 0)
    num = -1;

  return [i, num];
}

function readTo(str, i, ch) {
  let j = i;

  for (; j < str.length; j++) {
    if (str[j] === ch)
      break;
  }

  assert(j < str.length);

  return [j + 1, str.substring(i, j)];
}

/*
 * Expose
 */

module.exports = Packet;

'use strict';

const assert = require('bsert');
const DUMMY = Buffer.alloc(0);

const types = {
  OPEN: 0,
  CLOSE: 1,
  PING: 2,
  PONG: 3,
  MESSAGE: 4,
  UPGRADE: 5,
  NOOP: 6
};

const table = [
  'open',
  'close',
  'ping',
  'pong',
  'message',
  'upgrade',
  'noop'
];

class Frame {
  constructor(type, data, binary) {
    assert(typeof type === 'number');
    assert((type >>> 0) === type);
    assert(type <= types.NOOP);
    assert(typeof binary === 'boolean');

    if (binary) {
      if (data == null)
        data = DUMMY;
      assert(Buffer.isBuffer(data));
    } else {
      if (data == null)
        data = '';
      assert(typeof data === 'string');
    }

    this.type = type;
    this.data = data;
    this.binary = binary;
  }

  toString() {
    let str = '';

    if (this.binary) {
      str += 'b';
      str += this.type.toString(10);
      str += this.data.toString('base64');
    } else {
      str += this.type.toString(10);
      str += this.data;
    }

    return str;
  }

  static fromString(str) {
    assert(typeof str === 'string');

    let type = str.charCodeAt(0);
    let binary = false;
    let data;

    // 'b' - base64
    if (type === 0x62) {
      assert(str.length > 1);
      type = str.charCodeAt(1);
      data = Buffer.from(str.substring(2), 'base64');
      binary = true;
    } else {
      data = str.substring(1);
    }

    type -= 0x30;
    assert(type >= 0 && type <= 9);
    assert(type <= types.NOOP);

    return new this(type, data, binary);
  }

  size() {
    let len = 1;

    if (this.binary)
      len += this.data.length;
    else
      len += Buffer.byteLength(this.data, 'utf8');

    return len;
  }

  toRaw() {
    const data = Buffer.allocUnsafe(this.size());

    data[0] = this.type;

    if (this.binary) {
      this.data.copy(data, 1);
    } else {
      if (this.data.length > 0)
        data.write(this.data, 1, 'utf8');
    }

    return data;
  }

  static fromRaw(data) {
    assert(Buffer.isBuffer(data));
    assert(data.length > 0);

    const type = data[0];
    assert(type <= types.NOOP);

    return new this(type, data.slice(1), true);
  }
}

Frame.types = types;
Frame.table = table;

module.exports = Frame;

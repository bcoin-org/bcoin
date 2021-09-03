'use strict';

const assert = require('bsert');
const crypto = require('crypto');
const python = require('./python');
const GOST94 = require('../../lib/gost94');
const Keccak224 = require('../../lib/keccak224');
const Keccak256 = require('../../lib/keccak256');
const Keccak384 = require('../../lib/keccak384');
const Keccak512 = require('../../lib/keccak512');
const MD2 = require('../../lib/md2');

class Hash160 {
  constructor() {
    this.ctx = crypto.createHash('sha256');
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this.ctx.update(data);
    return this;
  }

  digest() {
    const ctx = crypto.createHash('ripemd160');
    ctx.update(this.ctx.digest());
    return ctx.digest();
  }
}

class Hash256 {
  constructor() {
    this.ctx = crypto.createHash('sha256');
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this.ctx.update(data);
    return this;
  }

  digest() {
    const ctx = crypto.createHash('sha256');
    ctx.update(this.ctx.digest());
    return ctx.digest();
  }
}

class PythonHash {
  constructor(name, ...args) {
    assert(typeof name === 'string');
    this.name = name;
    this.args = args;
    this.buffer = [];
  }

  update(data) {
    assert(Buffer.isBuffer(data));
    this.buffer.push(Buffer.from(data));
    return this;
  }

  digest() {
    const data = Buffer.concat(this.buffer);
    this.buffer.length = 0;
    return python[this.name](data, ...this.args);
  }
}

class BcryptoHash {
  constructor(Hash, ...args) {
    assert(typeof Hash === 'function');
    this.ctx = new Hash();
    this.ctx.init(...args);
  }

  update(data) {
    this.ctx.update(data);
    return this;
  }

  digest() {
    return this.ctx.final();
  }
}

class HMAC {
  constructor(name, size, key) {
    assert(typeof name === 'string');
    this.inner = createHash(name);
    this.outer = createHash(name);
    this.init(name, size, key);
  }

  init(name, size, key) {
    assert(typeof name === 'string');
    assert((size >>> 0) === size);
    assert(Buffer.isBuffer(key));

    if (key.length > size) {
      const h = createHash(name);

      h.update(key);

      key = h.digest();

      assert(key.length <= size);
    }

    const pad = Buffer.alloc(size);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x36;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x36;

    this.inner.update(pad);

    for (let i = 0; i < key.length; i++)
      pad[i] = key[i] ^ 0x5c;

    for (let i = key.length; i < pad.length; i++)
      pad[i] = 0x5c;

    this.outer.update(pad);

    return this;
  }

  update(data) {
    this.inner.update(data);
    return this;
  }

  digest() {
    this.outer.update(this.inner.digest());
    return this.outer.digest();
  }
}

function createHash(name, key) {
  assert(typeof name === 'string');
  assert(key == null || Buffer.isBuffer(key));

  name = name.toLowerCase();

  if (name === 'blake2b160')
    return new PythonHash('blake2b', 20, key);

  if (name === 'blake2b256')
    return new PythonHash('blake2b', 32, key);

  if (name === 'blake2b384')
    return new PythonHash('blake2b', 48, key);

  if (name === 'blake2b512' && key != null)
    return new PythonHash('blake2b', 64, key);

  if (name === 'blake2s128')
    return new PythonHash('blake2s', 16, key);

  if (name === 'blake2s160')
    return new PythonHash('blake2s', 20, key);

  if (name === 'blake2s224')
    return new PythonHash('blake2s', 28, key);

  if (name === 'blake2s256' && key != null)
    return new PythonHash('blake2s', 32, key);

  if (name === 'gost94')
    return new BcryptoHash(GOST94);

  if (name === 'hash160')
    return new Hash160();

  if (name === 'hash256')
    return new Hash256();

  if (name === 'keccak224')
    return new BcryptoHash(Keccak224);

  if (name === 'keccak256')
    return new BcryptoHash(Keccak256);

  if (name === 'keccak384')
    return new BcryptoHash(Keccak384);

  if (name === 'keccak512')
    return new BcryptoHash(Keccak512);

  if (name === 'md2')
    return new BcryptoHash(MD2);

  return crypto.createHash(name);
}

function createHmac(name, key) {
  assert(typeof name === 'string');
  assert(Buffer.isBuffer(key));

  name = name.toLowerCase();

  if (name === 'blake2b160'
      || name === 'blake2b256'
      || name === 'blake2b384') {
    return new HMAC(name, 128, key);
  }

  if (name === 'blake2s128'
      || name === 'blake2s160'
      || name === 'blake2s224') {
    return new HMAC(name, 64, key);
  }

  if (name === 'gost94')
    return new HMAC(name, 32, key);

  if (name === 'hash160')
    return new HMAC(name, 64, key);

  if (name === 'hash256')
    return new HMAC(name, 64, key);

  if (name === 'keccak224')
    return new HMAC(name, 144, key);

  if (name === 'keccak256')
    return new HMAC(name, 136, key);

  if (name === 'keccak384')
    return new HMAC(name, 104, key);

  if (name === 'keccak512')
    return new HMAC(name, 72, key);

  if (name === 'md2')
    return new HMAC(name, 16, key);

  return crypto.createHmac(name, key);
}

exports.createHash = createHash;
exports.createHmac = createHmac;

/*!
 * pem.js - PEM for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
 *   https://tools.ietf.org/html/rfc1421
 *   https://tools.ietf.org/html/rfc1422
 *   https://tools.ietf.org/html/rfc1423
 *   https://tools.ietf.org/html/rfc1424
 *   https://tools.ietf.org/html/rfc4880
 *   https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
 *   https://github.com/crypto-browserify/EVP_BytesToKey/blob/master/index.js
 *   https://github.com/openssl/openssl/blob/master/include/openssl/pem.h
 *   https://github.com/openssl/openssl/blob/master/crypto/pem/pem_lib.c
 *   https://github.com/openssl/openssl/blob/master/crypto/evp/evp_key.c
 *   https://github.com/openssl/openssl/blob/master/crypto/pem/pem_pkey.c
 */

/* eslint spaced-comment: "off" */

'use strict';

const assert = require('../internal/assert');
const base64 = require('./base64');
const lines = require('./lines');

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);

/**
 * PEMBlock
 */

class PEMBlock {
  constructor(type, data) {
    if (type == null)
      type = 'PRIVACY-ENHANCED MESSAGE';

    if (data == null)
      data = EMPTY;

    assert(typeof type === 'string');
    assert(Buffer.isBuffer(data));

    this.type = type;
    this.headers = new Map();
    this.data = data;
  }

  toString(armor) {
    return encode(this.type, this.headers, this.data, armor);
  }

  fromString(str, armor) {
    const iter = decode(str, armor);
    const it = iter.next();

    if (it.done)
      throw new Error('No PEM data found.');

    const block = it.value;

    this.type = block.type;
    this.headers = block.headers;
    this.data = block.data;

    return this;
  }

  getProcType() {
    const hdr = this.headers.get('Proc-Type');

    if (!hdr)
      return null;

    return ProcType.fromString(hdr);
  }

  setProcType(version, state) {
    assert(version != null && state);
    const proc = new ProcType(version, state);
    this.headers.set('Proc-Type', proc.toString());
    return this;
  }

  unsetProcType() {
    this.headers.delete('Proc-Type');
    return this;
  }

  getDEKInfo() {
    const hdr = this.headers.get('DEK-Info');

    if (!hdr)
      return null;

    return DEKInfo.fromString(hdr);
  }

  setDEKInfo(name, iv) {
    assert(name);
    const info = new DEKInfo(name, iv);
    this.headers.set('DEK-Info', info.toString());
    return this;
  }

  unsetDEKInfo() {
    this.headers.delete('DEK-Info');
    return this;
  }

  isEncrypted() {
    let type;

    try {
      type = this.getProcType();
    } catch (e) {
      return false;
    }

    if (!type)
      return false;

    return type.version === 4
        && type.state === 'ENCRYPTED';
  }

  static fromString(str, armor) {
    return new this().fromString(str, armor);
  }
}

/**
 * ProcType
 */

class ProcType {
  constructor(version, state) {
    if (version == null)
      version = 0;

    if (state == null)
      state = 'NONE';

    assert((version >>> 0) === version);
    assert(typeof state === 'string');

    this.version = version;
    this.state = state.toUpperCase();
  }

  toString() {
    return `${this.version},${this.state}`;
  }

  fromString(str) {
    assert(typeof str === 'string');

    const parts = str.split(',', 3);

    if (parts.length !== 2)
      throw new Error('Invalid Proc-Type.');

    this.version = parseU32(parts[0]);
    this.state = parts[1].toUpperCase();

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }
}

/**
 * DEKInfo
 */

class DEKInfo {
  constructor(name, iv) {
    if (name == null)
      name = 'AES-128-ECB';

    if (iv == null)
      iv = EMPTY;

    assert(typeof name === 'string');
    assert(Buffer.isBuffer(iv));

    this.name = name.toUpperCase();
    this.iv = iv;
  }

  toString() {
    const name = this.name;

    if (this.iv.length === 0)
      return name;

    const iv = this.iv.toString('hex');

    return `${name},${iv.toUpperCase()}`;
  }

  fromString(str) {
    assert(typeof str === 'string');

    const parts = str.split(',', 3);

    if (parts.length < 1 || parts.length > 2)
      throw new Error('Invalid DEK-Info.');

    const name = parts[0];

    if (name.length === 0)
      throw new Error('Invalid DEK-Info name.');

    this.name = name.toUpperCase();
    this.iv = EMPTY;

    if (parts.length > 1) {
      const hex = parts[1];
      const iv = Buffer.from(hex, 'hex');

      if (iv.length !== (hex.length >>> 1))
        throw new Error('Invalid DEK-Info IV.');

      this.iv = iv;
    }

    return this;
  }

  static fromString(str) {
    return new this().fromString(str);
  }
}

/*
 * PEM
 */

function encode(type, headers, data, armor = false) {
  assert(typeof type === 'string');
  assert(headers instanceof Map);
  assert(Buffer.isBuffer(data));
  assert(typeof armor === 'boolean');

  let str = '';

  str += `-----BEGIN ${type}-----\n`;

  if (headers.size > 0) {
    for (const [key, value] of headers)
      str += `${key}: ${value}\n`;

    str += '\n';
  }

  const s = base64.encode(data);

  for (let i = 0; i < s.length; i += 64)
    str += s.substring(i, i + 64) + '\n';

  if (armor) {
    const crc = crc24(data);

    str += `=${base64.encode(crc)}\n`;
  }

  str += `-----END ${type}-----\n`;

  return str;
}

function *decode(str, armor = false) {
  assert(typeof str === 'string');
  assert(typeof armor === 'boolean');

  let chunk = '';
  let block = null;
  let crc = null;

  for (const [, line] of lines(str)) {
    const index = line.indexOf(':');

    if (index !== -1) {
      if (!block)
        throw new Error('PEM parse error (misplaced header).');

      const key = line.substring(0, index).trim();
      const value = line.substring(index + 1).trim();

      block.headers.set(key, value);

      continue;
    }

    if (line.length >= 15 && line.substring(0, 5) === '-----') {
      if (line.slice(-5) !== '-----')
        throw new Error('PEM parse error (invalid preamble).');

      const preamble = line.slice(5, -5);

      if (preamble.substring(0, 6) === 'BEGIN ') {
        if (block)
          throw new Error('PEM parse error (un-ended block).');

        const type = preamble.substring(6).trim();

        block = new PEMBlock();
        block.type = type;

        continue;
      }

      if (preamble.substring(0, 4) === 'END ') {
        if (!block)
          throw new Error('PEM parse error (unexpected end).');

        const type = preamble.substring(4).trim();

        if (block.type !== type)
          throw new Error('PEM parse error (type mismatch).');

        block.data = base64.decode(chunk);

        if (crc && !crc24(block.data).equals(crc))
          throw new Error('PEM parse error (invalid armor checksum).');

        yield block;

        chunk = '';
        block = null;
        crc = null;

        continue;
      }

      throw new Error('PEM parse error (unknown preamble).');
    }

    if (!block)
      throw new Error('PEM parse error (unexpected data).');

    if (line.length === 5 && line.charCodeAt(0) === 0x3d /*'='*/) {
      if (!armor)
        continue;

      if (crc)
        throw new Error('PEM parse error (unexpected armor checksum).');

      crc = base64.decode(line.substring(1));

      continue;
    }

    if (line.length > 96)
      throw new Error('PEM parse error (line too long).');

    chunk += line.replace(/[\t\v ]/g, '');
  }

  if (block || crc)
    throw new Error('PEM parse error (un-ended block).');

  if (chunk.length !== 0)
    throw new Error('PEM parse error (trailing data).');
}

function toPEM(data, type, armor) {
  assert(Buffer.isBuffer(data));
  assert(typeof type === 'string');

  const block = new PEMBlock();
  block.type = type;
  block.data = data;

  return block.toString(armor);
}

function fromPEM(str, type, armor) {
  assert(typeof str === 'string');
  assert(typeof type === 'string');

  const block = PEMBlock.fromString(str, armor);

  if (block.type !== type)
    throw new Error('PEM type mismatch.');

  return block.data;
}

/*
 * Helpers
 */

function crc24(data) {
  assert(Buffer.isBuffer(data));

  let crc = 0xb704ce;

  for (let i = 0; i < data.length; i++) {
    const ch = data[i];

    crc ^= ch << 16;

    for (let j = 0; j < 8; j++) {
      crc <<= 1;

      if (crc & 0x1000000)
        crc ^= 0x1864cfb;
    }
  }

  crc &= 0xffffff;

  const buf = Buffer.alloc(3);

  buf[2] = crc;
  crc >>>= 8;
  buf[1] = crc;
  crc >>>= 8;
  buf[0] = crc;

  return buf;
}

function parseU32(str) {
  assert(typeof str === 'string');

  if (str.length < 1 || str.length > 10)
    throw new Error('Invalid integer.');

  let word = 0;

  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch < 0x30 || ch > 0x39)
      throw new Error('Invalid integer.');

    word *= 10;
    word += ch - 0x30;

    if (i > 0 && word === 0)
      throw new Error('Invalid integer.');

    if (word > 0xffffffff)
      throw new Error('Invalid integer.');
  }

  return word;
}

/*
 * Expose
 */

exports.PEMBlock = PEMBlock;
exports.ProcType = ProcType;
exports.DEKInfo = DEKInfo;
exports.encode = encode;
exports.decode = decode;
exports.toPEM = toPEM;
exports.fromPEM = fromPEM;

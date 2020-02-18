/*!
 * asn1-mini.js - miniature asn1 implementation for bcrypto
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const EOF = -1;
const INT = 0x02;
const BIT = 0x03;
const OCT = 0x04;
const NULL = 0x05;
const OID = 0x06;
const SEQ = 0x30;

const DSA_OID = Buffer.from('2a8648ce380401', 'hex');
const RSA_OID = Buffer.from('2a864886f70d010101', 'hex');
const ECDSA_OID = Buffer.from('2a8648ce3d0201', 'hex');
const EDDSA_OID = Buffer.from('2b06010401da47040c01', 'hex');

const EMPTY = Buffer.alloc(0);
const ZERO = Buffer.alloc(1, 0x00);

/*
 * Encoding
 */

function encodeSEC1(pki) {
  assert(pki && typeof pki === 'object');

  const items = [
    encodeByte(pki.version),
    encodeOct(pki.key)
  ];

  if (pki.oid)
    items.push(encodeExplicit(encodeOID(pki.oid), 0));

  if (pki.pub)
    items.push(encodeExplicit(encodeBit(pki.pub), 1));

  return encodeSeq(items);
}

function encodePKCS8(pki) {
  assert(pki && typeof pki === 'object');
  return encodeSeq([
    encodeByte(pki.version),
    encodeAlgorithm(pki.algorithm),
    encodeOct(pki.key)
  ]);
}

function encodeSPKI(spki) {
  assert(spki && typeof spki === 'object');
  return encodeSeq([
    encodeAlgorithm(spki.algorithm),
    encodeBit(spki.key)
  ]);
}

function encodeAlgorithm(algorithm) {
  assert(algorithm && typeof algorithm === 'object');

  let params = EMPTY;

  if (algorithm.type !== NULL)
    params = encodeNode(algorithm.params, algorithm.type);

  return encodeSeq([
    encodeOID(algorithm.oid),
    params
  ]);
}

function encodeParams(p, q, g) {
  return Buffer.concat([
    encodeInt(p),
    encodeInt(q),
    encodeInt(g)
  ]);
}

function encodeInt(data) {
  assert(Buffer.isBuffer(data));

  if (data.length === 0)
    data = ZERO;

  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0x00)
      break;
  }

  if (i === data.length)
    return encodeNode(ZERO, INT);

  data = data.slice(i);

  if (data[0] & 0x80)
    data = Buffer.concat([ZERO, data]);

  return encodeNode(data, INT);
}

function encodeByte(num) {
  assert((num & 0xff) === num);
  return encodeInt(Buffer.from([num]));
}

function encodeBit(data) {
  assert(Buffer.isBuffer(data));
  return encodeNode(Buffer.concat([ZERO, data]), BIT);
}

function encodeOct(data) {
  return encodeNode(data, OCT);
}

function encodeOID(data) {
  return encodeNode(data, OID);
}

function encodeSeq(items) {
  assert(Array.isArray(items));
  return encodeNode(Buffer.concat(items), SEQ);
}

function encodeNode(data, type) {
  assert(Buffer.isBuffer(data));
  assert((type & 0xff) === type);

  let size = 0;
  let bytes = 0;

  size += 1;
  size += 1;

  if (data.length >= 0x80) {
    let len = data.length;

    while (len) {
      size += 1;
      bytes += 1;
      len >>>= 8;
    }
  }

  size += data.length;

  const out = Buffer.allocUnsafe(size);

  let pos = 0;

  out[pos] = type;
  pos += 1;

  if (bytes) {
    out[pos] = 0x80 | bytes;
    pos += 1;

    let len = data.length;

    for (let i = bytes - 1; i >= 0; i--) {
      out[pos + i] = len;
      len >>>= 8;
    }

    pos += bytes;
  } else {
    out[pos] = data.length;
    pos += 1;
  }

  data.copy(out, pos);

  return out;
}

function encodeExplicit(data, type) {
  assert((type & 0xff) === type);
  return encodeNode(data, 0xa0 | type);
}

/*
 * Decoding
 */

function decodeSEC1(raw) {
  return readSEC1(raw, 0)[0];
}

function decodePKCS8(raw) {
  return readPKCS8(raw, 0)[0];
}

function decodeSPKI(raw) {
  return readSPKI(raw, 0)[0];
}

function decodeAlgorithm(raw) {
  return readAlgorithm(raw, 0)[0];
}

function decodeParams(raw) {
  return readParams(raw, 0)[0];
}

function decodeInt(raw) {
  return readInt(raw, 0)[0];
}

function decodeOct(raw) {
  return readOct(raw, 0)[0];
}

function readSEC1(raw, pos) {
  [raw, pos] = readSeq(raw, pos);

  const end = pos;

  pos = 0;

  let version, key, oidr, pubr;

  let oid = null;
  let pub = null;

  [version, pos] = readByte(raw, pos);
  [key, pos] = readOct(raw, pos);
  [oidr, pos] = readExplicit(raw, pos, 0);

  if (oidr) {
    try {
      [oid] = readOID(oidr, 0);
    } catch (e) {
      ;
    }
  }

  [pubr, pos] = readExplicit(raw, pos, 1);

  if (pubr)
    [pub] = readBit(pubr, 0);

  return [{ version, key, oid, pub }, end];
}

function readPKCS8(raw, pos) {
  [raw, pos] = readSeq(raw, pos);

  const end = pos;

  pos = 0;

  let version, algorithm, key;

  [version, pos] = readByte(raw, pos);
  [algorithm, pos] = readAlgorithm(raw, pos);
  [key, pos] = readOct(raw, pos);

  return [{ version, algorithm, key }, end];
}

function readSPKI(raw, pos) {
  [raw, pos] = readSeq(raw, pos);

  const end = pos;

  pos = 0;

  let algorithm, key;

  [algorithm, pos] = readAlgorithm(raw, pos);
  [key, pos] = readBit(raw, pos);

  return [{ algorithm, key }, end];
}

function readAlgorithm(raw, pos) {
  [raw, pos] = readSeq(raw, pos);

  const end = pos;

  pos = 0;

  let oid;

  [oid, pos] = readOID(raw, pos);

  let type = pos < raw.length ? raw[pos] : EOF;
  let params = EMPTY;

  switch (type) {
    case EOF:
      type = NULL;
      break;
    case NULL:
      pos += 1;
      assert(pos < raw.length);
      assert(raw[pos] === 0x00);
      break;
    default:
      [params] = readNode(raw, pos, type);
      break;
  }

  return [{ oid, type, params }, end];
}

function readParams(raw, pos) {
  let p, q, g;

  [p, pos] = readInt(raw, pos);
  [q, pos] = readInt(raw, pos);
  [g, pos] = readInt(raw, pos);

  return [[p, q, g], pos];
}

function readInt(data, pos) {
  [data, pos] = readNode(data, pos, INT);

  assert(data.length > 0);

  let i = 0;

  for (; i < data.length; i++) {
    if (data[i] !== 0x00)
      break;
  }

  if (i === data.length)
    return [ZERO, pos];

  if (i === 0 && (data[0] & 0x80))
    throw new Error('Integer is negative.');

  return [data.slice(i), pos];
}

function readByte(data, pos) {
  [data, pos] = readInt(data, pos);
  assert(data.length === 1);
  return [data[0], pos];
}

function readBit(data, pos) {
  [data, pos] = readNode(data, pos, BIT);

  assert(data.length > 0);
  assert(data[0] === 0x00);

  return [data.slice(1), pos];
}

function readOct(data, pos) {
  return readNode(data, pos, OCT);
}

function readOID(data, pos) {
  return readNode(data, pos, OID);
}

function readSeq(data, pos) {
  return readNode(data, pos, SEQ);
}

function readNode(data, pos, type) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(pos < data.length);
  assert((type & 0xff) === type);

  assert(data[pos] === type);
  pos += 1;

  let len;
  [len, pos] = readSize(data, pos);

  assert(pos + len <= data.length);

  const body = data.slice(pos, pos + len);

  pos += len;

  return [body, pos];
}

function readExplicit(data, pos, type) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(pos < data.length);
  assert((type & 0xff) === type);

  try {
    return readNode(data, pos, 0xa0 | type);
  } catch (e) {
    return [null, pos];
  }
}

function readSize(data, pos) {
  assert(Buffer.isBuffer(data));
  assert((pos >>> 0) === pos);
  assert(pos < data.length);

  const field = data[pos];
  const bytes = field & 0x7f;

  pos += 1;

  // Definite form
  if ((field & 0x80) === 0) {
    // Short form
    return [bytes, pos];
  }

  // Indefinite form.
  if (bytes === 0)
    throw new Error('Indefinite length.');

  let len = 0;

  for (let i = 0; i < bytes; i++) {
    assert(pos < data.length);

    const ch = data[pos];

    pos += 1;

    if (len >= (1 << 23))
      throw new Error('Length too large.');

    len *= 0x100;
    len += ch;

    if (len === 0)
      throw new Error('Unexpected leading zeroes.');
  }

  if (len < 0x80)
    throw new Error('Non-minimal length.');

  return [len, pos];
}

// Make eslint happy.
readExplicit;

/*
 * Expose
 */

exports.INT = INT;
exports.BIT = BIT;
exports.OCT = OCT;
exports.NULL = NULL;
exports.OID = OID;
exports.SEQ = SEQ;

exports.DSA_OID = DSA_OID;
exports.RSA_OID = RSA_OID;
exports.ECDSA_OID = ECDSA_OID;
exports.EDDSA_OID = EDDSA_OID;

exports.encodeSEC1 = encodeSEC1;
exports.encodePKCS8 = encodePKCS8;
exports.encodeSPKI = encodeSPKI;
exports.encodeAlgorithm = encodeAlgorithm;
exports.encodeParams = encodeParams;
exports.encodeInt = encodeInt;
exports.encodeOct = encodeOct;
exports.decodeSEC1 = decodeSEC1;
exports.decodePKCS8 = decodePKCS8;
exports.decodeSPKI = decodeSPKI;
exports.decodeAlgorithm = decodeAlgorithm;
exports.decodeParams = decodeParams;
exports.decodeInt = decodeInt;
exports.decodeOct = decodeOct;

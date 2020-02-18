/*!
 * ip.js - ip utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on node-ip.
 * https://github.com/indutny/node-ip
 * Copyright (c) 2012, Fedor Indutny (MIT License).
 */

/* eslint no-unreachable: "off" */
/* eslint spaced-comment: "off" */

'use strict';

const assert = require('bsert');
const os = require('os');
const base32 = require('bs32');
const inet = require('./inet');
const onion = require('./onion');
const binet = exports;

/*
 * Constants
 */

const ZERO_IP = Buffer.from('00000000000000000000000000000000', 'hex');
const LOCAL_IP = Buffer.from('00000000000000000000000000000001', 'hex');
const RFC6052 = Buffer.from('0064ff9b0000000000000000', 'hex');
const RFC4862 = Buffer.from('fe80000000000000', 'hex');
const RFC6145 = Buffer.from('0000000000000000ffff0000', 'hex');
const SHIFTED = Buffer.from('00000000000000ffff', 'hex');
const TOR_ONION = Buffer.from('fd87d87eeb43', 'hex');
const ZERO_KEY = Buffer.alloc(33, 0x00);
const POOL = Buffer.alloc(16, 0x00);
const POOLX = Buffer.alloc(16, 0x00);
const POOLY = Buffer.alloc(16, 0x00);

const ALL = 0;
const LOCAL = 1;
const NONLOCAL = 2;
const PRIVATE = 3;
const PUBLIC = 4;

/**
 * Address types.
 * @enum {Number}
 */

const types = {
  NONE: 0,
  INET4: 4,
  INET6: 6,
  ONION: 10
};

/**
 * Address networks.
 * @enum {Number}
 */

const networks = {
  NONE: 0,
  INET4: 1,
  INET6: 2,
  ONION: 3,
  TEREDO: 4
};

/**
 * Convert a buffer to an ip string.
 * @param {Buffer} raw
 * @returns {String}
 */

binet.encode = function encode(raw) {
  assert(Buffer.isBuffer(raw));
  return binet.read(raw, 0, raw.length);
};

/**
 * Parse an IP string and return a buffer.
 * @param {String} str
 * @returns {Buffer}
 */

binet.decode = function decode(str) {
  const raw = Buffer.allocUnsafe(16);
  binet.write(raw, str, 0, 16);
  return raw;
};

/**
 * Read an IP string from a buffer.
 * @param {Buffer} raw
 * @param {Number} [off=0]
 * @param {Number} [size=16]
 * @returns {String}
 */

binet.read = function read(raw, off, size) {
  if (off == null)
    off = 0;

  if (size == null)
    size = 16;

  assert(Buffer.isBuffer(raw));
  assert((off >>> 0) === off);
  assert((size >>> 0) === size);

  if (off + size > raw.length)
    throw new Error('Out of bounds read.');

  if (size === 4) {
    const str = inet.ntop4(raw, off);

    if (!str)
      throw new Error('Invalid IPv4 address.');

    return str;
  }

  if (size === 16) {
    if (inet.onion(raw, off)) {
      const on = raw.slice(off + 6, off + 16);
      const str = onion.encodeLegacy(on);
      return str;
    }

    let str;

    if (inet.mapped(raw, off))
      str = inet.ntop4(raw, off + 12);
    else
      str = inet.ntop6(raw, off);

    if (!str)
      throw new Error('Invalid IPv6 address.');

    return str;
  }

  throw new Error('Invalid IP address.');
};

/**
 * Write an IP string to a buffer.
 * @param {Buffer} dst
 * @param {String} str
 * @param {Number} [off=0]
 * @param {Number} [size=16]
 * @returns {Number}
 */

binet.write = function write(dst, str, off, size) {
  if (off == null)
    off = 0;

  if (size == null)
    size = 16;

  assert(Buffer.isBuffer(dst));
  assert(typeof str === 'string');
  assert((off >>> 0) === off);
  assert((size >>> 0) === size);

  if (off + size > dst.length)
    throw new Error('Out of bounds write.');

  if (size === 4) {
    if (inet.pton4(str, dst, off) >= 0)
      return off + 4;

    const raw = POOL;

    if (inet.pton6(str, raw, 0) < 0)
      throw new Error('Invalid IPv4 address.');

    if (!inet.mapped(raw, 0))
      throw new Error('Out of bounds write.');

    off += raw.copy(dst, off, 12, 16);

    return off;
  }

  if (size === 16) {
    if (onion.isLegacyString(str)) {
      const prefix = TOR_ONION;
      const data = onion.decodeLegacy(str);

      off += prefix.copy(dst, off);
      off += data.copy(dst, off);

      return off;
    }

    if (inet.pton4(str, dst, off + 12) >= 0) {
      dst.fill(0x00, off, off + 10);
      off += 10;
      dst[off++] = 0xff;
      dst[off++] = 0xff;
      return off;
    }

    if (inet.pton6(str, dst, off) >= 0)
      return off + 16;

    throw new Error('Invalid IPv6 address.');
  }

  throw new Error('Invalid IP address.');
};

/**
 * Write an IP string to a buffer writer.
 * @param {BufferWriter} bw
 * @param {String} str
 * @param {Number} [size=16]
 * @returns {BufferWriter}
 */

binet.writeBW = function writeBW(bw, str, size) {
  assert(bw && typeof bw === 'object');
  bw.offset = binet.write(bw.data, str, bw.offset, size);
  return bw;
};

/**
 * Read an IP string from a buffer reader.
 * @param {BufferReader} br
 * @param {Number} [size=16]
 * @returns {String}
 */

binet.readBR = function readBR(br, size) {
  if (size == null)
    size = 16;

  assert(br && typeof br === 'object');

  const str = binet.read(br.data, br.offset, size);

  br.offset += size;

  return str;
};

/**
 * Normalize an ip.
 * @param {String} str
 * @returns {String}
 */

binet.normalize = function normalize(str) {
  if (onion.isLegacyString(str))
    return onion.normalizeLegacy(str);

  const raw = POOL;

  if (inet.pton4(str, raw, 0) >= 0)
    return inet.ntop4(raw, 0);

  if (inet.pton6(str, raw, 0) >= 0) {
    if (binet.isMapped(raw))
      return inet.ntop4(raw, 12);
    return inet.ntop6(raw, 0);
  }

  throw new Error('Invalid IP address.');
};

/**
 * Convert 4 byte ip address
 * to IPv4 mapped IPv6 address.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

binet.map = function map(raw) {
  assert(Buffer.isBuffer(raw));

  if (raw.length === 16)
    return raw;

  if (raw.length !== 4)
    throw new Error('Not an IPv4 address.');

  const data = Buffer.allocUnsafe(16);

  data.fill(0x00, 0, 10);

  data[10] = 0xff;
  data[11] = 0xff;

  raw.copy(data, 12);

  return data;
};

/**
 * Convert 16 byte ip address
 * from a IPv4 mapped IPv6 address.
 * @param {Buffer} raw
 * @returns {Buffer}
 */

binet.unmap = function unmap(raw) {
  assert(Buffer.isBuffer(raw));

  if (raw.length === 4)
    return raw;

  if (raw.length !== 16)
    throw new Error('Not an IPv6 address.');

  if (!binet.isMapped(raw))
    throw new Error('Not an IPv4 mapped address.');

  return raw.slice(12, 16);
};

/**
 * Concatenate a host and port.
 * @param {String} host
 * @param {Number} port
 * @param {Buffer|null} key
 * @returns {String}
 */

binet.toHost = function toHost(host, port, key) {
  if (key == null)
    key = null;

  assert(typeof host === 'string');
  assert((port & 0xffff) === port);
  assert(key === null || Buffer.isBuffer(key));
  assert(!key || key.length === 33);

  if (host.length === 0)
    throw new Error('Invalid host (zero length).');

  if (host.length > 255 + 1 + 5)
    throw new Error('Invalid host (too large).');

  let colon = false;

  for (let i = 0; i < host.length; i++) {
    const ch = host.charCodeAt(i);

    switch (ch) {
      case 0x3a /*:*/:
        colon = true;
        break;
      case 0x40 /*@*/:
      case 0x5b /*[*/:
      case 0x5d /*]*/:
        throw new Error('Bad host.');
      default:
        if (ch < 0x20 || ch > 0x7e)
          throw new Error('Bad host.');
        break;
    }
  }

  if (colon) {
    if (inet.pton6(host, null, 0) < 0)
      throw new Error('Unexpected colon.');
  }

  const type = binet.getTypeString(host);

  if (type !== types.NONE)
    host = binet.normalize(host);

  let prefix = '';

  if (key && !key.equals(ZERO_KEY))
    prefix = `${base32.encode(key)}@`;

  if (type === types.INET6)
    return `${prefix}[${host}]:${port}`;

  return `${prefix}${host}:${port}`;
};

/**
 * Parse a hostname.
 * @param {String} addr
 * @param {Number?} fport - Fallback port.
 * @param {Buffer?} fkey - Fallback key.
 * @returns {Object} Contains `host`, `port`, and `type`.
 */

binet.fromHost = function fromHost(addr, fport, fkey) {
  if (fport == null)
    fport = 0;

  if (fkey == null)
    fkey = null;

  assert(typeof addr === 'string');
  assert((fport & 0xffff) === fport);
  assert(fkey === null || Buffer.isBuffer(fkey));

  if (addr.length === 0)
    throw new Error('Invalid host (zero length).');

  if (addr.length > 53 + 1 + 255 + 1 + 5)
    throw new Error('Invalid host (too large).');

  if (fkey && fkey.length !== 33)
    throw new Error('Invalid fallback key (bad size).');

  let key = fkey;
  let host = '';
  let port = null;
  let inet6 = false;

  const at = addr.indexOf('@');

  if (at !== -1) {
    const front = addr.substring(0, at);
    const back = addr.substring(at + 1);

    if (front.length > 53)
      throw new Error('Invalid identity key (too large).');

    key = base32.decode(front);

    if (key.length !== 33)
      throw new Error('Invalid identity key (bad size).');

    addr = back;
  }

  if (addr[0] === '[') {
    if (addr[addr.length - 1] === ']') {
      // Case:
      // [::1]
      host = addr.slice(1, -1);
      port = null;
      inet6 = true;
    } else {
      // Case:
      // [::1]:80
      const colon = addr.indexOf(']:');

      if (colon === -1)
        throw new Error('IPv6 bracket mismatch.');

      host = addr.substring(1, colon);
      port = addr.substring(colon + 2);
      inet6 = true;
    }
  } else {
    const colon = addr.indexOf(':');

    if (colon !== -1) {
      const front = addr.substring(0, colon);
      const back = addr.substring(colon + 1);

      if (back.indexOf(':') !== -1) {
        // Case:
        // ::1
        host = addr;
        port = null;
        inet6 = true;
      } else {
        // Cases:
        // 127.0.0.1:80
        // localhost:80
        host = front;
        port = back;
      }
    } else {
      // Cases:
      // 127.0.0.1
      // localhost
      host = addr;
      port = null;
    }
  }

  if (host.length === 0)
    throw new Error('Invalid host (zero length).');

  if (port != null) {
    let word = 0;
    let total = 0;

    for (let i = 0; i < port.length; i++) {
      const ch = port.charCodeAt(i);

      if (ch < 0x30 || ch > 0x39)
        throw new Error('Invalid port (bad character).');

      if (total > 0 && word === 0)
        throw new Error('Invalid port (leading zero).');

      word *= 10;
      word += ch - 0x30;
      total += 1;

      if (total > 5 || word > 0xffff)
        throw new Error('Invalid port (overflow).');
    }

    if (total === 0)
      throw new Error('Invalid port (bad size).');

    port = word;
  } else {
    port = fport;
  }

  if (inet6) {
    if (inet.pton6(host, null, 0) < 0)
      throw new Error('Invalid IPv6 address.');
  }

  let raw = null;
  let type = types.NONE;
  let hostname;

  try {
    raw = binet.decode(host);
  } catch (e) {
    ;
  }

  if (raw) {
    host = binet.encode(raw);
    type = binet.getType(raw);
  }

  if (type === types.INET6)
    hostname = `[${host}]:${port}`;
  else
    hostname = `${host}:${port}`;

  return {
    host,
    port,
    type,
    hostname,
    raw,
    key
  };
};

/**
 * Get address type (0=none, 4=inet4, 6=inet6, 10=tor).
 * @param {String} str
 * @returns {Number}
 */

binet.getTypeString = function getTypeString(str) {
  assert(typeof str === 'string');

  if (str.length === 0)
    return types.NONE;

  if (str.length > 255)
    return types.NONE;

  if (onion.isLegacyString(str))
    return types.ONION;

  if (inet.pton4(str, null, 0) >= 0)
    return types.INET4;

  const raw = POOL;

  if (inet.pton6(str, raw, 0) >= 0)
    return binet.getType(raw);

  return types.NONE;
};

/**
 * Test whether a string is IPv4 mapped.
 * @param {String} str
 * @returns {Boolean}
 */

binet.isMappedString = function isMappedString(str) {
  const raw = POOL;

  if (inet.pton6(str, raw, 0) >= 0) {
    if (binet.isMapped(raw))
      return true;
  }

  return false;
};

/**
 * Test whether a string is IPv4.
 * @param {String} str
 * @returns {Boolean}
 */

binet.isIPv4String = function isIPv4String(str) {
  return binet.getTypeString(str) === types.INET4;
};

/**
 * Test whether a string is IPv6.
 * @param {String} str
 * @returns {Boolean}
 */

binet.isIPv6String = function isIPv6String(str) {
  return binet.getTypeString(str) === types.INET6;
};

/**
 * Test whether a string is an onion address.
 * @param {String} str
 * @returns {Boolean}
 */

binet.isOnionString = function isOnionString(str) {
  return binet.getTypeString(str) === types.ONION;
};

/**
 * Test whether a string is a domain name.
 * @param {String} str
 * @returns {Boolean}
 */

binet.isUnknownString = function isUnknownString(str) {
  return binet.getTypeString(str) === types.NONE;
};

/**
 * Test whether a string is IPv4 or IPv6.
 * @param {String} str
 * @returns {Number}
 */

binet.isIPString = function isIPString(str) {
  const type = binet.getTypeString(str);

  switch (type) {
    case types.INET4:
    case types.INET6:
      return type;
    default:
      return types.NONE;
  }
};

/**
 * Test whether two IPs are equal.
 * @param {String} a
 * @param {String} b
 * @returns {Boolean}
 */

binet.isEqualString = function isEqualString(a, b) {
  const x = POOLX;
  const y = POOLY;

  binet.write(x, a, 0, 16);
  binet.write(y, b, 0, 16);

  return x.equals(y);
};

/**
 * Apply a network mask to IP.
 * @param {String} str
 * @param {String} mask
 * @returns {Buffer}
 */

binet.maskString = function maskString(str, mask) {
  const x = POOLX;
  const y = POOLY;

  binet.write(x, str, 0, 16);
  binet.write(y, mask, 0, 16);
  binet.mask(x, y, x);

  return binet.encode(x);
};

/**
 * Apply a network mask
 * to IP from CIDR bits.
 * @param {String} str
 * @param {Number} bits
 * @returns {Buffer}
 */

binet.cidrString = function cidrString(str, bits) {
  const x = POOLX;

  binet.write(x, str, 0, 16);
  binet.cidr(x, bits, x);

  return binet.encode(x);
};

/**
 * Get address type.
 * @param {Buffer} raw
 * @returns {Number}
 */

binet.getType = function getType(raw) {
  if (binet.isMapped(raw))
    return types.INET4;

  if (binet.isOnion(raw))
    return types.ONION;

  return types.INET6;
};

/**
 * Test whether the address is IPv4 mapped.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isMapped = function isMapped(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);
  return inet.mapped(raw, 0);
};

/**
 * Test whether the address is IPv4.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isIPv4 = function isIPv4(raw) {
  return binet.isMapped(raw);
};

/**
 * Test whether the address is IPv6.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isIPv6 = function isIPv6(raw) {
  return !binet.isMapped(raw) && !binet.isOnion(raw);
};

/**
 * Test whether the ip has a tor onion prefix.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isOnion = function isOnion(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);
  return inet.onion(raw, 0);
};

/**
 * Test whether the address is IPv4 or IPv6.
 * @param {Buffer} raw
 * @returns {Number}
 */

binet.isIP = function isIP(raw) {
  if (binet.isIPv4(raw))
    return types.INET4;

  if (binet.isIPv6(raw))
    return types.INET6;

  return types.NONE;
};

/**
 * Test whether two IPs are equal.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

binet.isEqual = function isEqual(a, b) {
  assert(Buffer.isBuffer(a));
  assert(Buffer.isBuffer(b));
  assert(a.length === 16);
  assert(b.length === 16);
  return a.equals(b);
};

/**
 * Apply a network mask to IP.
 * @param {Buffer} raw
 * @param {Buffer} mask
 * @param {Buffer?} dst
 * @returns {Buffer}
 */

binet.mask = function(raw, mask, dst) {
  if (dst == null)
    dst = Buffer.allocUnsafe(16);

  assert(Buffer.isBuffer(raw));
  assert(Buffer.isBuffer(mask));
  assert(Buffer.isBuffer(dst));
  assert(raw.length === 16);
  assert(mask.length === 16);
  assert(dst.length === 16);

  const start = binet.isMapped(raw) ? 12 : 0;

  if (raw !== dst)
    raw.copy(dst, 0, 0, 16);

  for (let i = start; i < 16; i++)
    dst[i] = raw[i] & mask[i];

  return dst;
};

/**
 * Apply a network mask
 * to IP from CIDR bits.
 * @param {Buffer} raw
 * @param {Number} bits
 * @param {Buffer?} dst
 * @returns {Buffer}
 */

binet.cidr = function cidr(raw, bits, dst) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);
  assert((bits & 0xff) === bits);

  const mask = POOL;

  let start = 0;
  let max = 128;

  if (binet.isMapped(raw)) {
    start = 12;
    max = 32;
    mask.fill(0x00, 0, 10);
    mask[10] = 0xff;
    mask[11] = 0xff;
  }

  if (bits > max)
    throw new Error('Too many CIDR bits.');

  for (let i = start; i < 16; i++) {
    let b = 8;

    if (bits < 8)
      b = bits;

    bits -= b;

    mask[i] = ~(0xff >> b) & 0xff;
  }

  return binet.mask(raw, mask, dst);
};

/**
 * Test whether the host is null.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isNull = function isNull(raw) {
  if (binet.isIPv4(raw)) {
    // 0.0.0.0
    return raw[12] === 0
      && raw[13] === 0
      && raw[14] === 0
      && raw[15] === 0;
  }
  // ::
  return binet.isEqual(raw, ZERO_IP);
};

/**
 * Test whether the host is a broadcast address.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isBroadcast = function isBroadcast(raw) {
  if (!binet.isIPv4(raw))
    return false;

  // 255.255.255.255
  return raw[12] === 255
    && raw[13] === 255
    && raw[14] === 255
    && raw[15] === 255;
};

/**
 * Test whether the ip is RFC 1918.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC1918 = function isRFC1918(raw) {
  if (!binet.isIPv4(raw))
    return false;

  if (raw[12] === 10)
    return true;

  if (raw[12] === 192 && raw[13] === 168)
    return true;

  if (raw[12] === 172 && (raw[13] >= 16 && raw[13] <= 31))
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 2544.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC2544 = function isRFC2544(raw) {
  if (!binet.isIPv4(raw))
    return false;

  if (raw[12] === 198 && (raw[13] === 18 || raw[13] === 19))
    return true;

  if (raw[12] === 169 && raw[13] === 254)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 3927.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC3927 = function isRFC3927(raw) {
  if (!binet.isIPv4(raw))
    return false;

  if (raw[12] === 169 && raw[13] === 254)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 6598.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC6598 = function isRFC6598(raw) {
  if (!binet.isIPv4(raw))
    return false;

  if (raw[12] === 100
      && (raw[13] >= 64 && raw[13] <= 127)) {
    return true;
  }

  return false;
};

/**
 * Test whether the ip is RFC 5737.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC5737 = function isRFC5737(raw) {
  if (!binet.isIPv4(raw))
    return false;

  if (raw[12] === 192
      && (raw[13] === 0 && raw[14] === 2)) {
    return true;
  }

  if (raw[12] === 198 && raw[13] === 51 && raw[14] === 100)
    return true;

  if (raw[12] === 203 && raw[13] === 0 && raw[14] === 113)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 3849.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC3849 = function isRFC3849(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  if (raw[0] === 0x20 && raw[1] === 0x01
      && raw[2] === 0x0d && raw[3] === 0xb8) {
    return true;
  }

  return false;
};

/**
 * Test whether the ip is RFC 3964.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC3964 = function isRFC3964(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  if (raw[0] === 0x20 && raw[1] === 0x02)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 6052.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC6052 = function isRFC6052(raw) {
  return hasPrefix(raw, RFC6052);
};

/**
 * Test whether the ip is RFC 4380.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC4380 = function isRFC4380(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  if (raw[0] === 0x20 && raw[1] === 0x01
      && raw[2] === 0x00 && raw[3] === 0x00) {
    return true;
  }

  return false;
};

/**
 * Test whether the ip is RFC 4862.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC4862 = function isRFC4862(raw) {
  return hasPrefix(raw, RFC4862);
};

/**
 * Test whether the ip is RFC 4193.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC4193 = function isRFC4193(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  if ((raw[0] & 0xfe) === 0xfc)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 6145.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC6145 = function isRFC6145(raw) {
  return hasPrefix(raw, RFC6145);
};

/**
 * Test whether the ip is RFC 4843.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRFC4843 = function isRFC4843(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  if (raw[0] === 0x20 && raw[1] === 0x01
      && raw[2] === 0x00 && (raw[3] & 0xf0) === 0x10) {
    return true;
  }

  return false;
};

/**
 * Test whether the ip is local.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isLocal = function isLocal(raw) {
  if (binet.isIPv4(raw)) {
    if (raw[12] === 127 && raw[13] === 0)
      return true;
    return false;
  }

  if (binet.isEqual(raw, LOCAL_IP))
    return true;

  return false;
};

/**
 * Test whether the ip is a multicast address.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isMulticast = function isMulticast(raw) {
  if (binet.isIPv4(raw)) {
    if ((raw[12] & 0xf0) === 0xe0)
      return true;
    return false;
  }
  return raw[0] === 0xff;
};

/**
 * Test whether the ip is valid.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isValid = function isValid(raw) {
  if (hasPrefix(raw, SHIFTED))
    return false;

  if (binet.isNull(raw))
    return false;

  if (binet.isBroadcast(raw))
    return false;

  if (binet.isRFC3849(raw))
    return false;

  return true;
};

/**
 * Test whether the ip is routable.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

binet.isRoutable = function isRoutable(raw) {
  if (!binet.isValid(raw))
    return false;

  if (binet.isRFC1918(raw))
    return false;

  if (binet.isRFC2544(raw))
    return false;

  if (binet.isRFC3927(raw))
    return false;

  if (binet.isRFC4862(raw))
    return false;

  if (binet.isRFC6598(raw))
    return false;

  if (binet.isRFC5737(raw))
    return false;

  if (binet.isRFC4193(raw) && !binet.isOnion(raw))
    return false;

  if (binet.isRFC4843(raw))
    return false;

  if (binet.isLocal(raw))
    return false;

  return true;
};

/**
 * Get addr network. Similar to
 * type, but includes teredo.
 * @param {Buffer} raw
 * @returns {Number}
 */

binet.getNetwork = function getNetwork(raw) {
  if (binet.isIPv4(raw))
    return networks.INET4;

  if (binet.isRFC4380(raw))
    return networks.TEREDO;

  if (binet.isOnion(raw))
    return networks.ONION;

  return networks.INET6;
};

/**
 * Calculate reachable score from source to destination.
 * @param {Buffer} src
 * @param {Buffer} dest
 * @returns {Number} Ranges from 0-6.
 */

binet.getReachability = function getReachability(src, dest) {
  const UNREACHABLE = 0;
  const DEFAULT = 1;
  const TEREDO = 2;
  const IPV6_WEAK = 3;
  const IPV4 = 4;
  const IPV6_STRONG = 5;
  const PRIVATE = 6;

  if (!binet.isRoutable(src))
    return UNREACHABLE;

  const srcNet = binet.getNetwork(src);
  const destNet = binet.getNetwork(dest);

  switch (destNet) {
    case networks.IPV4:
      switch (srcNet) {
        case networks.IPV4:
          return IPV4;
        default:
          return DEFAULT;
      }
      break;
    case networks.INET6:
      switch (srcNet) {
        case networks.TEREDO:
          return TEREDO;
        case networks.IPV4:
          return IPV4;
        case networks.INET6:
          if (binet.isRFC3964(src)
              || binet.isRFC6052(src)
              || binet.isRFC6145(src)) {
            // tunnel
            return IPV6_WEAK;
          }
          return IPV6_STRONG;
        default:
          return DEFAULT;
      }
      break;
    case networks.ONION:
      switch (srcNet) {
        case networks.IPV4:
          return IPV4;
        case networks.ONION:
          return PRIVATE;
        default:
          return DEFAULT;
      }
      break;
    case networks.TEREDO:
      switch (srcNet) {
        case networks.TEREDO:
          return TEREDO;
        case networks.INET6:
          return IPV6_WEAK;
        case networks.IPV4:
          return IPV4;
        default:
          return DEFAULT;
      }
      break;
    default:
      switch (srcNet) {
        case networks.TEREDO:
          return TEREDO;
        case networks.INET6:
          return IPV6_WEAK;
        case networks.IPV4:
          return IPV4;
        case networks.ONION:
          return PRIVATE;
        default:
          return DEFAULT;
      }
      break;
  }
};

/**
 * Get IP address from network interfaces.
 * @private
 * @param {Number} filter
 * @param {Number} af
 * @returns {String}
 */

binet._interfaces = function _interfaces(filter, af) {
  if (typeof os.networkInterfaces !== 'function')
    return [];

  assert((filter >>> 0) === filter);

  const family = af2str(af);
  const interfaces = os.networkInterfaces();
  const result = [];
  const raw = POOL;

  for (const key of Object.keys(interfaces)) {
    const items = interfaces[key];

    for (const details of items) {
      if (family && details.family !== family)
        continue;

      try {
        binet.write(raw, details.address, 0, 16);
      } catch (e) {
        continue;
      }

      if (!binet.isValid(raw))
        continue;

      switch (af) {
        case types.NONE: {
          break;
        }
        case types.INET4: {
          if (!binet.isIPv4(raw))
            continue;
          break;
        }
        case types.INET6: {
          if (binet.isIPv4(raw))
            continue;
          break;
        }
      }

      switch (filter) {
        case ALL: {
          break;
        }
        case LOCAL: {
          if (!binet.isLocal(raw))
            continue;
          break;
        }
        case NONLOCAL: {
          if (binet.isLocal(raw))
            continue;
          break;
        }
        case PRIVATE: {
          if (binet.isLocal(raw))
            continue;

          if (binet.isRoutable(raw))
            continue;

          break;
        }
        case PUBLIC: {
          if (binet.isLocal(raw))
            continue;

          if (!binet.isRoutable(raw))
            continue;

          break;
        }
      }

      result.push(binet.encode(raw));
    }
  }

  return result;
};

/**
 * Get local IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

binet.getInterfaces = function getInterfaces(family) {
  return binet._interfaces(ALL, str2af(family));
};

/**
 * Get local IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

binet.getLocal = function getLocal(family) {
  return binet._interfaces(LOCAL, str2af(family));
};

/**
 * Get non-local IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

binet.getNonlocal = function getNonlocal(family) {
  return binet._interfaces(NONLOCAL, str2af(family));
};

/**
 * Get private IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

binet.getPrivate = function getPrivate(family) {
  return binet._interfaces(PRIVATE, str2af(family));
};

/**
 * Get public IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

binet.getPublic = function getPublic(family) {
  return binet._interfaces(PUBLIC, str2af(family));
};

/*
 * Helpers
 */

function hasPrefix(raw, prefix) {
  assert(Buffer.isBuffer(raw));
  assert(Buffer.isBuffer(prefix));
  assert(raw.length >= prefix.length);

  for (let i = 0; i < prefix.length; i++) {
    if (raw[i] !== prefix[i])
      return false;
  }

  return true;
}

function af2str(af) {
  assert((af >>> 0) === af);

  switch (af) {
    case types.NONE:
      return null;
    case types.INET4:
      return 'IPv4';
    case types.INET6:
      return 'IPv6';
  }

  throw new Error(`Invalid address family: ${af}.`);
}

function str2af(family) {
  if (family == null)
    return types.NONE;

  if ((family >>> 0) === family)
    return family;

  assert(typeof family === 'string');
  assert(family.length <= 4);

  const name = family.toLowerCase();

  switch (name) {
    case 'all':
      return types.NONE;
    case 'ipv4':
      return types.INET4;
    case 'ipv6':
      return types.INET6;
  }

  throw new Error(`Invalid address family: ${family}.`);
}

/*
 * Aliases
 */

binet.type = binet.getTypeString;
binet.family = binet.isIPString;
binet.test = binet.getTypeString;
binet.equal = binet.isEqualString;

/*
 * Compat (deprecated)
 */

types.NAME = 0;
types.DNS = 0;
types.IPV4 = 4;
types.IPV6 = 6;

binet.toString = binet.encode;
binet.toBuffer = binet.decode;
binet.toMapped = binet.map;
binet.isNameString = binet.isUnknownString;
binet.hasPrefix = hasPrefix;
binet.getStringType = binet.getTypeString;
binet.isV4String = binet.isIPv4String;
binet.isV6String = binet.isIPv6String;
binet.isDNSString = binet.isUnknownString;
binet.fromHostname = binet.fromHost;
binet.toHostname = binet.toHost;
binet.IP = binet;
binet.ip = binet;

/*
 * Expose
 */

binet.types = types;
binet.networks = networks;
binet.ZERO_IP = ZERO_IP;
binet.onion = onion;
binet.inet = inet;

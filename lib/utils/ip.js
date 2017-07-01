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

'use strict';

const assert = require('assert');
const os = require('os');
const base32 = require('./base32');

/**
 * @exports utils/ip
 */

const IP = exports;

/*
 * Constants
 */

const ZERO_IP = Buffer.from('00000000000000000000000000000000', 'hex');
const LOCAL_IP = Buffer.from('00000000000000000000000000000001', 'hex');
const RFC6052 = Buffer.from('0064ff9b0000000000000000', 'hex');
const RFC4862 = Buffer.from('fe80000000000000', 'hex');
const RFC6145 = Buffer.from('0000000000000000ffff0000', 'hex');
const TOR_ONION = Buffer.from('fd87d87eeb43', 'hex');
const SHIFTED = Buffer.from('00000000000000ffff', 'hex');

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX =
  /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

/**
 * IP address of all zeroes.
 * @const {Buffer}
 */

IP.ZERO_IP = ZERO_IP;

/**
 * Address types.
 * @enum {Number}
 */

IP.types = {
  DNS: -1,
  IPV4: 4,
  IPV6: 6,
  ONION: 10,
  TEREDO: 11
};

/**
 * Parse a hostname.
 * @param {String} addr
 * @param {Number?} fallback - Fallback port.
 * @returns {Object} Contains `host`, `port`, and `type`.
 */

IP.fromHostname = function fromHostname(addr, fallback) {
  let parts, host, port, type, hostname, raw;

  assert(typeof addr === 'string');

  assert(addr.length > 0, 'Bad address.');

  if (addr[0] === '[') {
    if (addr[addr.length - 1] === ']') {
      // Case:
      // [::1]
      host = addr.slice(1, -1);
      port = null;
    } else {
      // Case:
      // [::1]:80
      addr = addr.slice(1);
      parts = addr.split(']:');
      assert(parts.length === 2, 'Bad IPv6 address.');
      host = parts[0];
      port = parts[1];
    }
  } else {
    parts = addr.split(':');
    switch (parts.length) {
      case 2:
        // Cases:
        // 127.0.0.1:80
        // localhost:80
        host = parts[0];
        port = parts[1];
        break;
      case 1:
        // Cases:
        // 127.0.0.1
        // localhost
        host = parts[0];
        port = null;
        break;
      default:
        // Case:
        // ::1
        assert(IP.isV6String(addr), 'Bad IPv6 address.');
        host = addr;
        port = null;
        break;
    }
  }

  assert(host.length > 0, 'Bad host.');

  if (port != null) {
    assert(port.length <= 5, 'Bad port.');
    assert(/^\d+$/.test(port), 'Bad port.');
    port = parseInt(port, 10);
    assert(port <= 0xffff);
  } else {
    port = fallback || 0;
  }

  type = IP.getStringType(host);

  if (type !== IP.types.DNS) {
    raw = IP.toBuffer(host);
    host = IP.toString(raw);
  }

  if (type === IP.types.IPV6)
    hostname = `[${host}]:${port}`;
  else
    hostname = `${host}:${port}`;

  return new Address(host, port, type, hostname, raw);
};

/**
 * Concatenate a host and port.
 * @param {String} host
 * @param {Number} port
 * @returns {String}
 */

IP.toHostname = function toHostname(host, port) {
  let type;

  assert(typeof host === 'string');
  assert(host.length > 0);
  assert(typeof port === 'number');
  assert(port >= 0 && port <= 0xffff);

  assert(!/[\[\]]/.test(host), 'Bad host.');

  type = IP.getStringType(host);

  if (host.indexOf(':') !== -1)
    assert(type === IP.types.IPV6, 'Bad host.');

  if (type !== IP.types.DNS)
    host = IP.normalize(host);

  if (type === IP.types.IPV6)
    return `[${host}]:${port}`;

  return `${host}:${port}`;
};

/**
 * Get address type (-1=dns, 4=ipv4, 6=ipv6, 10=tor).
 * @param {String?} str
 * @returns {Number}
 */

IP.getStringType = function getStringType(str) {
  if (IP.isV4String(str))
    return IP.types.IPV4;

  if (IP.isV6String(str))
    return IP.types.IPV6;

  if (IP.isOnionString(str))
    return IP.types.ONION;

  return IP.types.DNS;
};

/**
 * Test whether a string is IPv4.
 * @param {String?} str
 * @returns {Boolean}
 */

IP.isV4String = function isV4String(str) {
  assert(typeof str === 'string');

  if (str.length < 7)
    return false;

  if (str.length > 15)
    return false;

  return IPV4_REGEX.test(str);
};

/**
 * Test whether a string is IPv6.
 * @param {String?} str
 * @returns {Boolean}
 */

IP.isV6String = function isV6String(str) {
  assert(typeof str === 'string');

  if (str.length < 2)
    return false;

  if (str.length > 39)
    return false;

  return IPV6_REGEX.test(str);
};

/**
 * Test whether a string is an onion address.
 * @param {String?} str
 * @returns {Boolean}
 */

IP.isOnionString = function isOnionString(str) {
  assert(typeof str === 'string');

  if (str.length < 7)
    return false;

  return str.slice(-6) === '.onion';
};

/**
 * Test whether a buffer is an ipv4-mapped ipv6 address.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isMapped = function isMapped(raw) {
  assert(Buffer.isBuffer(raw));
  assert(raw.length === 16);

  return raw[0] === 0x00
    && raw[1] === 0x00
    && raw[2] === 0x00
    && raw[3] === 0x00
    && raw[4] === 0x00
    && raw[5] === 0x00
    && raw[6] === 0x00
    && raw[7] === 0x00
    && raw[8] === 0x00
    && raw[9] === 0x00
    && raw[10] === 0xff
    && raw[11] === 0xff;
};

/**
 * Parse an IP string and return a buffer.
 * @param {String} str
 * @returns {Buffer}
 */

IP.toBuffer = function toBuffer(str) {
  let raw = Buffer.allocUnsafe(16);

  assert(typeof str === 'string');

  if (IP.isV4String(str)) {
    raw.fill(0);
    raw[10] = 0xff;
    raw[11] = 0xff;
    return IP.parseV4(str, raw, 12);
  }

  if (IP.isOnionString(str)) {
    let data = TOR_ONION;
    data.copy(raw, 0);
    data = base32.decode(str.slice(0, -6));
    assert(data.length === 10, 'Invalid onion address.');
    data.copy(raw, 6);
    return raw;
  }

  return IP.parseV6(str, raw, 0);
};

/**
 * Convert an IPv4 string to a buffer.
 * @private
 * @param {String} str
 * @param {Buffer} raw
 * @param {Number} offset
 * @returns {Buffer}
 */

IP.parseV4 = function parseV4(str, raw, offset) {
  let parts = str.split('.');

  assert(parts.length === 4);

  for (let ch of parts) {
    assert(ch.length > 0);
    assert(ch.length <= 3);
    ch = parseInt(ch, 10);
    assert(ch >= 0 && ch <= 255);
    raw[offset++] = ch;
  }

  return raw;
};

/**
 * Convert an IPv6 string to a buffer.
 * @private
 * @param {String} str
 * @param {Buffer} raw
 * @param {Number} offset
 * @returns {Buffer}
 */

IP.parseV6 = function parseV6(str, raw, offset) {
  let parts = str.split(':');
  let missing = 8 - parts.length;
  let start = offset;
  let colon = false;

  assert(parts.length >= 2, 'Not an IPv6 address.');

  for (let word of parts) {
    if (IP.isV4String(word))
      missing--;
  }

  for (let i = 0; i < parts.length; i++) {
    let word = parts[i];

    if (word.length === 0) {
      assert(!colon, 'Overuse of double colon in IPv6 address.');

      colon = true;
      missing += 1;

      // Eat extra colons.
      // e.g. :::0
      while (i + 1 < parts.length) {
        word = parts[i + 1];
        if (word.length !== 0)
          break;
        missing += 1;
        i++;
      }

      while (missing > 0) {
        raw[offset++] = 0;
        raw[offset++] = 0;
        missing--;
      }

      continue;
    }

    if (IP.isV4String(word)) {
      IP.parseV4(word, raw, offset);
      offset += 4;
      continue;
    }

    assert(word.length <= 4);

    word = parseInt(word, 16);

    assert(word === word, 'Non-number in IPv6 address.');

    raw[offset++] = (word >> 8) & 0xff;
    raw[offset++] = word & 0xff;
  }

  assert(missing === 0, 'IPv6 address has missing sections.');
  assert.equal(offset, start + 16);

  return raw;
};

/**
 * Convert a buffer to an ip string.
 * @param {Buffer} raw
 * @returns {String}
 */

IP.toString = function toString(raw) {
  assert(Buffer.isBuffer(raw));

  if (raw.length === 4) {
    let host = '';
    host += raw[0];
    host += '.' + raw[1];
    host += '.' + raw[2];
    host += '.' + raw[3];
    return host;
  }

  if (raw.length === 16) {
    let host = '';

    if (IP.isMapped(raw)) {
      host += raw[12];
      host += '.' + raw[13];
      host += '.' + raw[14];
      host += '.' + raw[15];
      return host;
    }

    if (IP.isOnion(raw)) {
      host = base32.encode(raw.slice(6));
      return `${host}.onion`;
    }

    host += raw.readUInt16BE(0, true).toString(16);

    for (let i = 2; i < 16; i += 2) {
      host += ':';
      host += raw.readUInt16BE(i, true).toString(16);
    }

    host = host.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
    host = host.replace(/:{3,4}/, '::');

    return host;
  }

  throw new Error(`Invalid IP address: ${raw.toString('hex')}.`);
};

/**
 * Normalize an ip.
 * @param {String} str
 * @returns {String}
 */

IP.normalize = function normalize(str) {
  return IP.toString(IP.toBuffer(str));
};

/**
 * Test whether the address is IPv4.
 * @returns {Boolean}
 */

IP.isIPv4 = function isIPv4(raw) {
  return IP.isMapped(raw);
};

/**
 * Test whether the address is IPv6.
 * @returns {Boolean}
 */

IP.isIPv6 = function isIPv6(raw) {
  return !IP.isMapped(raw) && !IP.isOnion(raw);
};

/**
 * Get address type.
 * @param {Buffer} raw
 * @returns {Number}
 */

IP.getType = function getType(raw) {
  if (IP.isIPv4(raw))
    return IP.types.IPV4;

  if (IP.isIPv6(raw))
    return IP.types.IPV6;

  if (IP.isOnion(raw))
    return IP.types.ONION;

  assert(false, 'Unknown type.');
};

/**
 * Get addr network. Similar to
 * type, but includes teredo.
 * @param {Buffer} raw
 * @returns {Number}
 */

IP.getNetwork = function getNetwork(raw) {
  if (IP.isRFC4380(raw))
    return IP.types.TEREDO;

  return IP.getType(raw);
};

/**
 * Test whether the host is null.
 * @returns {Boolean}
 */

IP.isNull = function isNull(raw) {
  if (IP.isIPv4(raw)) {
    // 0.0.0.0
    return raw[12] === 0
      && raw[13] === 0
      && raw[14] === 0
      && raw[15] === 0;
  }
  // ::
  return IP.isEqual(raw, ZERO_IP);
};

/**
 * Test whether the host is a broadcast address.
 * @returns {Boolean}
 */

IP.isBroadcast = function isBroadcast(raw) {
  if (IP.isIPv4(raw)) {
    // 255.255.255.255
    return raw[12] === 255
      && raw[13] === 255
      && raw[14] === 255
      && raw[15] === 255;
  }
  return false;
};

/**
 * Test whether the ip is RFC 1918.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC1918 = function isRFC1918(raw) {
  if (!IP.isIPv4(raw))
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

IP.isRFC2544 = function isRFC2544(raw) {
  if (!IP.isIPv4(raw))
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

IP.isRFC3927 = function isRFC3927(raw) {
  if (!IP.isIPv4(raw))
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

IP.isRFC6598 = function isRFC6598(raw) {
  if (!IP.isIPv4(raw))
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

IP.isRFC5737 = function isRFC5737(raw) {
  if (!IP.isIPv4(raw))
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

IP.isRFC3849 = function isRFC3849(raw) {
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

IP.isRFC3964 = function isRFC3964(raw) {
  if (raw[0] === 0x20 && raw[1] === 0x02)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 6052.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC6052 = function isRFC6052(raw) {
  return IP.hasPrefix(raw, RFC6052);
};

/**
 * Test whether the ip is RFC 4380.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC4380 = function isRFC4380(raw) {
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

IP.isRFC4862 = function isRFC4862(raw) {
  return IP.hasPrefix(raw, RFC4862);
};

/**
 * Test whether the ip is RFC 4193.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC4193 = function isRFC4193(raw) {
  if ((raw[0] & 0xfe) === 0xfc)
    return true;

  return false;
};

/**
 * Test whether the ip is RFC 6145.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC6145 = function isRFC6145(raw) {
  return IP.hasPrefix(raw, RFC6145);
};

/**
 * Test whether the ip is RFC 4843.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRFC4843 = function isRFC4843(raw) {
  if (raw[0] === 0x20 && raw[1] === 0x01
      && raw[2] === 0x00 && (raw[3] & 0xf0) === 0x10) {
    return true;
  }

  return false;
};

/**
 * Test whether the ip has a tor onion prefix.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isOnion = function isOnion(raw) {
  return IP.hasPrefix(raw, TOR_ONION);
};

/**
 * Test whether the ip is local.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isLocal = function isLocal(raw) {
  if (IP.isIPv4(raw)) {
    if (raw[12] === 127 && raw[13] === 0)
      return true;
    return false;
  }

  if (IP.isEqual(raw, LOCAL_IP))
    return true;

  return false;
};

/**
 * Test whether the ip is a multicast address.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isMulticast = function isMulticast(raw) {
  if (IP.isIPv4(raw)) {
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

IP.isValid = function isValid(raw) {
  if (IP.hasPrefix(raw, SHIFTED))
    return false;

  if (IP.isNull(raw))
    return false;

  if (IP.isBroadcast(raw))
    return false;

  if (IP.isRFC3849(raw))
    return false;

  return true;
};

/**
 * Test whether the ip is routable.
 * @param {Buffer} raw
 * @returns {Boolean}
 */

IP.isRoutable = function isRoutable(raw) {
  if (!IP.isValid(raw))
    return false;

  if (IP.isRFC1918(raw))
    return false;

  if (IP.isRFC2544(raw))
    return false;

  if (IP.isRFC3927(raw))
    return false;

  if (IP.isRFC4862(raw))
    return false;

  if (IP.isRFC6598(raw))
    return false;

  if (IP.isRFC5737(raw))
    return false;

  if (IP.isRFC4193(raw) && !IP.isOnion(raw))
    return false;

  if (IP.isRFC4843(raw))
    return false;

  if (IP.isLocal(raw))
    return false;

  return true;
};

/**
 * Calculate reachable score from source to destination.
 * @param {Buffer} src
 * @param {Buffer} dest
 * @returns {Number} Ranges from 0-6.
 */

IP.getReachability = function getReachability(src, dest) {
  const UNREACHABLE = 0;
  const DEFAULT = 1;
  const TEREDO = 2;
  const IPV6_WEAK = 3;
  const IPV4 = 4;
  const IPV6_STRONG = 5;
  const PRIVATE = 6;

  let srcNet = IP.getNetwork(src);
  let destNet = IP.getNetwork(dest);
  let types = IP.types;

  if (!IP.isRoutable(src))
    return UNREACHABLE;

  switch (destNet) {
    case types.IPV4:
      switch (srcNet) {
        case types.IPV4:
          return IPV4;
        default:
          return DEFAULT;
      }
      break;
    case types.IPV6:
      switch (srcNet) {
        case types.TEREDO:
          return TEREDO;
        case types.IPV4:
          return IPV4;
        case types.IPV6:
          if (IP.isRFC3964(src)
              || IP.isRFC6052(src)
              || IP.isRFC6145(src)) {
            // tunnel
            return IPV6_WEAK;
          }
          return IPV6_STRONG;
        default:
          return DEFAULT;
      }
      break;
    case types.ONION:
      switch (srcNet) {
        case types.IPV4:
          return IPV4;
        case types.ONION:
          return PRIVATE;
        default:
          return DEFAULT;
      }
      break;
    case types.TEREDO:
      switch (srcNet) {
        case types.TEREDO:
          return TEREDO;
        case types.IPV6:
          return IPV6_WEAK;
        case types.IPV4:
          return IPV4;
        default:
          return DEFAULT;
      }
      break;
    default:
      switch (srcNet) {
        case types.TEREDO:
          return TEREDO;
        case types.IPV6:
          return IPV6_WEAK;
        case types.IPV4:
          return IPV4;
        case types.ONION:
          return PRIVATE;
        default:
          return DEFAULT;
      }
      break;
  }
};

/**
 * Test whether an IP has a prefix.
 * @param {Buffer} raw
 * @param {Buffer} prefix
 * @returns {Boolean}
 */

IP.hasPrefix = function hasPrefix(raw, prefix) {
  assert(Buffer.isBuffer(raw));
  assert(Buffer.isBuffer(prefix));
  assert(raw.length >= prefix.length);

  for (let i = 0; i < prefix.length; i++) {
    if (raw[i] !== prefix[i])
      return false;
  }

  return true;
};

/**
 * Test whether two IPs are equal.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {Boolean}
 */

IP.isEqual = function isEqual(a, b) {
  assert(a.length === 16);
  assert(b.length === 16);

  if (a.compare)
    return a.compare(b) === 0;

  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i])
      return false;
  }

  return true;
};

/**
 * Get IP address from network interfaces.
 * @param {String?} name - `public` or `private`.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

IP.getInterfaces = function _getInterfaces(name, family) {
  let interfaces = os.networkInterfaces();
  let keys = Object.keys(interfaces);
  let result = [];

  for (let key of keys) {
    let items = interfaces[key];

    for (let details of items) {
      let type = details.family.toLowerCase();
      let raw;

      if (family && type !== family)
        continue;

      if (details.internal)
        continue;

      try {
        raw = IP.toBuffer(details.address);
      } catch (e) {
        continue;
      }

      if (IP.isNull(raw))
        continue;

      if (IP.isLocal(raw))
        continue;

      if (name === 'public') {
        if (!IP.isRoutable(raw))
          continue;
      } else if (name === 'private') {
        if (IP.isRoutable(raw))
          continue;
      }

      result.push(IP.toString(raw));
    }
  }

  return result;
};

/**
 * Get private IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

IP.getPrivate = function getPrivate(family) {
  return IP.getInterfaces('private', family);
};

/**
 * Get public IP from network interfaces.
 * @param {String?} family - IP family name.
 * @returns {String}
 */

IP.getPublic = function getPublic(family) {
  return IP.getInterfaces('public', family);
};

/**
 * Represents a parsed address.
 * @constructor
 * @alias module:utils/ip.Address
 * @param {String} host
 * @param {Number} port
 * @param {Number} type
 * @param {String} hostname
 * @param {Buffer|null} raw
 * @property {String} host
 * @property {Number} port
 * @property {Number} type
 * @property {String} hostname
 * @property {Buffer} raw
 */

function Address(host, port, type, hostname, raw) {
  this.host = host || '0.0.0.0';
  this.port = port || 0;
  this.type = type || IP.types.IPV4;
  this.hostname = hostname || '0.0.0.0:0';
  this.raw = raw || ZERO_IP;
}

/*
 * Expose
 */

IP.Address = Address;

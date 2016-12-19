/*!
 * ip.js - ip utils for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License).
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on node-ip.
 * https://github.com/indutny/node-ip
 * Copyright (c) 202, Fedor Indutny (MIT License).
 */

'use strict';

var assert = require('assert');
var IP = exports;

/*
 * Constants
 */

var ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
var ipv6Regex =
  /^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

/**
 * Parse a hostname.
 * @param {String} addr
 * @param {Number?} fallback - Fallback port.
 * @returns {Object} Contains `host`, `port`, and `version`.
 */

IP.parseHost = function parseHost(addr, fallback) {
  var port = fallback || 0;
  var parts, host, version;

  assert(typeof addr === 'string');
  assert(typeof port === 'number');

  assert(addr.length > 0, 'Bad address.');

  // [ipv6]:port
  if (addr[0] === '[') {
    addr = addr.substring(1);
    parts = addr.split(/\]:?/);
    assert(parts.length === 2, 'Bad IPv6 address.');
  } else {
    parts = addr.split(':');
    if (parts.length > 2) {
      // ipv6 - no port
      assert(IP.isV6Format(addr), 'Bad IPv6 address.');
      parts = [addr];
    } else {
      // domain/ipv4:port?
      assert(parts.length <= 2, 'Bad host.');
    }
  }

  host = parts[0];
  assert(host.length > 0, 'Bad host.');

  if (parts.length === 2) {
    port = parts[1];
    assert(/^\d+$/.test(port), 'Bad port.');
    port = parseInt(port, 10);
  }

  version = IP.version(host);

  if (version !== -1)
    host = IP.normalize(host);

  return new Address(host, port, version);
};

/**
 * Concatenate a host and port.
 * @param {String} host
 * @param {Number} port
 * @returns {String}
 */

IP.hostname = function hostname(host, port) {
  var version;

  assert(typeof host === 'string');
  assert(host.length > 0);
  assert(typeof port === 'number');

  assert(!/[\[\]]/.test(host), 'Bad host.');

  version = IP.version(host);

  if (version !== -1)
    host = IP.normalize(host);

  if (version === 6)
    host = '[' + host + ']';

  return host + ':' + port;
};

/**
 * Test whether a string is an IP address.
 * @param {String?} str
 * @returns {Number} IP version (4 or 6).
 */

IP.version = function version(str) {
  assert(typeof str === 'string');

  if (IP.isV4Format(str))
    return 4;

  if (IP.isV6Format(str))
    return 6;

  return -1;
};

/**
 * Test whether a string is IPv4.
 * @param {String?} str
 * @returns {Boolean}
 */

IP.isV4Format = function(str) {
  return ipv4Regex.test(str);
};

/**
 * Test whether a string is IPv6.
 * @param {String?} str
 * @returns {Boolean}
 */

IP.isV6Format = function(str) {
  return ipv6Regex.test(str);
};

/**
 * Test whether a buffer is an ipv4-mapped ipv6 address.
 * @param {Buffer} buf
 * @returns {Boolean}
 */

IP.isMapped = function isMapped(buf) {
  var i;

  assert(Buffer.isBuffer(buf));
  assert(buf.length === 16);

  if (buf[10] !== 0xff && buf[11] !== 0xff)
    return false;

  for (i = 0; i < 10; i++) {
    if (buf[i] !== 0)
      return false;
  }

  return true;
};

/**
 * Convert an IP string to a buffer.
 * @param {String} str
 * @returns {Buffer}
 */

IP.toBuffer = function(str) {
  var buf = new Buffer(16);

  assert(typeof str === 'string');

  if (IP.isV4Format(str)) {
    buf.fill(0);
    buf[10] = 0xff;
    buf[11] = 0xff;
    return IP.parseV4(str, buf, 12);
  }

  if (IP.isV6Format(str))
    return IP.parseV6(str, buf, 0);

  throw Error('Invalid IP address: ' + str);
};

/**
 * Convert an IPv4 string to a buffer.
 * @private
 * @param {String} str
 * @param {Buffer} buf
 * @param {Number} offset
 * @returns {Buffer}
 */

IP.parseV4 = function parseV4(str, buf, offset) {
  var parts = str.split('.');
  var i, ch;

  assert(parts.length === 4);

  for (i = 0; i < parts.length; i++) {
    ch = parts[i];
    assert(ch.length > 0);
    assert(ch.length <= 3);
    ch = parseInt(ch, 10);
    assert(ch >= 0 && ch <= 255);
    buf[offset++] = ch;
  }

  return buf;
};

/**
 * Convert an IPv6 string to a buffer.
 * @private
 * @param {String} str
 * @param {Buffer} buf
 * @param {Number} offset
 * @returns {Buffer}
 */

IP.parseV6 = function parseV6(str, buf, offset) {
  var parts = str.split(':');
  var missing = 8 - parts.length;
  var start = offset;
  var len = parts.length;
  var i = 0;
  var word;

  assert(missing >= 0, 'IPv6 address is too long.');
  assert(parts.length >= 2, 'Not an IPv6 address.');

  if (parts[0].length === 0) {
    assert(parts[1].length === 0,
      'Empty leading colon in IPv6 address.');
    missing += 1;
    i++;
  } else if (parts[len - 1].length === 0) {
    assert(parts[len - 2].length === 0,
      'Empty trailing colon in IPv6 address.');
    missing += 1;
    len--;
  }

  for (; i < len; i++) {
    word = parts[i];

    if (word.length === 0) {
      assert(missing > 0, 'Overuse of double colon in IPv6 address.');

      missing += 1;

      // Eat extra colons.
      // e.g. :::0
      while (i + 1 < len) {
        word = parts[i + 1];
        if (word.length !== 0)
          break;
        missing += 1;
        i++;
      }

      while (missing > 0) {
        buf[offset++] = 0;
        buf[offset++] = 0;
        missing--;
      }

      continue;
    }

    if (IP.isV4Format(word)) {
      IP.parseV4(word, buf, offset);
      offset += 4;
      continue;
    }

    assert(word.length <= 4);

    word = parseInt(word, 16);

    assert(word === word, 'Non-number in IPv6 address.');

    buf[offset++] = (word >> 8) & 0xff;
    buf[offset++] = word & 0xff;
  }

  assert(missing === 0, 'IPv6 address has missing sections.');
  assert.equal(offset, start + 16);

  return buf;
};

/**
 * Convert a buffer to an ip string.
 * @param {Buffer} buf
 * @returns {String}
 */

IP.toString = function(buf) {
  var str = '';
  var i;

  assert(Buffer.isBuffer(buf));

  if (buf.length === 4) {
    str += buf[0];
    str += '.' + buf[1];
    str += '.' + buf[2];
    str += '.' + buf[3];
    return str;
  }

  if (buf.length === 16) {
    if (IP.isMapped(buf)) {
      str += buf[12];
      str += '.' + buf[13];
      str += '.' + buf[14];
      str += '.' + buf[15];
      return str;
    }

    str += buf.readUInt16BE(0, true).toString(16);

    for (i = 2; i < 16; i += 2) {
      str += ':';
      str += buf.readUInt16BE(i, true).toString(16);
    }

    str = str.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
    str = str.replace(/:{3,4}/, '::');

    return str;
  }

  throw Error('Invalid IP address: ' + buf.toString('hex'));
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
 * Test whether a string is a private address.
 * @param {String} str
 * @returns {Boolean}
 */

IP.isPrivate = function(str) {
  return /^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(str)
    || /^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(str)
    || /^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(str)
    || /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(str)
    || /^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(str)
    || /^f[cd][0-9a-f]{2}:/i.test(str)
    || /^fe80:/i.test(str)
    || /^::1$/.test(str)
    || /^::$/.test(str);
};

/**
 * Test whether a string is a public address.
 * @param {String} str
 * @returns {Boolean}
 */

IP.isPublic = function(str) {
  return !IP.isPrivate(str);
};

/**
 * Test whether a string is a loopback address.
 * @param {String} str
 * @returns {Boolean}
 */

IP.isLoopback = function(str) {
  return /^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/.test(str)
    || /^fe80::1$/.test(str)
    || /^::1$/.test(str)
    || /^::$/.test(str);
};

/**
 * Get loopback address for ip family.
 * @param {String} family - ipv4 or ipv6.
 * @returns {String}
 */

IP.loopback = function(family) {
  if (!family)
    family = 'ipv4';

  family = family.toLowerCase();

  if (family !== 'ipv4' && family !== 'ipv6')
    throw new Error('Family must be ipv4 or ipv6.');

  return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
};

/*
 * Helpers
 */

function Address(host, port, version) {
  this.host = host;
  this.port = port;
  this.version = version;
}

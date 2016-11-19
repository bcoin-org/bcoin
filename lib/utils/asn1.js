/*!
 * asn1.js - asn1 parsing for bcoin
 * Copyright (c) 2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on asn1.js.
 * https://github.com/indutny/asn1.js
 *
 * Copyright Fedor Indutny, 2013.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

'use strict';

var assert = require('assert');
var BufferReader = require('../utils/reader');
var ASN1 = exports;

ASN1.parseTag = function parseTag(p) {
  var tag = p.readU8();
  var primitive = (tag & 0x20) === 0;
  var oct;

  if ((tag & 0x1f) === 0x1f) {
    oct = tag;
    tag = 0;
    while ((oct & 0x80) === 0x80) {
      oct = p.readU8();
      tag <<= 7;
      tag |= oct & 0x7f;
    }
  } else {
    tag &= 0x1f;
  }

  return {
    primitive: primitive,
    tag: tag,
    len: ASN1.parseLen(p, primitive)
  };
};

ASN1.parseLen = function parseLen(p, primitive) {
  var len = p.readU8();
  var num, i, j;

  // Indefinite form
  if (!primitive && len === 0x80)
    return null;

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len;
  }

  // Long form
  num = len & 0x7f;
  assert(num < 4, 'length octect is too long');

  len = 0;
  for (i = 0; i < num; i++) {
    len <<= 8;
    j = p.readU8();
    len |= j;
  }

  return len;
};

ASN1.parseCert = function parseCert(data) {
  var d = BufferReader(data);
  var p;

  d.start();

  p = BufferReader(ASN1.parseSeq(d));

  return {
    tbs: ASN1.parseTBS(p),
    sigAlg: ASN1.parseAlgIdent(p),
    sig: ASN1.parseBitstr(p),
    raw: d.endData(true)
  };
};

ASN1.parseTBS = function parseTBS(data) {
  var d = BufferReader(data);
  var p;

  d.start();

  p = BufferReader(ASN1.parseSeq(d));

  return {
    version: ASN1.parseExplicitInt(p, 0, true),
    serial: ASN1.parseInt(p),
    sig: ASN1.parseAlgIdent(p),
    issuer: ASN1.parseName(p),
    validity: ASN1.parseValidity(p),
    subject: ASN1.parseName(p),
    pubkey: ASN1.parsePubkey(p),
    raw: d.endData(true)
  };
};

ASN1.parseSeq = function parseSeq(data) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  assert.equal(tag.tag, 0x10); // seq
  return p.readBytes(tag.len, true);
};

ASN1.parseInt = function parseInt(data, readNum) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  var num;

  assert.equal(tag.tag, 0x02); // int

  num = p.readBytes(tag.len, true);

  if (readNum)
    return num.readUIntBE(0, num.length);

  return num;
};

ASN1.parseExplicitInt = function parseExplicitInt(data, i, readNum) {
  var p = BufferReader(data);
  var off = p.offset;
  var tag = ASN1.parseTag(p);
  if (tag.tag !== i) {
    p.seek(-(p.offset - off));
    return -1;
  }
  return ASN1.parseInt(p, readNum);
};

ASN1.parseBitstr = function parseBitstr(data) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  assert.equal(tag.tag, 0x03); // bitstr
  return ASN1.alignBitstr(p.readBytes(tag.len, true));
};

ASN1.parseString = function parseString(data) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  switch (tag.tag) {
    case 0x03: // bitstr
      return ASN1.alignBitstr(p.readBytes(tag.len, true));
    case 0x04: // octstr
    case 0x12: // numstr
    case 0x13: // prinstr
    case 0x14: // t61str
    case 0x15: // videostr
    case 0x16: // ia5str
    case 0x19: // graphstr
    case 0x0c: // utf8str
    case 0x1a: // iso646str
    case 0x1b: // genstr
    case 0x1c: // unistr
    case 0x1d: // charstr
    case 0x1e: // bmpstr
      return p.readString('utf8', tag.len);
    default:
      assert(false, 'Bad string.');
  }
};

ASN1.alignBitstr = function(data) {
  var padding = data[0];
  var bits = (data.length - 1) * 8 - padding;
  var buf = data.slice(1);
  var shift = 8 - (bits % 8);
  var i, out;

  if (shift === 8 || buf.length === 0)
    return buf;

  out = new Buffer(buf.length);
  out[0] = buf[0] >>> shift;

  for (i = 1; i < buf.length; i++) {
    out[i] = buf[i - 1] << (8 - shift);
    out[i] |= buf[i] >>> shift;
  }

  return out;
};

ASN1.parsePubkey = function parsePubkey(data) {
  var p = BufferReader(data);
  p = BufferReader(ASN1.parseSeq(p));
  return {
    alg: ASN1.parseAlgIdent(p),
    pubkey: ASN1.parseBitstr(p)
  };
};

ASN1.parseName = function parseName(data) {
  var p = BufferReader(data);
  var values = [];
  var tag;

  p = BufferReader(ASN1.parseSeq(p));

  while (p.left()) {
    tag = ASN1.parseTag(p);
    assert.equal(tag.tag, 0x11); // set
    tag = ASN1.parseTag(p);
    assert.equal(tag.tag, 0x10); // seq
    values.push({
      type: ASN1.parseOID(p),
      value: ASN1.parseString(p)
    });
  }

  return values;
};

ASN1.parseValidity = function parseValidity(data) {
  var p = BufferReader(data);
  p = BufferReader(ASN1.parseSeq(p));
  return {
    notBefore: ASN1.parseTime(p),
    notAfter: ASN1.parseTime(p)
  };
};

ASN1.parseTime = function parseTime(data) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  var str = p.readString('ascii', tag.len);
  var year, mon, day, hour, min, sec;

  switch (tag.tag) {
    case 0x17: // utctime
      year = str.slice(0, 2) | 0;
      mon = str.slice(2, 4) | 0;
      day = str.slice(4, 6) | 0;
      hour = str.slice(6, 8) | 0;
      min = str.slice(8, 10) | 0;
      sec = str.slice(10, 12) | 0;
      if (year < 70)
        year = 2000 + year;
      else
        year = 1900 + year;
      break;
    case 0x18: // gentime
      year = str.slice(0, 4) | 0;
      mon = str.slice(4, 6) | 0;
      day = str.slice(6, 8) | 0;
      hour = str.slice(8, 10) | 0;
      min = str.slice(10, 12) | 0;
      sec = str.slice(12, 14) | 0;
      break;
    default:
      assert(false);
      break;
  }

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0) / 1000;
};

ASN1.parseOID = function parseOID(data) {
  var p = BufferReader(data);
  var tag = ASN1.parseTag(p);
  var ids = [];
  var ident = 0;
  var subident = 0;
  var objid, result, first, second;

  assert.equal(tag.tag, 0x06); // objid

  objid = p.readBytes(tag.len, true);
  p = BufferReader(objid);

  while (p.left()) {
    subident = p.readU8();
    ident <<= 7;
    ident |= subident & 0x7f;
    if ((subident & 0x80) === 0) {
      ids.push(ident);
      ident = 0;
    }
  }

  if (subident & 0x80)
    ids.push(ident);

  first = (ids[0] / 40) | 0;
  second = ids[0] % 40;
  result = [first, second].concat(ids.slice(1));

  return result.join('.');
};

ASN1.parseAlgIdent = function parseAlgIdent(data) {
  var p = BufferReader(data);
  var params = null;
  var alg;

  p = BufferReader(ASN1.parseSeq(p));

  alg = ASN1.parseOID(p);

  if (p.left() > 0) {
    params = p.readBytes(ASN1.parseTag(p).len, true);
    if (params.length === 0)
      params = null;
  }

  return {
    alg: alg,
    params: params
  };
};

ASN1.parseRSAPublic = function parseRSAPublic(data) {
  var p = BufferReader(data);
  p = BufferReader(ASN1.parseSeq(p));
  return {
    modulus: ASN1.parseInt(p),
    publicExponent: ASN1.parseInt(p)
  };
};

ASN1.parseRSAPrivate = function parseRSAPrivate(data) {
  var p = BufferReader(data);
  p = BufferReader(ASN1.parseSeq(p));
  return {
    version: ASN1.parseInt(p, true),
    modulus: ASN1.parseInt(p),
    publicExponent: ASN1.parseInt(p),
    privateExponent: ASN1.parseInt(p),
    prime1: ASN1.parseInt(p),
    prime2: ASN1.parseInt(p),
    exponent1: ASN1.parseInt(p),
    exponent2: ASN1.parseInt(p),
    coefficient: ASN1.parseInt(p)
  };
};

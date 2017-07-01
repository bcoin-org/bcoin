/*!
 * asn1.js - asn1 parsing for bcoin
 * Copyright (c) 2016-2017, Christopher Jeffrey (MIT License).
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

const BufferReader = require('./reader');

/**
 * @exports utils/asn1
 */

const ASN1 = exports;

/**
 * Read next tag.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readTag = function readTag(br) {
  let type = br.readU8();
  let primitive = (type & 0x20) === 0;
  let oct;

  if ((type & 0x1f) === 0x1f) {
    oct = type;
    type = 0;
    while ((oct & 0x80) === 0x80) {
      oct = br.readU8();
      type <<= 7;
      type |= oct & 0x7f;
    }
  } else {
    type &= 0x1f;
  }

  return {
    type: type,
    primitive: primitive,
    size: ASN1.readSize(br, primitive)
  };
};

/**
 * Read tag size.
 * @param {BufferReader} br
 * @param {Boolean} primitive
 * @returns {Number}
 * @throws on indefinite size
 */

ASN1.readSize = function readSize(br, primitive) {
  let size = br.readU8();
  let bytes, i, j;

  // Indefinite form
  if (!primitive && size === 0x80)
    throw new Error('Indefinite size.');

  // Definite form
  if ((size & 0x80) === 0) {
    // Short form
    return size;
  }

  // Long form
  bytes = size & 0x7f;

  if (bytes > 3)
    throw new Error('Length octet is too long.');

  size = 0;
  for (i = 0; i < bytes; i++) {
    size <<= 8;
    j = br.readU8();
    size |= j;
  }

  return size;
};

/**
 * Read implicit SEQ.
 * @param {BufferReader} br
 * @returns {Buffer}
 */

ASN1.readSeq = function readSeq(br) {
  let tag = ASN1.implicit(br, 0x10);
  return br.readBytes(tag.size);
};

/**
 * Read next tag and assert implicit.
 * @param {BufferReader} br
 * @param {Number} type
 * @returns {Object}
 * @throws on unexpected tag
 */

ASN1.implicit = function implicit(br, type) {
  let tag = ASN1.readTag(br);
  if (tag.type !== type)
    throw new Error(`Unexpected tag: ${tag.type}.`);
  return tag;
};

/**
 * Read implicit tag.
 * @param {BufferReader} br
 * @param {Number} type
 * @returns {Boolean}
 */

ASN1.explicit = function explicit(br, type) {
  let offset = br.offset;
  let tag = ASN1.readTag(br);
  if (tag.type !== type) {
    br.offset = offset;
    return false;
  }
  return true;
};

/**
 * Read next implicit SEQ and return a new reader.
 * @param {BufferReader} br
 * @returns {BufferReader}
 */

ASN1.seq = function seq(br) {
  return new BufferReader(ASN1.readSeq(br), true);
};

/**
 * Read implicit int.
 * @param {BufferReader} br
 * @param {Boolean?} readNum
 * @returns {Buffer|Number}
 */

ASN1.readInt = function readInt(br, readNum) {
  let tag = ASN1.implicit(br, 0x02);
  let num = br.readBytes(tag.size);

  if (readNum)
    return num.readUIntBE(0, num.length);

  return num;
};

/**
 * Read explicit int.
 * @param {BufferReader} br
 * @param {Number} type
 * @param {Boolean?} readNum
 * @returns {Buffer|Number} `-1` on not present.
 */

ASN1.readExplicitInt = function readExplicitInt(br, type, readNum) {
  if (!ASN1.explicit(br, type))
    return -1;
  return ASN1.readInt(br, readNum);
};

/**
 * Read and align an implicit bitstr.
 * @param {BufferReader} br
 * @returns {Buffer}
 */

ASN1.readBitstr = function readBitstr(br) {
  let tag = ASN1.implicit(br, 0x03);
  let str = br.readBytes(tag.size);
  return ASN1.alignBitstr(str);
};

/**
 * Read an implicit string (any type).
 * @param {BufferReader} br
 * @returns {String}
 */

ASN1.readString = function readString(br) {
  let tag = ASN1.readTag(br);
  let str;

  switch (tag.type) {
    case 0x03: // bitstr
      str = br.readBytes(tag.size);
      return ASN1.alignBitstr(str);
    // Note:
    // Fuck all these.
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
      return br.readString('utf8', tag.size);
    default:
      throw new Error(`Unexpected tag: ${tag.type}.`);
  }
};

/**
 * Align a bitstr.
 * @param {Buffer} data
 * @returns {Buffer}
 */

ASN1.alignBitstr = function alignBitstr(data) {
  let padding = data[0];
  let bits = (data.length - 1) * 8 - padding;
  let buf = data.slice(1);
  let shift = 8 - (bits % 8);
  let i, out;

  if (shift === 8 || buf.length === 0)
    return buf;

  out = Buffer.allocUnsafe(buf.length);
  out[0] = buf[0] >>> shift;

  for (i = 1; i < buf.length; i++) {
    out[i] = buf[i - 1] << (8 - shift);
    out[i] |= buf[i] >>> shift;
  }

  return out;
};

/**
 * Read an entire certificate.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readCert = function readCert(br) {
  let buf = br;

  buf.start();

  br = ASN1.seq(buf);

  return {
    tbs: ASN1.readTBS(br),
    sigAlg: ASN1.readAlgIdent(br),
    sig: ASN1.readBitstr(br),
    raw: buf.endData(true)
  };
};

/**
 * Read only the TBS certificate.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readTBS = function readTBS(br) {
  let buf = br;

  buf.start();

  br = ASN1.seq(buf);

  return {
    version: ASN1.readExplicitInt(br, 0x00, true),
    serial: ASN1.readInt(br),
    sig: ASN1.readAlgIdent(br),
    issuer: ASN1.readName(br),
    validity: ASN1.readValidity(br),
    subject: ASN1.readName(br),
    pubkey: ASN1.readPubkey(br),
    raw: buf.endData(true)
  };
};

/**
 * Read an implicit pubkey.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readPubkey = function readPubkey(br) {
  br = ASN1.seq(br);
  return {
    alg: ASN1.readAlgIdent(br),
    pubkey: ASN1.readBitstr(br)
  };
};

/**
 * Read implicit name.
 * @param {BufferReader} br
 * @returns {Object[]}
 */

ASN1.readName = function readName(br) {
  let values = [];

  br = ASN1.seq(br);

  while (br.left()) {
    ASN1.implicit(br, 0x11); // set
    ASN1.implicit(br, 0x10); // seq
    values.push({
      type: ASN1.readOID(br),
      value: ASN1.readString(br)
    });
  }

  return values;
};

/**
 * Read implicit validity timerange.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readValidity = function readValidity(br) {
  br = ASN1.seq(br);
  return {
    notBefore: ASN1.readTime(br),
    notAfter: ASN1.readTime(br)
  };
};

/**
 * Read implicit timestamp.
 * @param {BufferReader} br
 * @returns {Number}
 */

ASN1.readTime = function readTime(br) {
  let tag = ASN1.readTag(br);
  let str = br.readString('ascii', tag.size);
  let year, mon, day, hour, min, sec;

  switch (tag.type) {
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
      throw new Error(`Unexpected tag: ${tag.type}.`);
  }

  return Date.UTC(year, mon - 1, day, hour, min, sec, 0) / 1000;
};

/**
 * Read and format OID to string.
 * @param {BufferReader} br
 * @returns {String}
 */

ASN1.readOID = function readOID(br) {
  let tag = ASN1.implicit(br, 0x06);
  let data = br.readBytes(tag.size);
  return ASN1.formatOID(data);
};

/**
 * Format an OID buffer to a string.
 * @param {Buffer} data
 * @returns {String}
 */

ASN1.formatOID = function formatOID(data) {
  let br = new BufferReader(data);
  let ids = [];
  let ident = 0;
  let subident = 0;
  let result, first, second;

  while (br.left()) {
    subident = br.readU8();
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

/**
 * Read algorithm identifier.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readAlgIdent = function readAlgIdent(br) {
  let params = null;
  let alg, tag;

  br = ASN1.seq(br);

  alg = ASN1.readOID(br);

  if (br.left() > 0) {
    tag = ASN1.readTag(br);
    params = br.readBytes(tag.size);
    if (params.length === 0)
      params = null;
  }

  return {
    alg: alg,
    params: params
  };
};

/**
 * Read RSA public key.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readRSAPublic = function readRSAPublic(br) {
  br = ASN1.seq(br);
  return {
    modulus: ASN1.readInt(br),
    publicExponent: ASN1.readInt(br)
  };
};

/**
 * Read RSA private key.
 * @param {BufferReader} br
 * @returns {Object}
 */

ASN1.readRSAPrivate = function readRSAPrivate(br) {
  br = ASN1.seq(br);
  return {
    version: ASN1.readInt(br, true),
    modulus: ASN1.readInt(br),
    publicExponent: ASN1.readInt(br),
    privateExponent: ASN1.readInt(br),
    prime1: ASN1.readInt(br),
    prime2: ASN1.readInt(br),
    exponent1: ASN1.readInt(br),
    exponent2: ASN1.readInt(br),
    coefficient: ASN1.readInt(br)
  };
};

/**
 * Read RSA public key from buffer.
 * @param {Buffer} data
 * @returns {Object}
 */

ASN1.parseRSAPublic = function parseRSAPublic(data) {
  return ASN1.readRSAPublic(new BufferReader(data, true));
};

/**
 * Read RSA private key from buffer.
 * @param {Buffer} data
 * @returns {Object}
 */

ASN1.parseRSAPrivate = function parseRSAPrivate(data) {
  return ASN1.readRSAPrivate(new BufferReader(data, true));
};

/**
 * Read certificate from buffer.
 * @param {Buffer} data
 * @returns {Object}
 */

ASN1.parseCert = function parseCert(data) {
  return ASN1.readCert(new BufferReader(data, true));
};

/**
 * Read TBS certificate from buffer.
 * @param {Buffer} data
 * @returns {Object}
 */

ASN1.parseTBS = function parseTBS(data) {
  return ASN1.readTBS(new BufferReader(data, true));
};

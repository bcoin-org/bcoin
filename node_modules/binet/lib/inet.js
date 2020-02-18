/*!
 * inet.js - inet pton/ntop for bcoin
 * Copyright (c) 2018, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 *
 * Parts of this software are based on c-ares:
 *   Copyright (c) 2007-2018, Daniel Stenberg (MIT License)
 *   https://github.com/c-ares/c-ares
 *   https://github.com/c-ares/c-ares/blob/master/inet_net_pton.c
 *   https://github.com/c-ares/c-ares/blob/master/inet_ntop.c
 */

/* eslint spaced-comment: "off" */

'use strict';

const assert = require('bsert');

/*
 * Constants
 */

const ENOENT = 1;
const EMSGSIZE = 2;

const POOL16 = Buffer.allocUnsafe(16);
const BUFFER16 = Buffer.allocUnsafe(16);
const UINT16 = new Uint16Array(16 / 2);

const CHARSET = [
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
];

const TABLE = new Int8Array([
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, 10, 11, 12, 13, 14, 15, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
]);

/*
 * Presentation to Network
 */

function pton4(src, dst, off) {
  if (dst == null)
    dst = null;

  if (off == null)
    off = 0;

  assert(typeof src === 'string');
  assert(dst === null || Buffer.isBuffer(dst));
  assert((off >>> 0) === off);

  const start = off;

  let i = 0;
  let ch = -1;
  let first = -1;

  if (dst) {
    if (off + 4 > dst.length)
      return -ENOENT;
  }

  if (isHex(src, i)) {
    i += 2;

    let dirty = 0;
    let word = 0;
    let total = 0;

    for (; i < src.length; i++) {
      ch = byte(src, i);

      const n = TABLE[ch];

      if (n === -1)
        break;

      if (dirty === 0)
        word = n;
      else
        word = (word << 4) | n;

      total += 1;
      dirty += 1;

      if (total > 8)
        return -ENOENT;

      if (dirty === 2) {
        if ((off + 1) - start > 4)
          return -EMSGSIZE;

        if (dst)
          dst[off] = word;

        if (first === -1)
          first = word;

        off += 1;
        dirty = 0;
      }

      ch = -1;
    }

    if (dirty) {
      if ((off + 1) - start > 4)
        return -EMSGSIZE;

      if (dst)
        dst[off] = word << 4;

      if (first === -1)
        first = word << 4;

      off += 1;
    }
  } else if (isDecimal(src, i)) {
    let t = 0;

    for (;;) {
      let word = 0;
      let total = 0;

      for (; i < src.length; i++) {
        ch = byte(src, i);

        if (ch < 0x30 || ch > 0x39)
          break;

        word *= 10;
        word += ch - 0x30;
        total += 1;

        if (total > 3 || word > 255)
          return -ENOENT;

        ch = -1;
      }

      t += total;

      if (t > 12)
        return -ENOENT;

      if ((off + 1) - start > 4)
        return -EMSGSIZE;

      if (dst)
        dst[off] = word;

      if (first === -1)
        first = word;

      off += 1;

      if (ch === -1 || ch === 0x2f /*/*/)
        break;

      if (ch !== 0x2e /*.*/)
        return -ENOENT;

      i += 1;

      ch = byte(src, i);

      if (ch < 0x30 || ch > 0x39)
        return -ENOENT;
    }
  } else {
    return -ENOENT;
  }

  let bits = -1;

  if (isCIDR(src, i) && off > start) {
    i += 1;
    bits = 0;
    ch = -1;

    let total = 0;

    for (; i < src.length; i++) {
      ch = byte(src, i);

      if (ch < 0x30 || ch > 0x39)
        break;

      bits *= 10;
      bits += ch - 0x30;
      total += 1;

      if (total > 3 || bits > 32)
        return -ENOENT;

      ch = -1;
    }
  }

  if (ch !== -1)
    return -ENOENT;

  if (off === start)
    return -ENOENT;

  if (bits === -1) {
    assert(first !== -1);

    if (first >= 240)
      bits = 32;
    else if (first >= 224)
      bits = 8;
    else if (first >= 192)
      bits = 24;
    else if (first >= 128)
      bits = 16;
    else
      bits = 8;

    if (bits < (off - start) * 8)
      bits = (off - start) * 8;

    if (bits === 8 && first === 224)
      bits = 4;
  }

  assert(bits <= 32);

  const left = 4 - (off - start);
  assert(left >= 0 && left <= 4);

  if (dst) {
    assert(off + left <= dst.length);
    dst.fill(0x00, off, off + left);
  }

  off += left;

  return bits;
}

function pton6(src, dst, off) {
  if (dst == null)
    dst = null;

  if (off == null)
    off = 0;

  assert(typeof src === 'string');
  assert(dst === null || Buffer.isBuffer(dst));
  assert((off >>> 0) === off);

  const tmp = POOL16;

  let i = 0;
  let ptr = 0;
  let end = 16;
  let col = -1;
  let cur = 0;
  let digit = false;
  let word = 0;
  let digits = 0;
  let bits = -1;
  let inet4 = false;

  if (dst) {
    if (off + 16 > dst.length)
      return -EMSGSIZE;
  }

  if (isColon(src, i)) {
    if (!isColon(src, i + 1))
      return -ENOENT;
    i += 1;
  }

  tmp.fill(0x00, 0, 16);
  cur = i;

  for (; i < src.length; i++) {
    const ch = byte(src, i);
    const n = TABLE[ch];

    if (n !== -1) {
      word <<= 4;
      word |= n;

      digits += 1;

      if (digits > 4)
        return -ENOENT;

      digit = true;

      continue;
    }

    if (ch === 0x3a /*:*/) {
      cur = i + 1;

      if (!digit) {
        if (col !== -1)
          return -ENOENT;
        col = ptr;
        continue;
      }

      if (i === src.length)
        return -ENOENT;

      if (ptr + 2 > end)
        return -ENOENT;

      tmp[ptr++] = (word >>> 8) & 0xff;
      tmp[ptr++] = word & 0xff;

      digit = false;
      digits = 0;
      word = 0;

      continue;
    }

    if (ch === 0x2e /*.*/ && ptr + 4 <= end) {
      const b = getV4(src, cur, tmp, ptr);

      if (b !== -1) {
        if (b !== 0)
          bits = b;
        ptr += 4;
        digit = false;
        inet4 = true;
        break;
      }
    }

    if (ch === 0x2f /*/*/) {
      const b = getBits(src, i + 1);
      if (b !== -1) {
        bits = b;
        break;
      }
    }

    return -ENOENT;
  }

  if (digit) {
    if (ptr + 2 > end)
      return -ENOENT;

    tmp[ptr++] = (word >>> 8) & 0xff;
    tmp[ptr++] = word & 0xff;
  }

  if (bits === -1)
    bits = 128;

  assert(bits <= 128);

  let words = (bits + 15) / 16 | 0;

  if (words < 2)
    words = 2;

  if (inet4)
    words = 8;

  end = 2 * words;

  if (col !== -1) {
    const n = ptr - col;

    let i;

    if (ptr === end)
      return -ENOENT;

    for (i = 1; i <= n; i++) {
      tmp[end - i] = tmp[col + n - i];
      tmp[col + n - i] = 0;
    }

    ptr = end;
  }

  if (ptr !== end)
    return -ENOENT;

  const bytes = (bits + 7) / 8 | 0;
  const left = 16 - bytes;

  assert(bytes >= 0 && bytes <= 16);

  if (dst) {
    assert(off + bytes + left <= dst.length);
    off += tmp.copy(dst, off, 0, bytes);
    dst.fill(0x00, off, off + left);
    off += left;
  } else {
    off += bytes;
    off += left;
  }

  return bits;
}

function pton(af, src, dst, off) {
  if (dst == null)
    dst = null;

  if (off == null)
    off = 0;

  assert((af >>> 0) === af);
  assert(typeof src === 'string');
  assert(dst === null || Buffer.isBuffer(dst));
  assert((off >>> 0) === off);

  if (af === 4)
    return pton4(src, dst, off);

  if (af === 6)
    return pton6(src, dst, off);

  return -ENOENT;
}

/*
 * Network to Presentation
 */

function ntop4(src, off) {
  if (off == null)
    off = 0;

  assert(Buffer.isBuffer(src));
  assert((off >>> 0) === off);

  if (off + 4 > src.length)
    return '';

  let str = '';
  str += dec(src[off + 0]);
  str += '.';
  str += dec(src[off + 1]);
  str += '.';
  str += dec(src[off + 2]);
  str += '.';
  str += dec(src[off + 3]);

  return str;
}

function ntop6(src, off) {
  if (off == null)
    off = 0;

  assert(Buffer.isBuffer(src));
  assert((off >>> 0) === off);

  if (off + 16 > src.length)
    return '';

  let bestBase = -1;
  let bestLen = 0;
  let curBase = -1;
  let curLen = 0;
  let str = '';

  const words = UINT16;

  for (let i = 0; i < 16; i++)
    words[i] = 0;

  for (let i = 0; i < 16; i++)
    words[i >>> 1] |= src[off + i] << ((1 - (i & 1)) << 3);

  for (let i = 0; i < (16 / 2); i++) {
    if (words[i] === 0) {
      if (curBase === -1) {
        curBase = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
    } else {
      if (curBase !== -1) {
        if (bestBase === -1 || curLen > bestLen) {
          bestBase = curBase;
          bestLen = curLen;
        }
        curBase = -1;
      }
    }
  }

  if (curBase !== -1) {
    if (bestBase === -1 || curLen > bestLen) {
      bestBase = curBase;
      bestLen = curLen;
    }
  }

  if (bestBase !== -1 && bestLen < 2)
    bestBase = -1;

  for (let i = 0; i < (16 / 2); i++) {
    // Are we inside the best run of 0x00's?
    if (bestBase !== -1 && i >= bestBase && i < bestBase + bestLen) {
      if (i === bestBase)
        str += ':';
      continue;
    }

    // Are we following an initial run of 0x00s or any real hex?
    if (i !== 0)
      str += ':';

    // Is this address an encapsulated IPv4?
    if (i === 6
        && bestBase === 0
        && (bestLen === 6
        || (bestLen === 7 && words[7] !== 0x0001)
        || (bestLen === 5 && words[5] === 0xffff))) {
      const s = ntop4(src, off + 12);

      if (!s)
        return '';

      str += s;

      break;
    }

    str += hex(words[i]);
  }

  // Was it a trailing run of 0x00's?
  if (bestBase !== -1 && bestBase + bestLen === 16 / 2)
    str += ':';

  return str;
}

function ntop(af, src, off) {
  if (off == null)
    off = 0;

  assert((af >>> 0) === af);
  assert(Buffer.isBuffer(src));
  assert((off >>> 0) === off);

  if (af === 4)
    return ntop4(src, off);

  if (af === 6)
    return ntop6(src, off);

  return '';
}

/*
 * Public Helpers
 */

function family(str) {
  if (pton4(str, null, 0) >= 0)
    return 4;

  if (pton6(str, null, 0) >= 0)
    return 6;

  return 0;
}

function mapped(raw, off) {
  if (off == null)
    off = 0;

  assert(Buffer.isBuffer(raw));
  assert((off >>> 0) === off);

  if (off + 12 > raw.length)
    return false;

  return raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0x00
      && raw[off++] === 0xff
      && raw[off++] === 0xff;
}

function onion(raw, off) {
  if (off == null)
    off = 0;

  assert(Buffer.isBuffer(raw));
  assert((off >>> 0) === off);

  if (off + 6 > raw.length)
    return false;

  return raw[off++] === 0xfd
      && raw[off++] === 0x87
      && raw[off++] === 0xd8
      && raw[off++] === 0x7e
      && raw[off++] === 0xeb
      && raw[off++] === 0x43;
}

function normalize(str) {
  const raw = BUFFER16;

  if (pton4(str, raw, 0) >= 0)
    return ntop4(raw, 0);

  if (pton6(str, raw, 0) >= 0)
    return ntop6(raw, 0);

  return '';
}

/*
 * Helpers
 */

function byte(str, i) {
  const ch = str.charCodeAt(i);

  if (ch & 0xff80)
    return 0x00;

  return ch;
}

function dec(ch, i) {
  return ch.toString(10);
}

function hex(w) {
  let str = '';

  for (let i = 3; i >= 0; i--) {
    const n = (w >>> (i * 4)) & 0x0f;

    if (n === 0 && str.length === 0)
      continue;

    str += CHARSET[n];
  }

  if (str.length === 0)
    str += CHARSET[0];

  return str;
}

function isDecimal(str, i) {
  if (i + 1 > str.length)
    return false;

  const ch = byte(str, i);

  return ch >= 0x30 && ch <= 0x39;
}

function isHex(str, i) {
  if (i + 3 > str.length)
    return false;

  const a = byte(str, i);

  if (a !== 0x30 /*0*/)
    return false;

  const b = byte(str, i + 1);

  if (b !== 0x58 /*X*/ && b !== 0x78 /*x*/)
    return false;

  const c = byte(str, i + 2);

  if (TABLE[c] === -1)
    return false;

  return true;
}

function isCIDR(str, i) {
  if (i + 2 > str.length)
    return false;

  const a = byte(str, i);

  if (a !== 0x2f /*/*/)
    return false;

  const b = byte(str, i + 1);

  if (b < 0x30 || b > 0x39)
    return false;

  return true;
}

function isColon(str, i) {
  if (i + 1 > str.length)
    return false;

  return byte(str, i) === 0x3a /*:*/;
}

function getBits(src, i) {
  let word = 0;
  let total = 0;

  for (; i < src.length; i++) {
    const ch = byte(src, i);

    if (ch < 0x30 || ch > 0x39)
      return -1;

    if (total > 0 && word === 0)
      return -1;

    word *= 10;
    word += ch - 0x30;
    total += 1;

    if (total > 3 || word > 128)
      return -1;
  }

  if (total === 0)
    return -1;

  return word;
}

function getV4(src, i, dst, off) {
  const start = off;

  let word = 0;
  let total = 0;

  for (; i < src.length; i++) {
    const ch = byte(src, i);

    if (ch >= 0x30 && ch <= 0x39) {
      if (total > 0 && word === 0)
        return -1;

      word *= 10;
      word += ch - 0x30;
      total += 1;

      if (total > 3 || word > 255)
        return -1;

      continue;
    }

    if (ch === 0x2e /*.*/ || ch === 0x2f /*/*/) {
      if (off - start > 3)
        return -1;

      if (dst) {
        if (off + 1 > dst.length)
          return -1;
        dst[off] = word;
      }

      off += 1;

      if (ch === 0x2f)
        return getBits(src, i + 1);

      word = 0;
      total = 0;

      continue;
    }

    return -1;
  }

  if (total === 0)
    return -1;

  if (off - start > 3)
    return -1;

  if (dst) {
    if (off + 1 > dst.length)
      return -1;
    dst[off] = word;
  }

  off += 1;

  return 0;
}

/*
 * Expose
 */

exports.pton4 = pton4;
exports.pton6 = pton6;
exports.pton = pton;

exports.ntop4 = ntop4;
exports.ntop6 = ntop6;
exports.ntop = ntop;

exports.family = family;
exports.mapped = mapped;
exports.onion = onion;
exports.normalize = normalize;

/*!
 * Unorm
 * https://github.com/walling/unorm
 *
 * The software dual licensed under the MIT and GPL licenses. MIT license:
 *
 * Copyright (c) 2008-2013
 * Matsuza <matsuza@gmail.com>,
 * Bjarke Walling <bwp@bwp.dk>
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
 *
 * GPL notice (please read the [full GPL license] online):
 *
 * Copyright (C) 2008-2013
 * Matsuza <matsuza@gmail.com>,
 * Bjarke Walling <bwp@bwp.dk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * [full GPL license]: http://www.gnu.org/licenses/gpl-2.0-standalone.html
*/

'use strict';

const udata = require('./udata.json');
const DEFAULT_FEATURE = [null, 0, {}];
const CACHE_THRESHOLD = 10;
const SBase = 0xac00;
const LBase = 0x1100;
const VBase = 0x1161;
const TBase = 0x11a7;
const LCount = 19;
const VCount = 21;
const TCount = 28;
const NCount = VCount * TCount; // 588
const SCount = LCount * NCount; // 11172

const cache = {};
const cacheCounter = [];

for (let i = 0; i <= 0xff; i++)
  cacheCounter[i] = 0;

let fromCharCode = null;

class UChar {
  constructor(cp, feature) {
    this.codepoint = cp;
    this.feature = feature;
  }

  static isHighSurrogate(cp) {
    return cp >= 0xd800 && cp <= 0xdbff;
  }

  static isLowSurrogate(cp) {
    return cp >= 0xdc00 && cp <= 0xdfff;
  }

  prepFeature() {
    if (!this.feature)
      this.feature = fromCharCode(this.codepoint, true).feature;
  }

  toString() {
    if (this.codepoint < 0x10000)
      return String.fromCharCode(this.codepoint);

    const x = this.codepoint - 0x10000;

    return String.fromCharCode(
      Math.floor(x / 0x400) + 0xd800,
      x % 0x400 + 0xdc00
    );
  }

  getDecomp() {
    this.prepFeature();
    return this.feature[0] || null;
  }

  isCompatibility() {
    this.prepFeature();
    return Boolean(this.feature[1]) && (this.feature[1] & (1 << 8)) !== 0;
  }

  isExclude() {
    this.prepFeature();
    return Boolean(this.feature[1]) && (this.feature[1] & (1 << 9)) !== 0;
  }

  getCanonicalClass() {
    this.prepFeature();
    return this.feature[1] ? (this.feature[1] & 0xff) : 0;
  }

  getComposite(following) {
    this.prepFeature();

    if (!this.feature[2])
      return null;

    const cp = this.feature[2][following.codepoint];

    return cp ? fromCharCode(cp) : null;
  }
}

function fromCache(next, cp, needFeature) {
  let ret = cache[cp];

  if (!ret) {
    ret = next(cp, needFeature);
    if (ret.feature && ++cacheCounter[(cp >> 8) & 0xff] > CACHE_THRESHOLD)
      cache[cp] = ret;
  }

  return ret;
}

function fromData(next, cp, needFeature) {
  const hash = cp & 0xff00;
  const dunit = udata[hash] || {};
  const f = dunit[cp];
  return f ? new UChar(cp, f) : new UChar(cp, DEFAULT_FEATURE);
}

function fromCpOnly(next, cp, needFeature) {
  return needFeature ? next(cp, needFeature) : new UChar(cp, null);
}

function fromRuleBasedJamo(next, cp, needFeature) {
  if (cp < LBase
      || (LBase + LCount <= cp && cp < SBase)
      || (SBase + SCount < cp)) {
    return next(cp, needFeature);
  }

  if (LBase <= cp && cp < LBase + LCount) {
    const c = {};
    const base = (cp - LBase) * VCount;

    for (let j = 0; j < VCount; j++)
      c[VBase + j] = SBase + TCount * (j + base);

    return new UChar(cp, [null, null, c]);
  }

  const SIndex = cp - SBase;
  const TIndex = SIndex % TCount;
  const feature = [];

  if (TIndex !== 0) {
    feature[0] = [SBase + SIndex - TIndex, TBase + TIndex];
  } else {
    feature[0] = [
      LBase + Math.floor(SIndex / NCount),
      VBase + Math.floor((SIndex % NCount) / TCount)
    ];
    feature[2] = {};
    for (let j = 1; j < TCount; j++)
      feature[2][TBase + j] = cp + j;
  }

  return new UChar(cp, feature);
}

function fromCpFilter(next, cp, needFeature) {
  return cp < 60 || 13311 < cp && cp < 42607
    ? new UChar(cp, DEFAULT_FEATURE)
    : next(cp, needFeature);
}

const strategies = [
  fromCpFilter,
  fromCache,
  fromCpOnly,
  fromRuleBasedJamo,
  fromData
];

fromCharCode = strategies.reduceRight((next, strategy) => {
  return (cp, needFeature) => {
    return strategy(next, cp, needFeature);
  };
}, null);

class UCharIterator {
  constructor(str) {
    this.str = str;
    this.cursor = 0;
  }
  next() {
    if (this.str && this.cursor < this.str.length) {
      let cp = this.str.charCodeAt(this.cursor++);

      if (UChar.isHighSurrogate(cp) && this.cursor < this.str.length) {
        const d = this.str.charCodeAt(this.cursor);
        if (UChar.isLowSurrogate(d)) {
          cp = (cp - 0xd800) * 0x400 + (d - 0xdc00) + 0x10000;
          this.cursor += 1;
        }
      }

      return fromCharCode(cp);
    }

    this.str = null;
    return null;
  }
}

class RecursDecompIterator {
  constructor(it, cano) {
    this.it = it;
    this.canonical = cano;
    this.resBuf = [];
  }

  recursiveDecomp(uchar) {
    const cano = this.canonical;
    const decomp = uchar.getDecomp();

    if (decomp && !(cano && uchar.isCompatibility())) {
      let ret = [];
      for (let i = 0; i < decomp.length; i++) {
        const a = this.recursiveDecomp(fromCharCode(decomp[i]));
        ret = ret.concat(a);
      }
      return ret;
    }

    return [uchar];
  }

  next() {
    if (this.resBuf.length === 0) {
      const uchar = this.it.next();

      if (!uchar)
        return null;

      this.resBuf = this.recursiveDecomp(uchar);
    }

    return this.resBuf.shift();
  }
}

class DecompIterator {
  constructor(it) {
    this.it = it;
    this.resBuf = [];
  }

  next() {
    if (this.resBuf.length === 0) {
      for (;;) {
        const uchar = this.it.next();

        if (!uchar)
          break;

        const cc = uchar.getCanonicalClass();

        let inspt = this.resBuf.length;

        if (cc !== 0) {
          while (inspt > 0) {
            const uchar2 = this.resBuf[inspt - 1];
            const cc2 = uchar2.getCanonicalClass();
            if (cc2 <= cc)
              break;
            inspt -= 1;
          }
        }

        this.resBuf.splice(inspt, 0, uchar);

        if (cc === 0)
          break;
      }
    }

    return this.resBuf.shift();
  }
}

class CompIterator {
  constructor(it) {
    this.it = it;
    this.procBuf = [];
    this.resBuf = [];
    this.lastClass = null;
  }
  next() {
    while (this.resBuf.length === 0) {
      const uchar = this.it.next();

      if (!uchar) {
        this.resBuf = this.procBuf;
        this.procBuf = [];
        break;
      }

      if (this.procBuf.length === 0) {
        this.lastClass = uchar.getCanonicalClass();
        this.procBuf.push(uchar);
        continue;
      }

      const starter = this.procBuf[0];
      const composite = starter.getComposite(uchar);
      const cc = uchar.getCanonicalClass();

      if (composite && (this.lastClass < cc || this.lastClass === 0)) {
        this.procBuf[0] = composite;
        continue;
      }

      if (cc === 0) {
        this.resBuf = this.procBuf;
        this.procBuf = [];
      }

      this.lastClass = cc;
      this.procBuf.push(uchar);
    }

    return this.resBuf.shift();
  }
}

function createIterator(mode, str) {
  switch (mode) {
    case 'NFD': {
      const it1 = new UCharIterator(str);
      const it2 = new RecursDecompIterator(it1, true);
      return new DecompIterator(it2);
    }
    case 'NFKD': {
      const it1 = new UCharIterator(str);
      const it2 = new RecursDecompIterator(it1, false);
      return new DecompIterator(it2);
    }
    case 'NFC': {
      const it1 = new UCharIterator(str);
      const it2 = new RecursDecompIterator(it1, true);
      const it3 = new DecompIterator(it2);
      return new CompIterator(it3);
    }
    case 'NFKC': {
      const it1 = new UCharIterator(str);
      const it2 = new RecursDecompIterator(it1, false);
      const it3 = new DecompIterator(it2);
      return new CompIterator(it3);
    }
  }

  throw new Error(`${mode} is invalid.`);
}

function normalize(mode, str) {
  const it = createIterator(mode, str);

  let ret = '';
  let uchar;

  for (;;) {
    uchar = it.next();

    if (!uchar)
      break;

    ret += uchar.toString();
  }

  return ret;
};

function nfd(str) {
  return normalize('NFD', str);
}

function nfkd(str) {
  return normalize('NFKD', str);
}

function nfc(str) {
  return normalize('NFC', str);
}

function nfkc(str) {
  return normalize('NFKC', str);
}

exports.nfc = nfc;
exports.nfd = nfd;
exports.nfkc = nfkc;
exports.nfkd = nfkd;

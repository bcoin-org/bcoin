/**
 * hd.js - hd seeds and keys (BIP32, BIP39) for bcoin.
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 */

/**
 * Code adapted from bitcore-lib:
 * https://github.com/bitpay/bitcore-lib/blob/master/lib/hdprivatekey.js
 * https://github.com/bitpay/bitcore-lib/blob/master/lib/hdpublickey.js
 * https://github.com/ryanxcharles/fullnode/blob/master/lib/bip32.js
 *
 * Copyright (c) 2013-2015 BitPay, Inc.
 *
 * Parts of this software are based on Bitcoin Core
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 *
 * Parts of this software are based on fullnode
 * Copyright (c) 2014 Ryan X. Charles
 * Copyright (c) 2014 reddit, Inc.
 *
 * Parts of this software are based on BitcoinJS
 * Copyright (c) 2011 Stefan Thomas <justmoon@members.fsf.org>
 *
 * Parts of this software are based on BitcoinJ
 * Copyright (c) 2011 Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

var hd = exports;

/**
 * Modules
 */

var bcoin = require('../bcoin');
var hash = require('hash.js');
var bn = require('bn.js');
var elliptic = require('elliptic');
var utils = bcoin.utils;
var assert = utils.assert;
var network = bcoin.protocol.network;

var EventEmitter = require('events').EventEmitter;

var english = require('../../etc/english.json');

var ec = elliptic.curves.secp256k1;

/**
 * HD Seeds
 */

function HDSeed(options) {
  if (!(this instanceof HDSeed))
    return new HDSeed(options);

  this.bits = options.bits || 128;
  this.entropy = options.entropy || HDSeed._entropy(this.bits / 8);
  this.mnemonic = options.mnemonic || HDSeed._mnemonic(this.entropy);
  if (options.passphrase !== undefined) {
    this.seed = this.createSeed(options.passphrase);
  }
}

HDSeed.create = function(options) {
  var obj = new HDSeed(options);
  return obj.seed || obj;
};

HDSeed.prototype.createSeed = function(passphrase) {
  this.passphrase = passphrase || '';
  return pbkdf2(this.mnemonic, 'mnemonic' + passphrase, 2048, 64);
};

HDSeed._entropy = function(size) {
  return randomBytes(size);
};

HDSeed._mnemonic = function(entropy) {
  var bin = '';
  var mnemonic = [];
  var i, wi;

  for (i = 0; i < entropy.length; i++)
    bin = bin + ('00000000' + entropy[i].toString(2)).slice(-8);

  for (i = 0; i < bin.length / 11; i++) {
    wi = parseInt(bin.slice(i * 11, (i + 1) * 11), 2);
    mnemonic.push(english[wi]);
  }

  return mnemonic.join(' ');
};

/**
 * HD Keys
 */

var HARDENED = 0x80000000;
var MAX_INDEX = 2 * HARDENED;
var MIN_ENTROPY = 128 / 8;
var MAX_ENTROPY = 512 / 8;
var PARENT_FINGER_PRINT_SIZE = 4;
var PATH_ROOTS = ['m', 'M', 'm\'', 'M\''];

/**
 * HD Private Key
 */

function HDPriv(options) {
  var data;

  if (!(this instanceof HDPriv))
    return new HDPriv(options);

  if (!options)
    options = { seed: new HDSeed({ passphrase: '' }) };

  if (typeof options === 'string' && options.indexOf('xprv') === 0)
    options = { xkey: options };

  if (options.passphrase !== undefined)
    options.seed = new HDSeed({ passphrase: options.passphrase });

  if (options.seed) {
    if (typeof options.seed === 'object' && !(options.seed instanceof HDSeed)) {
      options.seed = new HDSeed(options.seed);
    }
    this.seed = options.seed;
    data = this._seed(options.seed);
  } else if (options.xkey) {
    data = this._unbuild(options.xkey);
  } else {
    data = options;
  }

  this.master = options.master || this;

  data = this._normalize(data, network.prefixes.xprivkey);

  this.data = data;

  this._build(data);
}

HDPriv.prototype._normalize = function(data, version) {
  var b;

  data.version = version || network.prefixes.xprivkey;
  data.version = +data.version;

  data.depth = +data.depth;

  if (typeof data.parentFingerPrint === 'number') {
    b = [];
    utils.writeU32BE(b, data.parentFingerPrint, 0);
    data.parentFingerPrint = b;
  }

  data.childIndex = +data.childIndex;

  if (typeof data.chainCode === 'string')
    data.chainCode = utils.toArray(data.chainCode, 'hex');

  data.privateKey = data.privateKey || data.priv;
  if (data.privateKey) {
    if (data.privateKey.getPrivate)
      data.privateKey = data.privateKey.getPrivate().toArray();
    else if (typeof data.privateKey === 'string')
      data.privateKey = utils.toKeyArray(data.privateKey);
  }

  data.publicKey = data.publicKey || data.pub;
  if (data.publicKey) {
    if (data.publicKey.getPublic)
      data.publicKey = data.privateKey.getPublic(true, 'array');
    else if (typeof data.publicKey === 'string')
      data.publicKey = utils.toKeyArray(data.publicKey);
  }

  if (typeof data.checksum === 'number') {
    b = [];
    utils.writeU32BE(b, data.checksum, 0);
    data.checksum = b;
  }

  return data;
};

HDPriv.prototype._seed = function(seed) {
  if (seed instanceof HDSeed)
    seed = seed.seed;

  if (utils.isHex(seed))
    seed = utils.toArray(seed, 'hex');

  if (seed.length < MIN_ENTROPY || seed.length > MAX_ENTROPY)
    throw new Error('entropy not in range');

  var hash = sha512hmac(seed, 'Bitcoin seed');

  return {
    // version: network.prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: 0,
    childIndex: 0,
    chainCode: hash.slice(32, 64),
    privateKey: hash.slice(0, 32),
    checksum: null
  };
};

HDPriv.prototype._unbuild = function(xkey) {
  var raw = utils.fromBase58(xkey);
  var data = {};
  var off = 0;
  var hash;

  data.version = utils.readU32BE(raw, off);
  off += 4;
  data.depth = raw[off];
  off += 1;
  data.parentFingerPrint = utils.readU32BE(raw, off);
  off += 4;
  data.childIndex = utils.readU32BE(raw, off);
  off += 4;
  data.chainCode = raw.slice(off, off + 32);
  off += data.chainCode.length;
  off += 1; // nul byte
  data.privateKey = raw.slice(off, off + 32);
  off += data.privateKey.length;
  data.checksum = utils.readU32BE(raw, off);
  off += 4;

  hash = utils.dsha256(raw.slice(0, -4));
  if (data.checksum !== utils.readU32BE(hash, 0))
    throw new Error('checksum mismatch');

  return data;
};

HDPriv.prototype._build = function(data) {
  var sequence = [];
  var off = 0;
  var checksum, xprivkey, pair, privateKey, publicKey, size, fingerPrint;

  utils.writeU32BE(sequence, data.version, off);
  off += 4;
  sequence[off] = data.depth;
  off += 1;
  utils.copy(data.parentFingerPrint, sequence, off, true);
  off += data.parentFingerPrint.length;
  utils.writeU32BE(sequence, data.childIndex, off);
  off += 4;
  utils.copy(data.chainCode, sequence, off, true);
  off += data.chainCode.length;
  sequence[off] = 0;
  off += 1;
  utils.copy(data.privateKey, sequence, off, true);
  off += data.privateKey.length;
  checksum = utils.dsha256(sequence).slice(0, 4);
  utils.copy(checksum, sequence, off, true);
  off += 4;

  xprivkey = utils.toBase58(sequence);

  pair = bcoin.ecdsa.keyPair({ priv: data.privateKey });
  privateKey = pair.getPrivate().toArray();
  publicKey = pair.getPublic(true, 'array');

  size = PARENT_FINGER_PRINT_SIZE;
  fingerPrint = utils.ripesha(publicKey).slice(0, size);

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.privateKey = privateKey;
  // this.checksum = checksum;

  this.xprivkey = xprivkey;
  this.fingerPrint = fingerPrint;
  this.publicKey = publicKey;

  this.hdpub = new HDPub(this);
  this.xpubkey = this.hdpub.xpubkey;
  this.pair = bcoin.ecdsa.keyPair({ priv: this.privateKey });
};

HDPriv.prototype.derive = function(index, hard) {
  if (typeof index === 'string')
    return this.deriveString(index);

  var index_ = [];
  var data, hash, leftPart, chainCode, privateKey;

  hard = index >= HARDENED ? true : hard;
  if (index < HARDENED && hard === true)
    index += HARDENED;

  utils.writeU32BE(index_, index, 0);

  data = hard
    ? [0].concat(this.privateKey).concat(index_)
    : data = [].concat(this.publicKey).concat(index_);

  hash = sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = leftPart.add(new bn(this.privateKey)).mod(ec.curve.n).toArray();

  return new HDPriv({
    master: this.master,
    // version: this.version,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    privateKey: privateKey
  });
};

// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
HDPriv._getIndexes = function(path) {
  var steps = path.split('/');
  var root = steps.shift();
  var indexes = [];
  var i, step, hard, index;

  if (~PATH_ROOTS.indexOf(path))
    return indexes;

  if (!~PATH_ROOTS.indexOf(root))
    return null;

  for (i = 0; i < steps.length; i++) {
    step = steps[i];
    hard = step[step.length - 1] === '\'';

    if (hard)
      step = step.slice(0, -1);

    if (!step || step[0] === '-')
      return null;

    index = +step;
    if (hard)
      index += HARDENED;

    indexes.push(index);
  }

  return indexes;
};

HDPriv.isValidPath = function(path, hard) {
  if (typeof path === 'string') {
    var indexes = HDPriv._getIndexes(path);
    return indexes !== null && indexes.every(HDPriv.isValidPath);
  }

  if (typeof path === 'number') {
    if (path < HARDENED && hard === true) {
      path += HARDENED;
    }
    return path >= 0 && path < MAX_INDEX;
  }

  return false;
};

HDPriv.prototype.deriveString = function(path) {
  if (!HDPriv.isValidPath(path))
    throw new Error('invalid path');

  var indexes = HDPriv._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  });
};

/**
 * HD Public Key
 */

function HDPub(options) {
  var data;

  if (!(this instanceof HDPub))
    return new HDPub(options);

  if (typeof options === 'string' && options.indexOf('xpub') === 0)
    options = { xkey: options };

  data = options.xkey
    ? this._unbuild(options.xkey)
    : options;

  data = this._normalize(data, network.prefixes.xpubkey);

  this.data = data;

  this._build(data);
}

HDPub.prototype._normalize = HDPriv.prototype._normalize;

HDPub.prototype._unbuild = function(xkey) {
  var raw = utils.fromBase58(xkey);
  var data = {};
  var off = 0;
  var hash;

  data.version = utils.readU32BE(raw, off);
  off += 4;
  data.depth = raw[off];
  off += 1;
  data.parentFingerPrint = utils.readU32BE(raw, off);
  off += 4;
  data.childIndex = utils.readU32BE(raw, off);
  off += 4;
  data.chainCode = raw.slice(off, off + 32);
  off += data.chainCode.length;
  data.publicKey = raw.slice(off, off + 33);
  off += data.publicKey.length;
  data.checksum = utils.readU32BE(raw, off);
  off += 4;

  hash = utils.dsha256(raw.slice(0, -4));
  if (data.checksum !== utils.readU32BE(hash, 0))
    throw new Error('checksum mismatch');

  return data;
};

HDPub.prototype._build = function(data) {
  var sequence = [];
  var off = 0;
  var checksum, xpubkey, publicKey, size, fingerPrint;

  utils.writeU32BE(sequence, data.version, off);
  off += 4;
  sequence[off] = data.depth;
  off += 1;
  utils.copy(data.parentFingerPrint, sequence, off, true);
  off += data.parentFingerPrint.length;
  utils.writeU32BE(sequence, data.childIndex, off);
  off += 4;
  utils.copy(data.chainCode, sequence, off, true);
  off += data.chainCode.length;
  utils.copy(data.publicKey, sequence, off, true);
  off += data.publicKey.length;
  checksum = utils.dsha256(sequence).slice(0, 4);
  utils.copy(checksum, sequence, off, true);
  off += 4;

  if (!data.checksum || !data.checksum.length)
    data.checksum = checksum;
  else if (utils.toHex(checksum) !== utils.toHex(data.checksum))
    throw new Error('checksum mismatch');

  xpubkey = utils.toBase58(sequence);

  publicKey = data.publicKey;
  size = PARENT_FINGER_PRINT_SIZE;
  fingerPrint = utils.ripesha(publicKey).slice(0, size);

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.publicKey = publicKey;
  // this.checksum = checksum;

  this.xpubkey = xpubkey;
  this.fingerPrint = fingerPrint;

  this.xprivkey = data.xprivkey;
  this.pair = bcoin.ecdsa.keyPair({ pub: this.publicKey });
};

HDPub.prototype.derive = function(index, hard) {
  var index_ = [];
  var data, hash, leftPart, chainCode, pair, pubkeyPoint, publicKey;

  if (typeof index === 'string')
    return this.deriveString(index);

  if (index >= HARDENED || hard)
    throw new Error('invalid index');

  if (index < 0)
    throw new Error('invalid path');

  utils.writeU32BE(index_, index, 0);

  data = [].concat(this.publicKey).concat(index_);
  hash = sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  pair = bcoin.ecdsa.keyPair({ pub: this.publicKey });
  pubkeyPoint = ec.curve.g.mul(leftPart).add(pair.pub);
  publicKey = bcoin.ecdsa.keyFromPublic(pubkeyPoint).getPublic(true, 'array');

  return new HDPub({
    // version: network.prefixes.xpubkey,
    depth: this.depth + 1,
    parentFingerPrint: this.fingerPrint,
    childIndex: index,
    chainCode: chainCode,
    publicKey: publicKey
  });
};

HDPub.isValidPath = function(arg) {
  if (typeof arg === 'string') {
    var indexes = HDPriv._getIndexes(arg);
    return indexes !== null && indexes.every(HDPub.isValidPath);
  }

  if (typeof arg === 'number')
    return arg >= 0 && arg < HARDENED;

  return false;
};

HDPub.prototype.deriveString = function(path) {
  if (~path.indexOf('\''))
    throw new Error('cannot derive hardened');
  else if (!HDPub.isValidPath(path))
    throw new Error('invalid path');

  var indexes = HDPriv._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  });
};

/**
 * Make HD keys behave like elliptic KeyPairs
 */

[HDPriv, HDPub].forEach(function(HD) {
  HD.prototype.validate = function validate() {
    return this.pair.validate.apply(this.pair, arguments);
  };

  HD.prototype.getPublic = function getPublic() {
    return this.pair.getPublic.apply(this.pair, arguments);
  };

  HD.prototype.getPrivate = function getPrivate() {
    return this.pair.getPublic.apply(this.pair, arguments);
  };

  HD.prototype.sign = function sign(msg) {
    return this.pair.sign.apply(this.pair, arguments);
  };

  HD.prototype.verify = function verify(msg, signature) {
    return this.pair.verify.apply(this.pair, arguments);
  };

  // HD.prototype.inspect = function inspect() {
  //   return this.pair.inspect.apply(this.pair, arguments);
  // };

  HD.prototype.__defineGetter__('pub', function() {
    return this.pair.pub;
  });

  HD.prototype.__defineGetter__('priv', function() {
    return this.pair.priv;
  });
});

/**
 * Helpers
 */

var isBrowser = (typeof process !== 'undefined' && process.browser)
  || typeof window !== 'undefined';

function sha512hmac(data, salt) {
  if (isBrowser) {
    var hmac = hash.hmac(hash.sha512, utils.toArray(salt));
    return hmac.update(utils.toArray(data)).digest();
  }
  var crypto = require('crypto');
  var hmac = crypto.createHmac('sha512', new Buffer(salt));
  var h = hmac.update(new Buffer(data)).digest();
  return Array.prototype.slice.call(h);
}

function randomBytes(size) {
  if (isBrowser) {
    var a = Uint8Array(size);
    var buf = new Array(size);
    (window.crypto || window.msCrypto).getRandomValues(a);
    utils.copy(a, buf, 0);
    return buf;
  }
  var crypto = require('crypto');
  return Array.prototype.slice.call(crypto.randomBytes(size));
}

/**
 * PDKBF2
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2014, JP Richardson Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 */

function pbkdf2(key, salt, iterations, dkLen) {
  'use strict';

  var hLen = 64;

  if (dkLen > (Math.pow(2, 32) - 1) * hLen)
    throw Error('Requested key length too long');

  if (typeof key !== 'string' && typeof key.length !== 'number')
    throw new TypeError('key must a string or array');

  if (typeof salt !== 'string' && typeof salt.length !== 'number')
    throw new TypeError('salt must a string or array');

  if (typeof key === 'string')
    key = utils.toArray(key, null);

  if (typeof salt === 'string')
    salt = utils.toArray(salt, null);

  var DK = new Array(dkLen);
  var U = new Array(hLen);
  var T = new Array(hLen);
  var block1 = new Array(salt.length + 4);

  var l = Math.ceil(dkLen / hLen);
  var r = dkLen - (l - 1) * hLen;

  var i, j, k, destPos, len;

  utils.copy(salt.slice(0, salt.length), block1, 0);

  for (i = 1; i <= l; i++) {
    block1[salt.length + 0] = (i >> 24 & 0xff);
    block1[salt.length + 1] = (i >> 16 & 0xff);
    block1[salt.length + 2] = (i >> 8  & 0xff);
    block1[salt.length + 3] = (i >> 0  & 0xff);

    U = sha512hmac(block1, key);

    utils.copy(U.slice(0, hLen), T, 0);

    for (j = 1; j < iterations; j++) {
      U = sha512hmac(U, key);

      for (k = 0; k < hLen; k++)
        T[k] ^= U[k];
    }

    destPos = (i - 1) * hLen;
    len = (i === l ? r : hLen);
    utils.copy(T.slice(0, len), DK, 0);
  }

  return DK;
}

/**
 * Expose
 */

hd.seed = HDSeed;
hd.priv = HDPriv;
hd.pub = HDPub;
hd.pbkdf2 = pbkdf2;

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

/**
 * Modules
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = require('./utils');
var ec = require('./ec');
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;
var KeyPair = require('./keypair');
var LRU = require('./lru');
var BufferWriter = require('./writer');
var BufferReader = require('./reader');

var english = require('../../etc/english.json');

/**
 * HD Seeds
 */

function HDSeed(options) {
  if (!(this instanceof HDSeed))
    return new HDSeed(options);

  if (!options)
    options = {};

  this.bits = options.bits || 128;
  this.entropy = options.entropy;
  this.mnemonic = options.mnemonic;
  this.passphrase = options.passphrase || '';

  assert(this.bits % 8 === 0);
}

HDSeed.prototype.createSeed = function createSeed() {
  if (this.seed)
    return this.seed;

  if (!this.entropy)
    this.entropy = ec.random(this.bits / 8);

  if (!this.mnemonic)
    this.mnemonic = this.createMnemonic(this.entropy);

  this.seed = utils.pbkdf2(
    this.mnemonic,
    'mnemonic' + this.passphrase,
    2048, 64);

  return this.seed;
};

HDSeed.prototype.createMnemonic = function createMnemonic(entropy) {
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

HDSeed.isHDSeed = function isHDSeed(obj) {
  return obj
    && typeof obj.bits === 'number'
    && typeof obj.createSeed === 'function';
};

/**
 * Abstract
 */

function HD(options) {
  return new HDPrivateKey(options);
}

HD.fromBase58 = function fromBase58(xkey) {
  if (HDPrivateKey.isExtended(xkey))
    return HDPrivateKey.fromBase58(xkey);
  return HDPublicKey.fromBase58(xkey);
};

HD.generate = function generate(options, networkType) {
  return HDPrivateKey.generate(options, networkType);
};

HD.fromSeed = function fromSeed(options, networkType) {
  return HDPrivateKey.fromSeed(options, networkType);
};

HD.cache = new LRU(500);

HD.isHD = function isHD(obj) {
  return HDPrivateKey.isHDPrivateKey(obj)
    || HDPublicKey.isHDPublicKey(obj);
};

/**
 * HDPrivateKey
 */

function HDPrivateKey(options) {
  var data;

  if (!(this instanceof HDPrivateKey))
    return new HDPrivateKey(options);

  assert(options, 'No options for HD private key.');
  assert(!(options instanceof HDPrivateKey));
  assert(!(options instanceof HDPublicKey));

  if (HDPrivateKey.isExtended(options))
    options = { xkey: options };

  if (options.xpubkey)
    options.xkey = options.xpubkey;

  if (options.xprivkey)
    options.xkey = options.xprivkey;

  if (HDPublicKey.isExtended(options.xkey))
    return new HDPublicKey(options);

  this.networkType = options.networkType || network.type;
  this.xprivkey = options.xkey;
  this.seed = options.seed;

  if (options.data) {
    data = options.data;
  } else if (options.xkey) {
    data = HDPrivateKey.parse(options.xkey);
    this.networkType = data.networkType;
    data = data.data;
  } else if (options.seed) {
    data = HDPrivateKey._fromSeed(options.seed, this.networkType);
  } else {
    assert(false, 'No data passed to HD key.');
  }

  assert(data.depth <= 0xff, 'Depth is too high.');

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.privateKey = data.privateKey;

  this.publicKey = ec.publicKeyCreate(data.privateKey, true);
  this.fingerPrint = null;

  this.hdPrivateKey = this;

  if (!this.xprivkey)
    this.xprivkey = HDPrivateKey.render(data);

  this.isPrivate = true;
  this.isPublic = false;
}

utils.inherits(HDPrivateKey, HD);

HDPrivateKey.prototype.__defineGetter__('hdPublicKey', function() {
  if (!this._hdPublicKey) {
    this._hdPublicKey = new HDPublicKey({
      networkType: this.networkType,
      data: {
        version: network[this.networkType].prefixes.xpubkey,
        depth: this.depth,
        parentFingerPrint: this.parentFingerPrint,
        childIndex: this.childIndex,
        chainCode: this.chainCode,
        publicKey: this.publicKey
      }
    });
  }
  return this._hdPublicKey;
});

HDPrivateKey.prototype.__defineGetter__('xpubkey', function() {
  return this.hdPublicKey.xpubkey;
});

HDPrivateKey.prototype.derive = function derive(index, hardened) {
  var cached, p, data, hash, leftPart, chainCode, privateKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xprivkey + '/' + index);

  if (cached)
    return cached;

  hardened = index >= constants.hd.hardened ? true : hardened;
  if (index < constants.hd.hardened && hardened)
    index += constants.hd.hardened;

  p = new BufferWriter();

  if (hardened) {
    p.writeU8(0);
    p.writeBytes(this.privateKey);
    p.writeU32BE(index);
  } else {
    p.writeBytes(this.publicKey);
    p.writeU32BE(index);
  }

  data = p.render();

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = leftPart
    .add(new bn(this.privateKey))
    .mod(ec.elliptic.curve.n)
    .toBuffer('be', 32);

  if (!this.fingerPrint) {
    this.fingerPrint = utils.ripesha(this.publicKey)
      .slice(0, constants.hd.parentFingerPrintSize);
  }

  child = new HDPrivateKey({
    networkType: this.networkType,
    data: {
      version: this.version,
      depth: this.depth + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      privateKey: privateKey
    }
  });

  HD.cache.set(this.xprivkey + '/' + index, child);

  return child;
};

HDPrivateKey.prototype.deriveAccount44 = function deriveAccount44(options) {
  var coinType, accountIndex, child;

  if (typeof options === 'number')
    options = { accountIndex: options };

  coinType = options.coinType;
  accountIndex = options.accountIndex;

  if (this instanceof HDPublicKey) {
    assert(this.isAccount44());
    return this;
  }

  if (coinType == null)
    coinType = this.networkType === 'main' ? 0 : 1;

  assert(utils.isFinite(coinType));
  assert(utils.isFinite(accountIndex));

  child = this
    .derive(44, true)
    .derive(coinType, true)
    .derive(accountIndex, true);

  assert(child.isAccount44());

  return child;
};

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45() {
  var child;

  if (this instanceof HDPublicKey) {
    assert(this.isPurpose45());
    return this;
  }

  child = this.derive(45, true);

  assert(child.isPurpose45());

  return child;
};

HDPrivateKey.prototype.isPurpose45 = function isPurpose45() {
  if (this.depth !== 1)
    return false;
  return this.childIndex === constants.hd.hardened + 45;
};

HDPrivateKey.prototype.isAccount44 = function isAccount44() {
  if (this.childIndex < constants.hd.hardened)
    return false;
  return this.depth === 3;
};

HDPrivateKey.isExtended = function isExtended(data) {
  if (typeof data !== 'string')
    return false;

  return network.xprivkeys[data.slice(0, 4)];
};

// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
HDPrivateKey._getIndexes = function _getIndexes(path) {
  var steps = path.split('/');
  var root = steps.shift();
  var indexes = [];
  var i, step, hardened, index;

  if (~constants.hd.pathRoots.indexOf(path))
    return indexes;

  if (!~constants.hd.pathRoots.indexOf(root))
    return null;

  for (i = 0; i < steps.length; i++) {
    step = steps[i];
    hardened = step[step.length - 1] === '\'';

    if (hardened)
      step = step.slice(0, -1);

    if (!step || step[0] === '-')
      return null;

    index = +step;

    if (hardened)
      index += constants.hd.hardened;

    indexes.push(index);
  }

  return indexes;
};

HDPrivateKey.isValidPath = function isValidPath(path, hardened) {
  var indexes;

  if (typeof path === 'string') {
    indexes = HDPrivateKey._getIndexes(path);
    return indexes !== null && indexes.every(HDPrivateKey.isValidPath);
  }

  if (typeof path === 'number') {
    if (path < constants.hd.hardened && hardened)
      path += constants.hd.hardened;
    return path >= 0 && path < constants.hd.maxIndex;
  }

  return false;
};

HDPrivateKey.prototype.derivePath = function derivePath(path) {
  var indexes;

  if (!HDPrivateKey.isValidPath(path))
    throw new Error('invalid path');

  indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  }, this);
};

HDPrivateKey._fromSeed = function _fromSeed(seed, networkType) {
  var data = seed.createSeed();
  var hash;

  if (data.length < constants.hd.minEntropy
      || data.length > constants.hd.maxEntropy) {
    throw new Error('Entropy not in range.');
  }

  hash = utils.sha512hmac(data, 'Bitcoin seed');

  return {
    version: networkType
      ? network[networkType].prefixes.xprivkey
      : network.prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: 0,
    chainCode: hash.slice(32, 64),
    privateKey: hash.slice(0, 32)
  };
};

HDPrivateKey.fromSeed = function fromSeed(options, networkType) {
  var seed, key;

  if (!options)
    options = {};

  seed = (options instanceof HDSeed)
    ? options
    : new HDSeed(options);

  key = new HDPrivateKey({
    data: HDPrivateKey._fromSeed(seed, networkType)
  });

  key.seed = seed;

  return key;
};

HDPrivateKey._generate = function _generate(options, networkType) {
  if (!options)
    opitons = {};

  if (Buffer.isBuffer(options))
    options = { privateKey: options };

  if (!options.privateKey)
    options.privateKey = ec.generatePrivateKey();

  if (!options.entropy)
    options.entropy = ec.random(32);

  return {
    version: networkType
      ? network[networkType].prefixes.xprivkey
      : network.prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: 0,
    chainCode: entropy,
    privateKey: privateKey
  };
};

HDPrivateKey.generate = function generate(options, networkType) {
  return new HDPrivateKey({
    data: HDPrivateKey._generate(options, networkType)
  });
};

HDPrivateKey.parse = function parse(xkey) {
  var raw = utils.fromBase58(xkey);
  var p = new BufferReader(raw, true);
  var data = {};
  var i, type, prefix;

  data.version = p.readU32BE();
  data.depth = p.readU8();
  data.parentFingerPrint = p.readBytes(4);
  data.childIndex = p.readU32BE();
  data.chainCode = p.readBytes(32);
  p.readU8();
  data.privateKey = p.readBytes(32);
  p.verifyChecksum();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xprivkey;
    if (data.version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  return {
    networkType: type,
    xprivkey: xkey,
    data: data
  };
};

HDPrivateKey.fromBase58 = function fromBase58(xkey) {
  var data = HDPrivateKey.parse(xkey);
  return new HDPrivateKey(data);
};

HDPrivateKey.render = function render(data) {
  var p = new BufferWriter();
  p.writeU32BE(data.version);
  p.writeU8(data.depth);
  p.writeBytes(data.parentFingerPrint);
  p.writeU32BE(data.childIndex);
  p.writeBytes(data.chainCode);
  p.writeU8(0);
  p.writeBytes(data.privateKey);
  p.writeChecksum();
  return utils.toBase58(p.render());
};

HDPrivateKey.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'hdkey',
    encrypted: false
  };

  if (this instanceof HDPrivateKey) {
    json.encrypted = passphrase ? true : false;
    if (this.seed) {
      json.mnemonic = passphrase
        ? utils.encrypt(this.seed.mnemonic, passphrase)
        : this.seed.mnemonic;
      json.passphrase = passphrase
        ? utils.encrypt(this.seed.passphrase, passphrase)
        : this.seed.passphrase;
    }
    json.xprivkey = passphrase
      ? utils.encrypt(this.xprivkey, passphrase)
      : this.xprivkey;
    return json;
  }

  json.xpubkey = this.xpubkey;

  return json;
};

HDPrivateKey._fromJSON = function _fromJSON(json, passphrase) {
  var data = {};

  assert.equal(json.v, 1);
  assert.equal(json.name, 'hdkey');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt address');

  if (json.mnemonic) {
    data.seed = {
      mnemonic: json.encrypted
        ? utils.decrypt(json.mnemonic, passphrase)
        : json.mnemonic,
      passphrase: json.encrypted
        ? utils.decrypt(json.passphrase, passphrase)
        : json.passphrase
    };
    if (!json.xprivkey)
      return data;
  }

  if (json.xprivkey) {
    data.xprivkey = json.encrypted
      ? utils.decrypt(json.xprivkey, passphrase)
      : json.xprivkey;
    return data;
  }

  if (json.xpubkey) {
    return {
      xpubkey: json.xpubkey
    };
  }

  assert(false);
};

HDPrivateKey.fromJSON = function fromJSON(json, passphrase) {
  var key;

  json = HDPrivateKey._fromJSON(json, passphrase);

  if (json.xprivkey) {
    key = HDPrivateKey.fromBase58(json.xprivkey);
    key.seed = json.seed ? new HDSeed(json.seed) : null;
    return key;
  }

  if (json.seed)
    return HDPrivateKey.fromSeed(json.seed);

  if (json.xpubkey)
    return HDPublicKey.fromBase58(json.xprivkey);

  assert(false, 'Could not handle HD key JSON.');
};

HDPublicKey.isHDPrivateKey = function isHDPrivateKey(obj) {
  return obj && obj.isPrivate && typeof obj.derive === 'function';
};

/**
 * HDPublicKey
 */

function HDPublicKey(options) {
  var data;

  if (!(this instanceof HDPublicKey))
    return new HDPublicKey(options);

  assert(options, 'No options for HDPublicKey');
  assert(!(options instanceof HDPrivateKey));
  assert(!(options instanceof HDPublicKey));

  if (HDPublicKey.isExtended(options))
    options = { xkey: options };

  if (options.xprivkey)
    options.xkey = options.xprivkey;

  if (options.xpubkey)
    options.xkey = options.xpubkey;

  if (HDPrivateKey.isExtended(options.xkey))
    throw new Error('Cannot pass xprivkey into HDPublicKey');

  this.networkType = options.networkType || network.type;
  this.xpubkey = options.xkey;

  if (options.data) {
    data = options.data;
  } else if (options.xkey) {
    data = HDPublicKey.parse(options.xkey);
    this.networkType = data.networkType;
    data = data.data;
  } else {
    assert(false, 'No data passed to HD key.');
  }

  assert(data.depth <= 0xff, 'Depth is too high.');

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.publicKey = data.publicKey;

  this.privateKey = null;
  this.fingerPrint = null;

  this.hdPublicKey = this;

  this.hdPrivateKey = null;
  this.xprivkey = null;

  if (!this.xpubkey)
    this.xpubkey = HDPublicKey.render(data);

  this.isPrivate = false;
  this.isPublic = true;
}

utils.inherits(HDPublicKey, HD);

HDPublicKey.prototype.derive = function derive(index, hardened) {
  var cached, p, data, hash, leftPart, chainCode;
  var publicPoint, point, publicKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xpubkey + '/' + index);

  if (cached)
    return cached;

  if (index >= constants.hd.hardened || hardened)
    throw new Error('Invalid index.');

  if (index < 0)
    throw new Error('Invalid path.');

  p = new BufferWriter();
  p.writeBytes(this.publicKey);
  p.writeU32BE(index);
  data = p.render();

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  publicPoint = ec.elliptic.curve.decodePoint(this.publicKey);
  point = ec.elliptic.curve.g.mul(leftPart).add(publicPoint);
  publicKey = new Buffer(point.encode('array', true));

  if (!this.fingerPrint) {
    this.fingerPrint = utils.ripesha(this.publicKey)
      .slice(0, constants.hd.parentFingerPrintSize);
  }

  child = new HDPublicKey({
    networkType: this.networkType,
    data: {
      version: this.version,
      depth: this.depth + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      publicKey: publicKey
    }
  });

  HD.cache.set(this.xpubkey + '/' + index, child);

  return child;
};

HDPublicKey.prototype.deriveAccount44 = HDPrivateKey.prototype.deriveAccount44;
HDPublicKey.prototype.derivePurpose45 = HDPrivateKey.prototype.derivePurpose45;
HDPublicKey.prototype.isPurpose45 = HDPrivateKey.prototype.isPurpose45;
HDPublicKey.prototype.isAccount44 = HDPrivateKey.prototype.isAccount44;

HDPublicKey.isValidPath = function isValidPath(arg) {
  var indexes;

  if (typeof arg === 'string') {
    indexes = HDPrivateKey._getIndexes(arg);
    return indexes !== null && indexes.every(HDPublicKey.isValidPath);
  }

  if (typeof arg === 'number')
    return arg >= 0 && arg < constants.hd.hardened;

  return false;
};

HDPublicKey.prototype.derivePath = function derivePath(path) {
  var indexes;

  if (path.indexOf('\'') !== -1)
    throw new Error('Cannot derive hardened.');

  if (!HDPublicKey.isValidPath(path))
    throw new Error('Invalid path.');

  indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  }, this);
};

HDPublicKey.prototype.toJSON = HDPrivateKey.prototype.toJSON;
HDPublicKey.fromJSON = HDPrivateKey.fromJSON;

HDPublicKey.isExtended = function isExtended(data) {
  if (typeof data !== 'string')
    return false;

  return network.xpubkeys[data.slice(0, 4)];
};

HDPublicKey.parse = function parse(xkey) {
  var raw = utils.fromBase58(xkey);
  var p = new BufferReader(raw, true);
  var data = {};
  var i, type, prefix;

  data.version = p.readU32BE();
  data.depth = p.readU8();
  data.parentFingerPrint = p.readBytes(4);
  data.childIndex = p.readU32BE();
  data.chainCode = p.readBytes(32);
  data.publicKey = p.readBytes(33);
  p.verifyChecksum();

  for (i = 0; i < network.types.length; i++) {
    type = network.types[i];
    prefix = network[type].prefixes.xpubkey;
    if (data.version === prefix)
      break;
  }

  assert(i < network.types.length, 'Network not found.');

  return {
    networkType: type,
    xpubkey: xkey,
    data: data
  };
};

HDPublicKey.render = function render(data) {
  var p = new BufferWriter();
  p.writeU32BE(data.version);
  p.writeU8(data.depth);
  p.writeBytes(data.parentFingerPrint);
  p.writeU32BE(data.childIndex);
  p.writeBytes(data.chainCode);
  p.writeBytes(data.publicKey);
  p.writeChecksum();
  return utils.toBase58(p.render());
};

HDPublicKey.fromBase58 = function fromBase58(xkey) {
  var data = HDPublicKey.parse(xkey);
  return new HDPublicKey(data);
};

HDPublicKey.isHDPublicKey = function isHDPublicKey(obj) {
  return obj && obj.isPublic && typeof obj.derive === 'function';
};

/**
 * Make HD keys behave like KeyPairs
 */

[HDPrivateKey, HDPublicKey].forEach(function(HD) {
  HD.prototype.getPrivateKey = function getPrivateKey() {
    return KeyPair.prototype.getPrivateKey.apply(this, arguments);
  };

  HD.prototype.getPublicKey = function getPublicKey() {
    return KeyPair.prototype.getPublicKey.apply(this, arguments);
  };

  HD.prototype.sign = function sign() {
    return KeyPair.prototype.sign.apply(this, arguments);
  };

  HD.prototype.verify = function verify() {
    return KeyPair.prototype.verify.apply(this, arguments);
  };

  HD.prototype.compressed = true;
});

HDPrivateKey.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret.call(this);
};

/**
 * Expose
 */

exports = HD;

exports.seed = HDSeed;
exports.priv = HDPrivateKey;
exports.pub = HDPublicKey;
exports.privateKey = HDPrivateKey;
exports.publicKey = HDPublicKey;
exports.fromJSON = HDPrivateKey.fromJSON;

module.exports = HD;

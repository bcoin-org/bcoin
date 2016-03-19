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

  this.seed = utils.pbkdf2(this.mnemonic, 'mnemonic' + this.passphrase, 2048, 64);

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

/**
 * Abstract
 */

function HD(options) {
  return new HDPrivateKey(options);
}

HD.generate = function generate(privateKey, entropy) {
  return HDPrivateKey.generate(privateKey, entropy);
};

HD.fromSeed = function fromSeed(options) {
  return HDPrivateKey.fromSeed(options);
};

HD.cache = new LRU(500);

/**
 * HD Private Key
 */

function HDPrivateKey(options) {
  var data;

  if (!(this instanceof HDPrivateKey))
    return new HDPrivateKey(options);

  assert(!(options instanceof HDPrivateKey));
  assert(!(options instanceof HDPublicKey));

  assert(options);

  if (HDPrivateKey.isExtended(options))
    options = { xkey: options };

  if (options.xpubkey)
    options.xkey = options.xpubkey;

  if (options.xprivkey)
    options.xkey = options.xprivkey;

  if (HDPublicKey.isExtended(options.xkey))
    return new HDPublicKey(options);

  this.network = options.network || network.type;
  this.seed = options.seed;

  if (options.xkey) {
    data = this._unbuild(options.xkey);
  } else if (options.seed) {
    data = this._seed(options.seed);
  } else {
    data = options.data;
  }
  assert(data);

  data = this._normalize(data);

  this.data = data;

  this._build(data);

  if (utils.readU32BE(data.parentFingerPrint) === 0)
    this.isMaster = true;
  else
    this.isMaster = false;

  this.isPrivate = true;
  this.isPublic = false;
}

utils.inherits(HDPrivateKey, HD);

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
    coinType = network[this.network].type === 'main' ? 0 : 1;

  assert(utils.isFinite(coinType));
  assert(utils.isFinite(accountIndex));

  child = this
    .derive(44, true)
    .derive(coinType, true)
    .derive(accountIndex, true);

  assert(child.isAccount44());

  return child;
};

HDPrivateKey.prototype.deriveBIP44 = function deriveBIP44(options) {
  var chain = options.chain;
  var addressIndex = options.addressIndex;

  if (chain == null)
    chain = options.change ? 1 : 0;

  assert(utils.isFinite(chain));
  assert(utils.isFinite(addressIndex));

  return this
    .deriveAccount44(options)
    .derive(chain)
    .derive(addressIndex);
};

HDPrivateKey.prototype.deriveChange = function deriveChange(accountIndex, addressIndex) {
  if (this instanceof HDPublicKey) {
    addressIndex = accountIndex;
    accountIndex = null;
  }

  return this.deriveBIP44({
    accountIndex: accountIndex,
    chain: 1,
    addressIndex: addressIndex
  });
};

HDPrivateKey.prototype.deriveAddress = function deriveAddress(accountIndex, addressIndex) {
  if (this instanceof HDPublicKey) {
    addressIndex = accountIndex;
    accountIndex = null;
  }

  return this.deriveBIP44({
    accountIndex: accountIndex,
    chain: 0,
    addressIndex: addressIndex
  });
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

HDPrivateKey.prototype.deriveBIP45 = function deriveBIP45(options) {
  var cosignerIndex = options.cosignerIndex;
  var chain = options.chain;
  var addressIndex = options.addressIndex;

  if (chain == null)
    chain = options.change ? 1 : 0;

  assert(utils.isFinite(cosignerIndex));
  assert(utils.isFinite(chain));
  assert(utils.isFinite(addressIndex));

  return this
    .derivePurpose45(options)
    .derive(cosignerIndex)
    .derive(chain)
    .derive(addressIndex);
};

HDPrivateKey.prototype.deriveCosignerChange = function deriveCosignerChange(cosignerIndex, addressIndex) {
  return this.deriveBIP45({
    cosignerIndex: cosignerIndex,
    chain: 1,
    addressIndex: addressIndex
  });
};

HDPrivateKey.prototype.deriveCosignerAddress = function deriveCosignerAddress(cosignerIndex, addressIndex) {
  return this.deriveBIP45({
    cosignerIndex: cosignerIndex,
    chain: 0,
    addressIndex: addressIndex
  });
};

HDPrivateKey.prototype.isPurpose45 = function isPurpose45() {
  if (utils.readU8(this.depth) !== 1)
    return false;
  return utils.readU32BE(this.childIndex) === constants.hd.hardened + 45;
};

HDPrivateKey.prototype.isAccount44 = function isAccount44() {
  if (utils.readU32BE(this.childIndex) < constants.hd.hardened)
    return false;
  return utils.readU8(this.depth) === 3;
};

HDPrivateKey.getPath = function getPath(options) {
  var purpose, coinType, accountIndex, chain, addressIndex;

  if (!options)
    options = {};

  purpose = options.purpose;
  coinType = options.coinType;
  accountIndex = options.accountIndex;
  chain = options.chain;
  addressIndex = options.addressIndex;

  if (purpose == null)
    purpose = 44;

  if (coinType == null)
    coinType = network[this.network].type === 'main' ? 0 : 1;

  if (chain == null)
    chain = options.change ? 1 : 0;

  return 'm/' + purpose + '\'/'
    + coinType + '\'/'
    + accountIndex + '\'/'
    + chain + '/'
    + addressIndex;
};

HDPrivateKey.isExtended = function isExtended(data) {
  if (typeof data !== 'string')
    return false;

  return network.xprivkeys[data.slice(0, 4)];
};

HDPrivateKey.prototype._normalize = function _normalize(data) {
  if (!data.version) {
    data.version = (this instanceof HDPrivateKey)
      ? network[this.network].prefixes.xprivkey
      : network[this.network].prefixes.xpubkey;
  }

  // version = uint_32be
  if (typeof data.version === 'number')
    data.version = array32(data.version);

  // depth = unsigned char
  if (typeof data.depth === 'number')
    data.depth = new Buffer([data.depth]);

  if (utils.readU8(data.depth) > 0xff)
    throw new Error('Depth is too high');

  // parent finger print = uint_32be
  if (typeof data.parentFingerPrint === 'number')
    data.parentFingerPrint = array32(data.parentFingerPrint);

  // child index = uint_32be
  if (typeof data.childIndex === 'number')
    data.childIndex = array32(data.childIndex);

  // chain code = 32 bytes
  if (typeof data.chainCode === 'string')
    data.chainCode = new Buffer(data.chainCode, 'hex');

  // checksum = 4 bytes
  if (typeof data.checksum === 'string')
    data.checksum = new Buffer(data.checksum, 'hex');

  return data;
};

HDPrivateKey.prototype._seed = function _seed(seed) {
  var hash;

  if (seed instanceof HDSeed)
    seed = seed.createSeed();

  if (utils.isHex(seed))
    seed = new Buffer(seed, 'hex');

  if (seed.length < constants.hd.minEntropy
      || seed.length > constants.hd.maxEntropy) {
    throw new Error('entropy not in range');
  }

  hash = utils.sha512hmac(seed, 'Bitcoin seed');

  return {
    version: network[this.network].prefixes.xprivkey,
    depth: new Buffer([0]),
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: new Buffer([0, 0, 0, 0]),
    chainCode: hash.slice(32, 64),
    privateKey: hash.slice(0, 32),
    checksum: null
  };
};

HDPrivateKey.fromSeed = function fromSeed(options) {
  var seed = (options instanceof HDSeed) ? options : new HDSeed(options);
  return new HDPrivateKey({ seed: seed });
};

HDPrivateKey._generate = function _generate(privateKey, entropy) {
  if (!privateKey)
    privateKey = ec.generatePrivateKey();

  if (!entropy)
    entropy = ec.random(32);

  return {
    version: null,
    depth: new Buffer([0]),
    parentFingerPrint: new Buffer([0, 0, 0, 0]),
    childIndex: new Buffer([0, 0, 0, 0]),
    chainCode: entropy,
    privateKey: privateKey,
    checksum: null
  };
};

HDPrivateKey.generate = function generate(privateKey, entropy) {
  return new HDPrivateKey(HDPrivateKey._generate(privateKey, entropy));
};

HDPrivateKey.prototype._generate = function _generate(privateKey, entropy) {
  var data = HDPrivateKey._generate(privateKey, entropy);
  data.version = network[this.network].prefixes.xprivkey;
  return data;
};

HDPrivateKey.prototype._unbuild = function _unbuild(xkey) {
  var raw = utils.fromBase58(xkey);
  var data = {};
  var off = 0;
  var hash;

  data.version = raw.slice(off, off + 4);
  off += 4;
  data.depth = raw.slice(off, off + 1);
  off += 1;
  data.parentFingerPrint = raw.slice(off, off + 4);
  off += 4;
  data.childIndex = raw.slice(off, off + 4);
  off += 4;
  data.chainCode = raw.slice(off, off + 32);
  off += 32;
  off += 1; // nul byte
  data.privateKey = raw.slice(off, off + 32);
  off += 32;
  data.checksum = raw.slice(off, off + 4);
  off += 4;

  hash = utils.dsha256(raw.slice(0, -4)).slice(0, 4);
  if (!utils.isEqual(data.checksum, hash))
    throw new Error('checksum mismatch');

  network.types.some(function(type) {
    if (utils.readU32BE(data.version) === network[type].prefixes.xprivkey) {
      this.network = type;
      return true;
    }
    return false;
  }, this);

  this.xprivkey = xkey;

  return data;
};

HDPrivateKey.prototype._build = function _build(data) {
  var off = 0;
  var sequence, checksum;

  if (!this.xprivkey) {
    sequence = new Buffer(82);
    off += utils.copy(data.version, sequence, off);
    off += utils.copy(data.depth, sequence, off);
    off += utils.copy(data.parentFingerPrint, sequence, off);
    off += utils.copy(data.childIndex, sequence, off);
    off += utils.copy(data.chainCode, sequence, off);
    off += utils.writeU8(sequence, 0, off);
    off += utils.copy(data.privateKey, sequence, off);
    assert(off === 78, off);
    checksum = utils.dsha256(sequence.slice(0, off)).slice(0, 4);
    off += utils.copy(checksum, sequence, off);
    assert(off === 82, off);

    this.xprivkey = utils.toBase58(sequence);
  }

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.privateKey = data.privateKey;
  this.checksum = null;

  this.publicKey = ec.publicKeyCreate(data.privateKey, true);
  this.fingerPrint = null;

  this.hdPrivateKey = this;
};

HDPrivateKey.prototype.__defineGetter__('hdPublicKey', function() {
  if (!this._hdPublicKey) {
    this._hdPublicKey = new HDPublicKey({
      network: this.network,
      data: {
        version: network[this.network].prefixes.xpubkey,
        depth: this.depth,
        parentFingerPrint: this.parentFingerPrint,
        childIndex: this.childIndex,
        chainCode: this.chainCode,
        checksum: this.checksum,
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
  var cached, data, hash, leftPart, chainCode, privateKey, child;
  var off = 0;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xprivkey + '/' + index);

  if (cached)
    return cached;

  hardened = index >= constants.hd.hardened ? true : hardened;
  if (index < constants.hd.hardened && hardened)
    index += constants.hd.hardened;

  if (hardened) {
    data = new Buffer(1 + this.privateKey.length + 4);
    off += utils.writeU8(data, 0, off);
    off += utils.copy(this.privateKey, data, off);
    off += utils.writeU32BE(data, index, off);
  } else {
    data = new Buffer(this.publicKey.length + 4);
    off += utils.copy(this.publicKey, data, off);
    off += utils.writeU32BE(data, index, off);
  }

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = new Buffer(leftPart
    .add(new bn(this.privateKey))
    .mod(ec.elliptic.curve.n)
    .toArray('be', 32));

  if (!this.fingerPrint) {
    this.fingerPrint = utils.ripesha(this.publicKey)
      .slice(0, constants.hd.parentFingerPrintSize);
  }

  child = new HDPrivateKey({
    network: this.network,
    data: {
      version: this.version,
      depth: utils.readU8(this.depth) + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      privateKey: privateKey,
      checksum: null
    }
  });

  HD.cache.set(this.xprivkey + '/' + index, child);

  return child;
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
  json = HDPrivateKey._fromJSON(json, passphrase);

  if (json.xprivkey) {
    return new HDPrivateKey({
      xkey: json.xprivkey,
      seed: json.seed ? new HDSeed(json.seed) : null
    });
  }

  if (json.seed)
    return HDPrivateKey.fromSeed(json.seed);

  if (json.xpubkey) {
    return new HDPublicKey({
      xkey: json.xpubkey
    });
  }
};

/**
 * HD Public Key
 */

function HDPublicKey(options) {
  var data;

  if (!(this instanceof HDPublicKey))
    return new HDPublicKey(options);

  if (!options)
    throw new Error('No options for HDPublicKey');

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

  this.network = options.network || network.type;

  data = options.xkey
    ? this._unbuild(options.xkey)
    : options.data;
  assert(data);

  data = this._normalize(data);

  this.data = data;

  this._build(data);

  if (utils.readU32BE(data.parentFingerPrint) === 0)
    this.isMaster = true;
  else
    this.isMaster = false;

  this.isPrivate = false;
  this.isPublic = true;
}

utils.inherits(HDPublicKey, HD);

HDPublicKey.prototype.scan44 = HDPrivateKey.prototype.scan44;
HDPublicKey.prototype.deriveAccount44 = HDPrivateKey.prototype.deriveAccount44;
HDPublicKey.prototype.deriveBIP44 = HDPrivateKey.prototype.deriveBIP44;
HDPublicKey.prototype.deriveChange = HDPrivateKey.prototype.deriveChange;
HDPublicKey.prototype.deriveAddress = HDPrivateKey.prototype.deriveAddress;

HDPublicKey.prototype.scan45 = HDPrivateKey.prototype.scan45;
HDPublicKey.prototype.derivePurpose45 = HDPrivateKey.prototype.derivePurpose45;
HDPublicKey.prototype.deriveBIP45 = HDPrivateKey.prototype.deriveBIP45;
HDPublicKey.prototype.deriveCosignerChange = HDPrivateKey.prototype.deriveCosignerChange;
HDPublicKey.prototype.deriveCosignerAddress = HDPrivateKey.prototype.deriveCosignerAddress;

HDPublicKey.prototype.isPurpose45 = HDPrivateKey.prototype.isPurpose45;
HDPublicKey.prototype.isAccount44 = HDPrivateKey.prototype.isAccount44;
HDPublicKey.prototype.toJSON = HDPrivateKey.prototype.toJSON;
HDPublicKey.fromJSON = HDPrivateKey.fromJSON;

HDPublicKey.isExtended = function isExtended(data) {
  if (typeof data !== 'string')
    return false;

  return network.xpubkeys[data.slice(0, 4)];
};

HDPublicKey.prototype._normalize = HDPrivateKey.prototype._normalize;

HDPublicKey.prototype._unbuild = function _unbuild(xkey) {
  var raw = utils.fromBase58(xkey);
  var data = {};
  var off = 0;
  var hash;

  data.version = raw.slice(off, off + 4);
  off += 4;
  data.depth = raw.slice(off, off + 1);
  off += 1;
  data.parentFingerPrint = raw.slice(off, off + 4);
  off += 4;
  data.childIndex = raw.slice(off, off + 4);
  off += 4;
  data.chainCode = raw.slice(off, off + 32);
  off += 32;
  data.publicKey = raw.slice(off, off + 33);
  off += 33;
  data.checksum = raw.slice(off, off + 4);
  off += 4;

  hash = utils.dsha256(raw.slice(0, -4)).slice(0, 4);
  if (!utils.isEqual(data.checksum, hash))
    throw new Error('checksum mismatch');

  network.types.some(function(type) {
    if (utils.readU32BE(data.version) === network[type].prefixes.xprivkey) {
      this.network = type;
      return true;
    }
    return false;
  }, this);

  this.xpubkey = xkey;

  return data;
};

HDPublicKey.prototype._build = function _build(data) {
  var off = 0;
  var sequence, checksum;

  if (!this.xpubkey) {
    sequence = new Buffer(82);
    off += utils.copy(data.version, sequence, off);
    off += utils.copy(data.depth, sequence, off);
    off += utils.copy(data.parentFingerPrint, sequence, off);
    off += utils.copy(data.childIndex, sequence, off);
    off += utils.copy(data.chainCode, sequence, off);
    off += utils.copy(data.publicKey, sequence, off);
    assert(off === 78, off);
    checksum = utils.dsha256(sequence.slice(0, off)).slice(0, 4);
    off += utils.copy(checksum, sequence, off);
    assert(off === 82, off);

    if (!data.checksum || !data.checksum.length)
      data.checksum = checksum;
    else if (utils.toHex(checksum) !== utils.toHex(data.checksum))
      throw new Error('checksum mismatch');

    this.xpubkey = utils.toBase58(sequence);
  }

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.publicKey = data.publicKey;
  this.checksum = null;

  this.privateKey = null;
  this.fingerPrint = null;

  this.hdPublicKey = this;

  this.hdPrivateKey = null;
  this.xprivkey = null;
};

HDPublicKey.prototype.derive = function derive(index, hardened) {
  var off = 0;
  var cached, data, hash, leftPart, chainCode;
  var publicPoint, point, publicKey, child;

  if (typeof index === 'string')
    return this.derivePath(index);

  cached = HD.cache.get(this.xpubkey + '/' + index);

  if (cached)
    return cached;

  if (index >= constants.hd.hardened || hardened)
    throw new Error('invalid index');

  if (index < 0)
    throw new Error('invalid path');

  data = new Buffer(this.publicKey.length + 4);
  off += utils.copy(this.publicKey, data, off);
  off += utils.writeU32BE(data, index, off);

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
    network: this.network,
    data: {
      version: this.version,
      depth: utils.readU8(this.depth) + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      publicKey: publicKey,
      checksum: null
    }
  });

  HD.cache.set(this.xpubkey + '/' + index, child);

  return child;
};

HDPublicKey.isValidPath = function isValidPath(arg) {
  if (typeof arg === 'string') {
    var indexes = HDPrivateKey._getIndexes(arg);
    return indexes !== null && indexes.every(HDPublicKey.isValidPath);
  }

  if (typeof arg === 'number')
    return arg >= 0 && arg < constants.hd.hardened;

  return false;
};

HDPublicKey.prototype.derivePath = function derivePath(path) {
  if (~path.indexOf('\''))
    throw new Error('cannot derive hardened');
  else if (!HDPublicKey.isValidPath(path))
    throw new Error('invalid path');

  var indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index) {
    return prev.derive(index);
  }, this);
};

/**
 * Make HD keys behave like elliptic KeyPairs
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
 * Helpers
 */

function array32(data) {
  var b = new Buffer(4);
  utils.writeU32BE(b, data, 0);
  return b;
}

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

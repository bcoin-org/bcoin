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
var elliptic = require('elliptic');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
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

  options = options || {};

  this.bits = options.bits || 128;
  this.entropy = options.entropy || new Buffer(elliptic.rand(this.bits / 8));
  this.mnemonic = options.mnemonic || HDSeed._mnemonic(this.entropy);
  this.seed = this.createSeed(options.passphrase);
}

HDSeed.prototype.createSeed = function createSeed(passphrase) {
  this.passphrase = passphrase || '';
  return pbkdf2(this.mnemonic, 'mnemonic' + this.passphrase, 2048, 64);
};

HDSeed._mnemonic = function _mnemonic(entropy) {
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

/**
 * HD Private Key
 */

function HDPrivateKey(options) {
  var data;

  if (!(this instanceof HDPrivateKey))
    return new HDPrivateKey(options);

  assert(!(options instanceof HDPrivateKey));
  assert(!(options instanceof HDPublicKey));

  if (!options)
    options = { seed: bcoin.hd.seed() };

  if (HDPrivateKey.isExtended(options))
    options = { xkey: options };

  if (options.xpubkey)
    options.xkey = options.xpubkey;

  if (options.xprivkey)
    options.xkey = options.xprivkey;

  if (HDPublicKey.isExtended(options.xkey))
    return new HDPublicKey(options);

  if (options instanceof bcoin.hd.seed)
    options = { seed: options };

  if (options.passphrase !== undefined
      || options.bits
      || options.entropy
      || options.mnemonic) {
    options.seed = bcoin.hd.seed(options);
  }

  if (options.seed
      && typeof options.seed === 'object'
      && !Buffer.isBuffer(options.seed)
      && !(options.seed instanceof bcoin.hd.seed)) {
    options.seed = bcoin.hd.seed(options.seed);
  }

  this.network = options.network || network.type;

  if (options.seed) {
    this.seed = options.seed;
    data = this._seed(options.seed);
  } else if (options.xkey) {
    data = this._unbuild(options.xkey);
  } else if (options.privateKey) {
    data = this._generate(options.privateKey, options.chainCode);
  } else {
    data = options.data;
  }
  assert(data);

  data = this._normalize(data);

  this.data = data;

  this._build(data);

  if (new bn(data.parentFingerPrint).cmpn(0) === 0)
    this.isMaster = true;
  else
    this.isMaster = false;

  this.isPrivate = true;
  this.isPublic = false;
}

utils.inherits(HDPrivateKey, HD);

HDPrivateKey.prototype.scan44 = function scan44(options, txByAddress, callback) {
  var self = this;
  var accounts = [];
  var isAccount = this.isAccount44();
  var coinType, root;

  // 0. get the root node
  if (!isAccount) {
    coinType = options.coinType;

    if (coinType == null)
      coinType = network[this.network].type === 'main' ? 0 : 1;

    assert(utils.isFinite(coinType));

    root = this
      .derive(44, true)
      .derive(coinType, true);
  }

  return (function chainCheck(chainConstant) {
    return (function scanner(accountIndex) {
      var addressIndex = 0;
      var total = 0;
      var gap = 0;

      // 1. derive the first account's node (index = 0)
      var account = isAccount
        ? self
        : root.derive(accountIndex, true);

      if (isAccount)
        accountIndex = new bn(self.childIndex).toNumber() - constants.hd.hardened;

      // 2. derive the external chain node of this account
      var chain = account.derive(chainConstant);

      // 3. scan addresses of the external chain;
      // respect the gap limit described below
      return (function next() {
        var address = chain.derive(addressIndex++);
        var addr = bcoin.address.compile(address.publicKey);

        return txByAddress(addr, function(err, txs) {
          var result;

          if (err)
            return callback(err);

          if (txs) {
            if (typeof txs === 'boolean')
              result = txs;
            else if (typeof txs === 'number')
              result = txs > 0;
            else if (Array.isArray(txs))
              result = txs.length > 0;
            else
              result = false;
          }

          if (result) {
            total++;
            gap = 0;
            return next();
          }

          if (++gap < 20)
            return next();

          assert(accounts[accountIndex] == null || chainConstant === 1);

          if (chainConstant === 0)
            accounts[accountIndex] = { addressDepth: addressIndex - gap };
          else
            accounts[accountIndex].changeDepth = addressIndex - gap;

          // 4. if no transactions are found on the
          // external chain, stop discovery
          if (total === 0) {
            if (chainConstant === 0)
              return chainCheck(1);
            if (isAccount)
              return callback(null, accounts[accountIndex]);
            return callback(null, accounts);
          }

          // 5. if there are some transactions, increase
          // the account index and go to step 1
          if (isAccount) {
            if (chainConstant === 0)
              return chainCheck(1);
            return callback(null, accounts[accountIndex]);
          }

          return scanner(accountIndex + 1);
        });
      })();
    })(0);
  })(0);
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

HDPrivateKey.prototype.scan45 = function scan45(options, txByAddress, callback) {
  var cosigners = [];
  var root;

  root = this.isPurpose45()
    ? this
    : this.derivePurpose45(options);

  return (function chainCheck(chainConstant) {
    return (function scanner(cosignerIndex) {
      var addressIndex = 0;
      var total = 0;
      var gap = 0;

      var cosigner = root.derive(cosignerIndex);
      var chain = cosigner.derive(chainConstant);

      return (function next() {
        var address = chain.derive(addressIndex++);
        var addr = bcoin.address.compile(address.publicKey);

        return txByAddress(addr, function(err, txs) {
          var result;

          if (err)
            return callback(err);

          if (txs) {
            if (typeof txs === 'boolean')
              result = txs;
            else if (typeof txs === 'number')
              result = txs > 0;
            else if (Array.isArray(txs))
              result = txs.length > 0;
            else
              result = false;
          }

          if (result) {
            total++;
            gap = 0;
            return next();
          }

          if (++gap < 20)
            return next();

          assert(cosigners[cosignerIndex] == null || chainConstant === 1);

          if (chainConstant === 0)
            cosigners[cosignerIndex] = { addressDepth: addressIndex - gap };
          else
            cosigners[cosginerIndex].changeDepth = addressIndex - gap;

          if (total === 0) {
            if (chainConstant === 0)
              return chainCheck(1);
            return callback(null, cosigners);
          }

          return scanner(cosignerIndex + 1);
        });
      })();
    })(0);
  })(0);
};

HDPrivateKey.prototype.derivePurpose45 = function derivePurpose45(options) {
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

HDPrivateKey.prototype.isPurpose45 = function isPurpose45(options) {
  if (new bn(this.depth).toNumber() !== 1)
    return false;
  return new bn(this.childIndex).toNumber() === constants.hd.hardened + 45;
};

HDPrivateKey.prototype.isAccount44 = function isAccount44(options) {
  if (new bn(this.childIndex).toNumber() < constants.hd.hardened)
    return false;
  return new bn(this.depth).toNumber() === 3;
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

  return data.indexOf('xprv') === 0 || data.indexOf('tprv') === 0;
};

HDPrivateKey.prototype._normalize = function _normalize(data) {
  if (!data.version) {
    data.version = (this instanceof HDPrivateKey)
      ? network[this.network].prefixes.xprivkey
      : network[this.network].prefixes.xpubkey;
  }

  // version = uint_32be
  if (typeof data.version === 'string')
    data.version = new Buffer(data.version, 'hex');
  else if (typeof data.version === 'number')
    data.version = array32(data.version);

  // depth = unsigned char
  if (typeof data.depth === 'string')
    data.depth = new Buffer(data.depth, 'hex');
  else if (typeof data.depth === 'number')
    data.depth = new Buffer([data.depth]);

  if (new bn(data.depth).toNumber() > 0xff)
    throw new Error('Depth is too high');

  // parent finger print = uint_32be
  if (typeof data.parentFingerPrint === 'string')
    data.parentFingerPrint = new Buffer(data.parentFingerPrint, 'hex');
  else if (typeof data.parentFingerPrint === 'number')
    data.parentFingerPrint = array32(data.parentFingerPrint);

  // child index = uint_32be
  if (typeof data.childIndex === 'string')
    data.childIndex = new Buffer(data.childIndex, 'hex');
  else if (typeof data.childIndex === 'number')
    data.childIndex = array32(data.childIndex);

  // chain code = 32 bytes
  if (typeof data.chainCode === 'string')
    data.chainCode = new Buffer(data.chainCode, 'hex');

  // private key = 32 bytes
  if (data.privateKey) {
    if (data.privateKey.getPrivateKey)
      data.privateKey = data.privateKey.getPrivateKey();
    else if (typeof data.privateKey === 'string')
      data.privateKey = utils.ensureBuffer(data.privateKey);
  }

  // public key = 33 bytes
  if (data.publicKey) {
    if (data.publicKey.getPublicKey)
      data.publicKey = data.privateKey.getPublicKey();
    else if (typeof data.publicKey === 'string')
      data.publicKey = utils.ensureBuffer(data.publicKey);
  }

  // checksum = 4 bytes
  if (typeof data.checksum === 'string')
    data.checksum = new Buffer(data.checksum, 'hex');
  else if (typeof data.checksum === 'number')
    data.checksum = array32(data.checksum);

  return data;
};

HDPrivateKey.prototype._seed = function _seed(seed) {
  var hash;

  if (seed instanceof HDSeed)
    seed = seed.seed;

  if (utils.isHex(seed))
    seed = new Buffer(seed, 'hex');

  if (seed.length < constants.hd.minEntropy
      || seed.length > constants.hd.maxEntropy) {
    throw new Error('entropy not in range');
  }

  hash = utils.sha512hmac(seed, 'Bitcoin seed');

  return {
    version: network[this.network].prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: 0,
    childIndex: 0,
    chainCode: hash.slice(32, 64),
    privateKey: hash.slice(0, 32),
    checksum: null
  };
};

HDPrivateKey.prototype._generate = function _generate(privateKey, entropy) {
  if (!privateKey)
    privateKey = bcoin.ec.generate().getPrivateKey();

  if (utils.isHex(privateKey))
    privateKey = new Buffer(privateKey, 'hex');
  else if (utils.isBase58(privateKey))
    privateKey = bcoin.keypair.fromSecret(privateKey).getPrivateKey();

  if (!entropy)
    entropy = new Buffer(elliptic.rand(32));

  return {
    version: network[this.network].prefixes.xprivkey,
    depth: 0,
    parentFingerPrint: 0,
    childIndex: 0,
    chainCode: entropy,
    privateKey: privateKey,
    checksum: null
  };
};

HDPrivateKey.prototype._unbuild = function _unbuild(xkey) {
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

  if (data.version === network.main.prefixes.xprivkey)
    this.network = 'main';
  else
    this.network = 'testnet';

  return data;
};

HDPrivateKey.prototype._build = function _build(data) {
  var sequence = new Buffer(82);
  var off = 0;
  var checksum, xprivkey, pair, privateKey, publicKey, size, fingerPrint;

  off += utils.copy(data.version, sequence, off);
  off += utils.copy(data.depth, sequence, off);
  off += utils.copy(data.parentFingerPrint, sequence, off);
  off += utils.copy(data.childIndex, sequence, off);
  off += utils.copy(data.chainCode, sequence, off);
  off += utils.copy([0], sequence, off);
  off += utils.copy(data.privateKey, sequence, off);
  assert(off === 78, off);
  checksum = utils.dsha256(sequence.slice(0, off)).slice(0, 4);
  off += utils.copy(checksum, sequence, off);
  assert(off === 82, off);

  xprivkey = utils.toBase58(sequence);

  pair = bcoin.keypair({ privateKey: data.privateKey });
  privateKey = pair.getPrivateKey();
  publicKey = pair.getPublicKey();

  size = constants.hd.parentFingerPrintSize;
  fingerPrint = utils.ripesha(publicKey).slice(0, size);

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.privateKey = privateKey;
  this.checksum = null;

  this.xprivkey = xprivkey;
  this.fingerPrint = fingerPrint;
  this.publicKey = publicKey;

  this.hdPublicKey = new HDPublicKey({
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
  this.hdPrivateKey = this;

  this.xpubkey = this.hdPublicKey.xpubkey;
  this.pair = bcoin.keypair({ privateKey: this.privateKey });
};

HDPrivateKey.prototype.derive = function derive(index, hardened) {
  var cached, data, hash, leftPart, chainCode, privateKey, child;
  var off = 0;

  if (typeof index === 'string')
    return this.deriveString(index);

  cached = cache.get(this.xprivkey, index);

  if (cached)
    return cached;

  hardened = index >= constants.hd.hardened ? true : hardened;
  if (index < constants.hd.hardened && hardened)
    index += constants.hd.hardened;

  if (hardened) {
    data = new Buffer(1 + this.privateKey.length + 4);
    off += utils.writeU8(data, 0, off);
    off += this.privateKey.copy(data, off, 0, this.privateKey.length);
    off += utils.writeU32BE(data, index, off);
  } else {
    data = new Buffer(this.publicKey.length + 4);
    off += this.publicKey.copy(data, off, 0, this.publicKey.length);
    off += utils.writeU32BE(data, index, off);
  }

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  privateKey = new Buffer(leftPart
    .add(new bn(this.privateKey))
    .mod(ec.curve.n)
    .toArray('be', 32));

  child = new HDPrivateKey({
    network: this.network,
    data: {
      version: this.version,
      depth: new bn(this.depth).toNumber() + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      privateKey: privateKey,
      checksum: null
    }
  });

  cache.set(this.xprivkey, index, child);

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

HDPrivateKey.prototype.deriveString = function deriveString(path) {
  var indexes, child;

  if (!HDPrivateKey.isValidPath(path))
    throw new Error('invalid path');

  indexes = HDPrivateKey._getIndexes(path);

  return indexes.reduce(function(prev, index, i) {
    return prev.derive(index);
  }, this);
};

HDPrivateKey.prototype.toJSON = function toJSON(passphrase) {
  var json = {
    v: 1,
    name: 'hdkey',
    encrypted: passphrase ? true : false
  };

  if (this instanceof HDPrivateKey) {
    if (this.seed) {
      json.mnemonic = passphrase
        ? utils.encrypt(this.seed.mnemonic, passphrase)
        : this.seed.mnemonic;
      json.passphrase = passphrase
        ? utils.encrypt(this.seed.passphrase, passphrase)
        : this.seed.passphrase;
      return json;
    }
    json.xprivkey = passphrase
      ? utils.encrypt(this.xprivkey, passphrase)
      : this.xprivkey;
    return json;
  }

  json.xpubkey = this.hd.xpubkey;

  return json;
};

HDPrivateKey.fromJSON = function fromJSON(json, passphrase) {
  assert.equal(json.v, 1);
  assert.equal(json.name, 'hdkey');

  if (json.encrypted && !passphrase)
    throw new Error('Cannot decrypt address');

  if (json.mnemonic) {
    return new HDPrivateKey({
      seed: new HDSeed({
        mnemonic: json.encrypted
          ? utils.decrypt(json.mnemonic, passphrase)
          : json.mnemonic,
        passphrase: json.encrypted
          ? utils.decrypt(json.passphrase, passphrase)
          : json.passphrase
      })
    });
  }

  if (json.xprivkey) {
    return new HDPrivateKey({
      xkey: json.encrypted
        ? utils.decrypt(json.xprivkey, passphrase)
        : json.xprivkey
    });
  }

  if (json.xpubkey) {
    return new HDPublicKey({
      xkey: json.xpubkey
    });
  }

  assert(false);
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

  if (new bn(data.parentFingerPrint).cmpn(0) === 0)
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

  return data.indexOf('xpub') === 0 || data.indexOf('tpub') === 0;
};

HDPublicKey.prototype._normalize = HDPrivateKey.prototype._normalize;

HDPublicKey.prototype._unbuild = function _unbuild(xkey) {
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

  if (data.version === network.main.prefixes.xpubkey)
    this.network = 'main';
  else
    this.network = 'testnet';

  return data;
};

HDPublicKey.prototype._build = function _build(data) {
  var sequence = new Buffer(82);
  var off = 0;
  var checksum, xpubkey, publicKey, size, fingerPrint;

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

  xpubkey = utils.toBase58(sequence);

  publicKey = data.publicKey;
  size = constants.hd.parentFingerPrintSize;
  fingerPrint = utils.ripesha(publicKey).slice(0, size);

  this.version = data.version;
  this.depth = data.depth;
  this.parentFingerPrint = data.parentFingerPrint;
  this.childIndex = data.childIndex;
  this.chainCode = data.chainCode;
  this.publicKey = publicKey;
  this.checksum = null;

  this.hdPublicKey = this;
  this.xpubkey = xpubkey;
  this.fingerPrint = fingerPrint;

  this.xprivkey = data.xprivkey;
  this.pair = bcoin.keypair({ publicKey: this.publicKey });
};

HDPublicKey.prototype.derive = function derive(index, hardened) {
  var cached, data, hash, leftPart, chainCode, pair, point, publicKey, child;
  var off = 0;

  if (typeof index === 'string')
    return this.deriveString(index);

  cached = cache.get(this.xpubkey, index);

  if (cached)
    return cached;

  if (index >= constants.hd.hardened || hardened)
    throw new Error('invalid index');

  if (index < 0)
    throw new Error('invalid path');

  data = new Buffer(this.publicKey.length + 4);
  off += this.publicKey.copy(data, off, 0, this.publicKey.length);
  off += utils.writeU32BE(data, index, off);

  hash = utils.sha512hmac(data, this.chainCode);
  leftPart = new bn(hash.slice(0, 32));
  chainCode = hash.slice(32, 64);

  pair = bcoin.keypair({ publicKey: this.publicKey });
  point = ec.curve.g.mul(leftPart).add(pair.publicPoint);
  publicKey = bcoin.keypair({ publicKey: point }).getPublicKey();

  child = new HDPublicKey({
    network: this.network,
    data: {
      version: this.version,
      depth: new bn(this.depth).toNumber() + 1,
      parentFingerPrint: this.fingerPrint,
      childIndex: index,
      chainCode: chainCode,
      publicKey: publicKey,
      checksum: null
    }
  });

  cache.set(this.xpubkey, index, child);

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

HDPublicKey.prototype.deriveString = function deriveString(path) {
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
  HD.prototype.validate = function validate() {
    return this.pair.validate.apply(this.pair, arguments);
  };

  HD.prototype.getPublicKey = function getPublicKey() {
    return bcoin.keypair.prototype.getPublicKey.apply(this, arguments);
  };

  HD.prototype.getPrivateKey = function getPrivateKey() {
    return bcoin.keypair.prototype.getPrivateKey.apply(this, arguments);
  };

  HD.prototype.sign = function sign(msg) {
    return this.pair.sign.apply(this.pair, arguments);
  };

  HD.prototype.verify = function verify(msg, signature) {
    return this.pair.verify.apply(this.pair, arguments);
  };

  HD.prototype.__defineGetter__('publicPoint', function() {
    return this.pair.publicPoint;
  });

  HD.prototype.__defineGetter__('privatePoint', function() {
    return this.pair.privatePoint;
  });

  HD.prototype.compressed = true;
});

HDPrivateKey.prototype.toSecret = function toSecret() {
  return bcoin.keypair.toSecret(this.privateKey, this.compressed);
};

HDPrivateKey.fromSecret = function fromSecret(privateKey) {
  return bcoin.keypair.fromSecret(privateKey);
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
 * PDKBF2
 * Credit to: https://github.com/stayradiated/pbkdf2-sha512
 * Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
 * Copyright (c) 2014, JP Richardson
 */

function pbkdf2(key, salt, iterations, dkLen) {
  'use strict';

  if (bcoin.crypto && bcoin.crypto.pbkdf2Sync)
    return bcoin.crypto.pbkdf2Sync(key, salt, iterations, dkLen, 'sha512');

  var hLen = 64;

  if (dkLen > (Math.pow(2, 32) - 1) * hLen)
    throw Error('Requested key length too long');

  if (typeof key !== 'string' && typeof key.length !== 'number')
    throw new TypeError('key must a string or array');

  if (typeof salt !== 'string' && typeof salt.length !== 'number')
    throw new TypeError('salt must a string or array');

  if (typeof key === 'string')
    key = new Buffer(key, 'ascii');

  if (typeof salt === 'string')
    salt = new Buffer(salt, 'ascii');

  var DK = new Buffer(dkLen);
  var U = new Buffer(hLen);
  var T = new Buffer(hLen);
  var block1 = new Buffer(salt.length + 4);

  var l = Math.ceil(dkLen / hLen);
  var r = dkLen - (l - 1) * hLen;

  var i, j, k, destPos, len;

  utils.copy(salt.slice(0, salt.length), block1, 0);

  for (i = 1; i <= l; i++) {
    block1[salt.length + 0] = i >> 24 & 0xff;
    block1[salt.length + 1] = i >> 16 & 0xff;
    block1[salt.length + 2] = i >> 8 & 0xff;
    block1[salt.length + 3] = i >> 0 & 0xff;

    U = utils.sha512hmac(block1, key);

    utils.copy(U.slice(0, hLen), T, 0);

    for (j = 1; j < iterations; j++) {
      U = utils.sha512hmac(U, key);

      for (k = 0; k < hLen; k++)
        T[k] ^= U[k];
    }

    destPos = (i - 1) * hLen;
    len = i === l ? r : hLen;
    utils.copy(T.slice(0, len), DK, 0);
  }

  return DK;
}

HD.cache = new bcoin.lru(500, function(key, value) {
  return 1;
});

var cache = {
  data: {},
  count: 0
};

cache.set = function(key, index, value) {
  key = key + '/' + index;

  if (this.count > 500) {
    this.data = {};
    this.count = 0;
  }

  if (this.data[key] === undefined)
    this.count++;

  this.data[key] = value;
};

cache.get = function(key, index) {
  key = key + '/' + index;
  return this.data[key];
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
exports.pbkdf2 = pbkdf2;
exports.fromJSON = HDPrivateKey.fromJSON;

module.exports = HD;

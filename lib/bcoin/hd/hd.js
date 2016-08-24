/*!
 * hd.js - hd keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var bcoin = require('../env');
var utils = require('../utils/utils');
var assert = utils.assert;
var constants = bcoin.constants;
var LRU = require('../utils/lru');
var Mnemonic = require('./mnemonic');
var HDPrivateKey = require('./private');
var HDPublicKey = require('./public');

/**
 * @exports HD
 */

var HD = exports;

/**
 * Instantiate an HD key (public or private) from an base58 string.
 * @param {Base58String} xkey
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromBase58 = function fromBase58(xkey) {
  if (HDPrivateKey.isExtended(xkey))
    return HDPrivateKey.fromBase58(xkey);
  return HDPublicKey.fromBase58(xkey);
};

/**
 * Generate an {@link HDPrivateKey}.
 * @param {Object} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.generate = function generate(options, network) {
  return HDPrivateKey.generate(options, network);
};

/**
 * Generate an {@link HDPrivateKey} from a seed.
 * @param {Object|Mnemonic|Buffer} options - seed,
 * mnemonic, mnemonic options.
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.fromSeed = function fromSeed(options, network) {
  return HDPrivateKey.fromSeed(options, network);
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic|Object} mnemonic
 * @param {String?} network
 * @returns {HDPrivateKey}
 */

HD.fromMnemonic = function fromMnemonic(options, network) {
  return HDPrivateKey.fromMnemonic(options, network);
};

/**
 * Instantiate an HD key from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromJSON = function fromJSON(json) {
  if (json.xprivkey)
    return HDPrivateKey.fromJSON(json);
  return HDPublicKey.fromJSON(json);
};

/**
 * Instantiate an HD key from serialized data.
 * @param {Buffer} data
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromRaw = function fromRaw(data) {
  if (HDPrivateKey.hasPrefix(data))
    return HDPrivateKey.fromRaw(data);
  return HDPublicKey.fromRaw(data);
};

/**
 * Instantiate HD key from extended serialized data.
 * @param {Buffer} data
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromExtended = function fromExtended(data) {
  if (HDPrivateKey.hasPrefix(data))
    return HDPrivateKey.fromExtended(data);
  return HDPublicKey.fromRaw(data);
};

/**
 * Generate an hdkey from any number of options.
 * @param {Object|Mnemonic|Buffer} options - mnemonic, mnemonic
 * options, seed, or base58 key.
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.from = function from(options, network) {
  var xkey;

  assert(options, 'Options required.');

  if (options.xkey)
    xkey = options.xkey;
  else if (options.xpubkey)
    xkey = options.xpubkey;
  else if (options.xprivkey)
    xkey = options.xprivkey;
  else
    xkey = options;

  if (HD.isExtended(xkey))
    return HD.fromBase58(xkey);

  if (HD.hasPrefix(options))
    return HD.fromRaw(options);

  return HD.fromMnemonic(options, network);
};

/**
 * Test whether an object is in the form of a base58 hd key.
 * @param {String} data
 * @returns {Boolean}
 */

HD.isExtended = function isExtended(data) {
  return HDPrivateKey.isExtended(data)
    || HDPublicKey.isExtended(data);
};

/**
 * Test whether an object is in the form of a serialized hd key.
 * @param {Buffer} data
 * @returns {NetworkType}
 */

HD.hasPrefix = function hasPrefix(data) {
  return HDPrivateKey.hasPrefix(data)
    || HDPublicKey.hasPrefix(data);
};

/**
 * Parse a derivation path and return an array of indexes.
 * @see https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
 * @param {String} path
 * @param {Number?} max - Max index.
 * @returns {Number[]}
 */

HD.parsePath = function parsePath(path, max) {
  var parts = path.split('/');
  var root = parts.shift();
  var result = [];
  var i, hardened, index;

  if (max == null)
    max = constants.hd.MAX_INDEX;

  if (root !== 'm'
      && root !== 'M'
      && root !== 'm\''
      && root !== 'M\'') {
    throw new Error('Bad path root.');
  }

  for (i = 0; i < parts.length; i++) {
    index = parts[i];
    hardened = index[index.length - 1] === '\'';

    if (hardened)
      index = index.slice(0, -1);

    if (!/^\d+$/.test(index))
      throw new Error('Non-number path index.');

    index = parseInt(index, 10);

    if (hardened)
      index += constants.hd.HARDENED;

    if (!(index >= 0 && index < max))
      throw new Error('Index out of range.');

    result.push(index);
  }

  return result;
};

/**
 * LRU cache to avoid deriving keys twice.
 * @type {LRU}
 */

HD.cache = new LRU(500);

/**
 * Test whether an object is an HD key.
 * @param {Object} obj
 * @returns {Boolean}
 */

HD.isHD = function isHD(obj) {
  return HDPrivateKey.isHDPrivateKey(obj)
    || HDPublicKey.isHDPublicKey(obj);
};

/**
 * Test whether an object is an HD private key.
 * @param {Object} obj
 * @returns {Boolean}
 */

HD.isPrivate = function isPrivate(obj) {
  return HDPrivateKey.isHDPrivateKey(obj);
};

/**
 * Test whether an object is an HD public key.
 * @param {Object} obj
 * @returns {Boolean}
 */

HD.isPublic = function isPublic(obj) {
  return HDPublicKey.isHDPublicKey(obj);
};

/*
 * Expose
 */

HD.Mnemonic = Mnemonic;
HD.PrivateKey = HDPrivateKey;
HD.PublicKey = HDPublicKey;

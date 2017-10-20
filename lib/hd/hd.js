/*!
 * hd.js - hd keys for bcoin
 * Copyright (c) 2015-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const common = require('./common');
const Mnemonic = require('./mnemonic');
const HDPrivateKey = require('./private');
const HDPublicKey = require('./public');
const wordlist = require('./wordlist');

/**
 * @exports hd
 */

const HD = exports;

/**
 * Instantiate an HD key (public or private) from an base58 string.
 * @param {Base58String} xkey
 * @param {Network?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromBase58 = function fromBase58(xkey, network) {
  if (HDPrivateKey.isBase58(xkey))
    return HDPrivateKey.fromBase58(xkey, network);
  return HDPublicKey.fromBase58(xkey, network);
};

/**
 * Generate an {@link HDPrivateKey}.
 * @param {Object} options
 * @param {Buffer?} options.privateKey
 * @param {Buffer?} options.entropy
 * @returns {HDPrivateKey}
 */

HD.generate = function generate() {
  return HDPrivateKey.generate();
};

/**
 * Generate an {@link HDPrivateKey} from a seed.
 * @param {Object|Mnemonic|Buffer} options - seed,
 * mnemonic, mnemonic options.
 * @returns {HDPrivateKey}
 */

HD.fromSeed = function fromSeed(options) {
  return HDPrivateKey.fromSeed(options);
};

/**
 * Instantiate an hd private key from a mnemonic.
 * @param {Mnemonic|Object} mnemonic
 * @returns {HDPrivateKey}
 */

HD.fromMnemonic = function fromMnemonic(options) {
  return HDPrivateKey.fromMnemonic(options);
};

/**
 * Instantiate an HD key from a jsonified key object.
 * @param {Object} json - The jsonified transaction object.
 * @param {Network?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromJSON = function fromJSON(json, network) {
  if (json.xprivkey)
    return HDPrivateKey.fromJSON(json, network);
  return HDPublicKey.fromJSON(json, network);
};

/**
 * Instantiate an HD key from serialized data.
 * @param {Buffer} data
 * @param {Network?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.fromRaw = function fromRaw(data, network) {
  if (HDPrivateKey.isRaw(data, network))
    return HDPrivateKey.fromRaw(data, network);
  return HDPublicKey.fromRaw(data, network);
};

/**
 * Generate an hdkey from any number of options.
 * @param {Object|Mnemonic|Buffer} options - mnemonic, mnemonic
 * options, seed, or base58 key.
 * @param {(Network|NetworkType)?} network
 * @returns {HDPrivateKey|HDPublicKey}
 */

HD.from = function from(options, network) {
  assert(options, 'Options required.');

  if (HD.isHD(options))
    return options;

  if (HD.isBase58(options, network))
    return HD.fromBase58(options, network);

  if (HD.isRaw(options, network))
    return HD.fromRaw(options, network);

  if (options && typeof options === 'object')
    return HD.fromMnemonic(options);

  throw new Error('Cannot create HD key from bad options.');
};

/**
 * Test whether an object is in the form of a base58 hd key.
 * @param {String} data
 * @param {Network?} network
 * @returns {Boolean}
 */

HD.isBase58 = function isBase58(data, network) {
  return HDPrivateKey.isBase58(data, network)
    || HDPublicKey.isBase58(data, network);
};

/**
 * Test whether an object is in the form of a serialized hd key.
 * @param {Buffer} data
 * @param {Network?} network
 * @returns {NetworkType}
 */

HD.isRaw = function isRaw(data, network) {
  return HDPrivateKey.isRaw(data, network)
    || HDPublicKey.isRaw(data, network);
};

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

HD.common = common;
HD.HD = HD;
HD.Mnemonic = Mnemonic;
HD.PrivateKey = HDPrivateKey;
HD.PublicKey = HDPublicKey;
HD.HDPrivateKey = HDPrivateKey;
HD.HDPublicKey = HDPublicKey;
HD.wordlist = wordlist;

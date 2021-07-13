/*!
 * pemcrypt.js - PEM encryption for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Resources:
 *   https://tools.ietf.org/html/rfc1421
 */

'use strict';

const assert = require('../internal/assert');
const {PEMBlock} = require('./pem');
const cipher = require('../cipher');
const random = require('../random');
const eb2k = require('../eb2k');
const MD5 = require('../md5');

/*
 * Constants
 */

const ciphers = {
  __proto__: null,
  'AES-128': [16, 16],
  'AES-192': [24, 16],
  'AES-256': [32, 16],
  'ARC2-40': [5, 8],
  'ARC2-64': [8, 8],
  'ARC2-128': [16, 8],
  'BF': [16, 8],
  'BLOWFISH': [16, 8],
  'CAMELLIA-128': [16, 16],
  'CAMELLIA-192': [24, 16],
  'CAMELLIA-256': [32, 16],
  'CAST5': [16, 8],
  'DES': [8, 8],
  'DES-EDE': [16, 8],
  'DES-EDE3': [24, 8],
  'IDEA': [16, 8],
  'SERPENT-128': [16, 16],
  'SERPENT-192': [24, 16],
  'SERPENT-256': [32, 16],
  'TWOFISH-128': [16, 16],
  'TWOFISH-192': [24, 16],
  'TWOFISH-256': [32, 16]
};

/**
 * Encrypt a block.
 * @param {PEMBlock} block
 * @param {String} name
 * @param {String} passwd
 * @returns {PEMBlock}
 */

function encrypt(block, name, passwd) {
  assert(block instanceof PEMBlock);
  assert(typeof name === 'string');
  assert(typeof passwd === 'string');

  if (block.isEncrypted())
    throw new Error('PEM block is already encrypted.');

  const [keySize, ivSize] = cipherInfo(name);
  const iv = random.randomBytes(ivSize);
  const [key] = eb2k.derive(MD5, passwd, iv, keySize, ivSize);

  block.data = cipher.encrypt(name, key, iv, block.data);

  block.setProcType(4, 'ENCRYPTED');
  block.setDEKInfo(name, iv);

  return block;
}

/**
 * Decrypt a block.
 * @param {PEMBlock} block
 * @param {String} passwd
 * @returns {PEMBlock}
 */

function decrypt(block, passwd) {
  assert(block instanceof PEMBlock);
  assert(typeof passwd === 'string');

  if (!block.isEncrypted())
    throw new Error('PEM block is not encrypted.');

  const info = block.getDEKInfo();

  if (!info)
    throw new Error('DEK-Info not found.');

  const [keySize, ivSize] = cipherInfo(info.name);
  const [key] = eb2k.derive(MD5, passwd, info.iv, keySize, ivSize);

  block.data = cipher.decrypt(info.name, key, info.iv, block.data);

  block.unsetProcType();
  block.unsetDEKInfo();

  return block;
}

/*
 * Helpers
 */

function cipherInfo(name) {
  assert(typeof name === 'string');

  if (name.substring(0, 3) === 'RC2')
    name = 'A' + name;

  if (name.length < 5 || name[name.length - 4] !== '-')
    throw new Error(`Unsupported cipher: ${name}.`);

  const algo = name.substring(0, name.length - 4);
  const info = ciphers[algo];

  if (!info)
    throw new Error(`Unsupported cipher: ${name}.`);

  return info;
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;

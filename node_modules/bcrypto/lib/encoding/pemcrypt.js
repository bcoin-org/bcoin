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

  const {keySize, ivSize} = cipher.get(name);
  const iv = random.randomBytes(ivSize);
  const [key] = eb2k.derive(passwd, iv, keySize, ivSize);

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

  const {keySize, ivSize} = cipher.get(info.name);
  const [key] = eb2k.derive(passwd, info.iv, keySize, ivSize);

  block.data = cipher.decrypt(info.name, key, info.iv, block.data);

  block.unsetProcType();
  block.unsetDEKInfo();

  return block;
}

/*
 * Expose
 */

exports.encrypt = encrypt;
exports.decrypt = decrypt;

/*!
 * ciphers.js - cipher list for bcrypto
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 */

/* eslint no-prototype-builtins: "off" */

'use strict';

const assert = require('../internal/assert');

/*
 * Constants
 */

const ciphers = {
  'AES-128': [16, 16],
  'AES-192': [16, 24],
  'AES-256': [16, 32],
  'BF': [8, 16], // 4 - 56/72 bytes, pgp default is 16
  'CAMELLIA-128': [16, 16],
  'CAMELLIA-192': [16, 24],
  'CAMELLIA-256': [16, 32],
  'CAST5': [8, 16],
  'DES': [8, 8],
  'DES-EDE': [8, 16],
  'DES-EDE3': [8, 24],
  'IDEA': [8, 16],
  'RC2-64': [8, 8], // 1 - 128 bytes, default is 8
  'TWOFISH-128': [16, 16],
  'TWOFISH-192': [16, 24],
  'TWOFISH-256': [16, 32]
};

/**
 * CipherInfo
 */

class CipherInfo {
  constructor(name, algorithm, mode, blockSize, keySize, ivSize) {
    this.name = name;
    this.algorithm = algorithm;
    this.mode = mode;
    this.blockSize = blockSize;
    this.keySize = keySize;
    this.ivSize = ivSize;
  }
}

/*
 * Ciphers
 */

function parse(name) {
  assert(typeof name === 'string');

  const len = name.length;

  if (len < 1 || len > 64)
    throw new Error('Invalid cipher name.');

  let suffix = null;
  let mode = null;
  let algorithm = null;

  if (len >= 6)
    suffix = name.substring(len - 4);

  switch (suffix) {
    case '-ECB':
      mode = 'ECB';
      break;
    case '-CBC':
      mode = 'CBC';
      break;
    case '-CTR':
      mode = 'CTR';
      break;
    case '-CFB':
      mode = 'CFB';
      break;
    case '-OFB':
      mode = 'OFB';
      break;
    case '-GCM':
      mode = 'GCM';
      break;
    default:
      suffix = null;
      break;
  }

  if (suffix)
    algorithm = name.substring(0, len - 4);
  else
    algorithm = name;

  if (!ciphers.hasOwnProperty(algorithm))
    throw new Error(`Unknown cipher: ${name}.`);

  if (mode === 'GCM') {
    const size = ciphers[algorithm][0];

    if (size !== 16)
      throw new Error(`Unsupported mode: ${mode}-${size * 8}.`);
  }

  return [name, algorithm, mode];
}

function info(cipher) {
  const [name, algorithm, mode] = parse(cipher);
  const [blockSize, keySize] = ciphers[algorithm];

  let ivSize = blockSize;

  if (!mode || mode === 'ECB')
    ivSize = 0;

  return new CipherInfo(
    name,
    algorithm,
    mode,
    blockSize,
    keySize,
    ivSize
  );
}

function get(cipher) {
  const c = info(cipher);

  if (!c.mode)
    throw new Error('No mode provided for cipher name.');

  return c;
}

function has(cipher) {
  assert(typeof cipher === 'string');

  try {
    const mode = parse(cipher)[2];
    return mode != null;
  } catch (e) {
    return false;
  }
}

/*
 * Expose
 */

exports.info = info;
exports.get = get;
exports.has = has;

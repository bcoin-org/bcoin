/*!
 * util.js - utils for bfile
 * Copyright (c) 2014-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bfile
 */

/* global SharedArrayBuffer */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const {resolve} = require('path');
const {ArgError} = require('./error');

/*
 * Constants
 */

const WINDOWS = process.platform === 'win32';
const HAS_SHARED_ARRAY_BUFFER = typeof SharedArrayBuffer === 'function';

let url = null;

/*
 * Utils
 */

function call(func, args) {
  return new Promise(function(resolve, reject) {
    const cb = function(err, res) {
      if (err)
        reject(err);
      else
        resolve(res);
    };

    try {
      func(...args, cb);
    } catch (e) {
      reject(e);
    }
  });
}

function promisify(func) {
  if (!func)
    return null;

  return function promisified(...args) {
    return new Promise(function(resolve, reject) {
      const cb = function(err, res) {
        if (err)
          reject(err);
        else
          resolve(res);
      };

      try {
        func(...args, cb);
      } catch (e) {
        reject(e);
      }
    });
  };
}

function isPath(path) {
  return typeof path === 'string'
      || Buffer.isBuffer(path)
      || (path instanceof Uint8Array)
      || ((path instanceof url.URL)
          && path.protocol === 'file:');
}

function fromPath(path) {
  if (typeof path === 'string')
    return path;

  if (Buffer.isBuffer(path))
    return path.toString('utf8');

  if (path instanceof Uint8Array)
    return toBuffer(path).toString('utf8');

  if (path instanceof url.URL)
    return fileURLToPath(path.href);

  throw new ArgError('path', path, ['string', 'Buffer', 'URL']);
}

function fromPaths(paths) {
  if (!Array.isArray(paths))
    return [fromPath(paths)];

  const out = [];

  for (const path of paths)
    out.push(fromPath(path));

  return out;
}

function toBuffer(data) {
  if (Buffer.isBuffer(data))
    return data;

  if (ArrayBuffer.isView(data))
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);

  if (isArrayBuffer(data))
    return Buffer.from(data, 0, data.byteLength);

  throw new ArgError('data', data, ['Buffer',
                                    'TypedArray',
                                    'DataView',
                                    'ArrayBuffer',
                                    'SharedArrayBuffer']);
}

/*
 * Helpers
 */

function fileURLToPath(uri) {
  if (!url)
    url = require('url');

  if (url.fileURLToPath)
    return resolve(url.fileURLToPath(uri), '.');

  if (typeof uri !== 'string')
    throw new ArgError('uri', uri, 'string');

  try {
    uri = url.parse(uri);
  } catch (e) {
    const err = new TypeError(`Invalid URL: ${uri}`);
    err.code = 'ERR_INVALID_URL';
    throw err;
  }

  if (uri.protocol !== 'file:') {
    const err = new TypeError('The URL must be of scheme file');
    err.code = 'ERR_INVALID_URL_SCHEME';
    throw err;
  }

  if (uri.port != null) {
    const err = new TypeError(`Invalid URL: ${uri.href}`);
    err.code = 'ERR_INVALID_URL';
    throw err;
  }

  const {hostname, pathname} = uri;

  if (!WINDOWS) {
    if (hostname !== '' && hostname !== 'localhost') {
      const err = new TypeError('File URL host be "localhost" or empty');
      err.code = 'ERR_INVALID_FILE_URL_HOST';
      throw err;
    }

    for (let i = 0; i < pathname.length - 2; i++) {
      if (pathname[i] === '%') {
        const third = pathname.codePointAt(i + 2) | 0x20;

        if (pathname[i + 1] === '2' && third === 102) {
          const err = new TypeError('File URL path must '
                                  + 'not include encoded '
                                  + '/ characters');
          err.code = 'ERR_INVALID_FILE_URL_PATH';
          throw err;
        }
      }
    }

    const path = decodeURIComponent(pathname);

    if (path.length === 0)
      return '/';

    return resolve(path, '.');
  }

  for (let i = 0; i < pathname.length - 2; i++) {
    if (pathname[i] === '%') {
      const third = pathname.codePointAt(i + 2) | 0x20;

      if ((pathname[i + 1] === '2' && third === 102)
          || (pathname[i + 1] === '5' && third === 99)) {
        const err = new TypeError('File URL path must '
                                + 'not include encoded '
                                + '\\ or / characters');
        err.code = 'ERR_INVALID_FILE_URL_PATH';
        throw err;
      }
    }
  }

  const path = decodeURIComponent(pathname);

  if (hostname !== '') {
    const punycode = require('punycode');
    return resolve(`//${punycode.toUnicode(hostname)}${path}`, '.');
  }

  let letter = 0x00;
  let sep = 0x00;

  if (path.length >= 3) {
    letter = path.codePointAt(1) | 0x20;
    sep = path.charCodeAt(2);
  }

  if (letter < 0x61 || letter > 0x7a || sep !== 0x3a) {
    const err = new TypeError('File URL path must be absolute');
    err.code = 'ERR_INVALID_FILE_URL_PATH';
    throw err;
  }

  return resolve(path.substring(1), '.');
}

function isArrayBuffer(data) {
  if (data instanceof ArrayBuffer)
    return true;

  if (HAS_SHARED_ARRAY_BUFFER) {
    if (data instanceof SharedArrayBuffer)
      return true;
  }

  return false;
}

/*
 * Expose
 */

exports.call = call;
exports.promisify = promisify;
exports.isPath = isPath;
exports.fromPath = fromPath;
exports.fromPaths = fromPaths;
exports.toBuffer = toBuffer;

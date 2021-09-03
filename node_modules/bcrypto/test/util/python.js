'use strict';

const assert = require('assert');
const cp = require('child_process');

function python(code) {
  const out = cp.execFileSync('/usr/bin/env', ['python3'], {
    input: code,
    encoding: 'binary'
  });
  return Buffer.from(out.trim(), 'hex');
}

function blake2b(data, size = 32, key = null) {
  assert(Buffer.isBuffer(data));
  assert((size >>> 0) === size);
  assert(size > 0 && size <= 64);
  assert(!key || Buffer.isBuffer(key));
  assert(!key || key.length <= 64);

  const str = data.toString('hex');
  const k = key ? key.toString('hex') : '';
  const code = `
import hashlib
import binascii
h = hashlib.blake2b(digest_size=${size},key=binascii.unhexlify(b'${k}'))
h.update(binascii.unhexlify(b'${str}'))
print(h.hexdigest())
  `;

  return python(code);
}

function blake2s(data, size = 32, key = null) {
  assert(Buffer.isBuffer(data));
  assert((size >>> 0) === size);
  assert(size > 0 && size <= 64);
  assert(!key || Buffer.isBuffer(key));
  assert(!key || key.length <= 64);

  const str = data.toString('hex');
  const k = key ? key.toString('hex') : '';
  const code = `
import hashlib
import binascii
h = hashlib.blake2s(digest_size=${size},key=binascii.unhexlify(b'${k}'))
h.update(binascii.unhexlify(b'${str}'))
print(h.hexdigest())
  `;

  return python(code);
}

function sha3(data, bits = 256) {
  assert(Buffer.isBuffer(data));
  assert((bits >>> 0) === bits);
  assert(bits === 256 || bits === 384 || bits === 512);

  const str = data.toString('hex');
  const code = `
import hashlib
import binascii
h = hashlib.new('sha3_${bits}')
h.update(binascii.unhexlify(b'${str}'))
print(h.hexdigest())
  `;

  return python(code);
}

exports.blake2b = blake2b;
exports.blake2s = blake2s;
exports.sha3 = sha3;

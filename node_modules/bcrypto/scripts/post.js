'use strict';

if (process.env.NODE_BACKEND && process.env.NODE_BACKEND !== 'native')
  return;

const parts = process.version.split(/[^\d]/);
const major = parts[1] >>> 0;
const minor = parts[2] >>> 0;
const patch = parts[3] >>> 0;

const binding = require('../lib/native/binding');
const random = require('../lib/native/random');
const {CipherBase, pbkdf2, rsa} = binding;

if (binding.major !== major
    || binding.minor !== minor
    || binding.patch !== patch) {
  throw new Error('Incorrect node.js version for bcrypto.');
}

function assert(ok) {
  if (!ok)
    throw new Error('Assertion error.');
}

// Make sure the RNG works.
{
  const bytes1 = random.randomBytes(32);
  const zero = Buffer.alloc(32, 0x00);
  zero.fill(0x00);

  assert(!bytes1.equals(zero));

  const bytes2 = random.randomBytes(32);

  assert(!bytes2.equals(zero));
  assert(!bytes2.equals(bytes1));
}

binding.load();

assert(CipherBase.hasCipher('AES-256-CBC'));
assert(pbkdf2.hasHash('SHA256'));
assert(pbkdf2.hasHash('SHA512'));

if (rsa) {
  assert(rsa.hasHash('SHA256'));
  assert(rsa.hasHash('SHA512'));
}

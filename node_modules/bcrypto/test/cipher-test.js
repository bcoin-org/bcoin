'use strict';

const assert = require('bsert');
const fs = require('fs');
const cipher = require('../lib/cipher');
const rng = require('../lib/random');
const {Cipher, Decipher, encrypt, decrypt} = cipher;

const algs = [
  {
    name: 'AES-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'AES-128-ECB',
      'AES-128-CBC',
      'AES-128-CTR',
      'AES-128-CFB',
      'AES-128-OFB',
      'AES-128-GCM'
    ]
  },
  {
    name: 'AES-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'AES-192-ECB',
      'AES-192-CBC',
      'AES-192-CTR',
      'AES-192-CFB',
      'AES-192-OFB',
      'AES-192-GCM'
    ]
  },
  {
    name: 'AES-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'AES-256-ECB',
      'AES-256-CBC',
      'AES-256-CTR',
      'AES-256-CFB',
      'AES-256-OFB',
      'AES-256-GCM'
    ]
  },
  {
    name: 'ARC2',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'ARC2-64-CBC'
    ]
  },
  {
    name: 'Blowfish',
    keyLen: 32,
    ivLen: 8,
    ids: [
      'BF-ECB',
      'BF-CBC',
      'BF-CFB',
      'BF-OFB'
    ]
  },
  {
    name: 'CAMELLIA-128',
    keyLen: 16,
    ivLen: 16,
    ids: [
      'CAMELLIA-128-ECB',
      'CAMELLIA-128-CBC',
      'CAMELLIA-128-CTR',
      'CAMELLIA-128-CFB',
      'CAMELLIA-128-OFB'
    ]
  },
  {
    name: 'CAMELLIA-192',
    keyLen: 24,
    ivLen: 16,
    ids: [
      'CAMELLIA-192-ECB',
      'CAMELLIA-192-CBC',
      'CAMELLIA-192-CTR',
      'CAMELLIA-192-CFB',
      'CAMELLIA-192-OFB'
    ]
  },
  {
    name: 'CAMELLIA-256',
    keyLen: 32,
    ivLen: 16,
    ids: [
      'CAMELLIA-256-ECB',
      'CAMELLIA-256-CBC',
      'CAMELLIA-256-CTR',
      'CAMELLIA-256-CFB',
      'CAMELLIA-256-OFB'
    ]
  },
  {
    name: 'CAST5',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'CAST5-ECB',
      'CAST5-CBC',
      'CAST5-CFB',
      'CAST5-OFB'
    ]
  },
  {
    name: 'DES',
    keyLen: 8,
    ivLen: 8,
    ids: [
      'DES-ECB',
      'DES-CBC',
      'DES-CFB',
      'DES-OFB'
    ]
  },
  {
    name: 'IDEA',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'IDEA-ECB',
      'IDEA-CBC',
      'IDEA-CFB',
      'IDEA-OFB'
    ]
  },
  {
    name: 'Triple-DES (EDE)',
    keyLen: 16,
    ivLen: 8,
    ids: [
      'DES-EDE-ECB',
      'DES-EDE-CBC',
      'DES-EDE-CFB',
      'DES-EDE-OFB'
    ]
  },
  {
    name: 'Triple-DES (EDE3)',
    keyLen: 24,
    ivLen: 8,
    ids: [
      'DES-EDE3-ECB',
      'DES-EDE3-CBC',
      'DES-EDE3-CFB',
      'DES-EDE3-OFB'
    ]
  }
];

function _encipher(ctx, gcm, key, iv, data) {
  ctx.init(key, iv);

  assert.throws(() => ctx.getAuthTag());
  assert.throws(() => ctx.setAuthTag(Buffer.alloc(16)));

  if (rng.randomRange(0, 2))
    ctx.update(Buffer.alloc(0));

  return Buffer.concat([
    ctx.update(data),
    ctx.final(),
    gcm ? ctx.getAuthTag() : Buffer.alloc(0)
  ]);
}

function _decipher(ctx, gcm, key, iv, data) {
  ctx.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    data = data.slice(0, -16);
    ctx.setAuthTag(tag);
  }

  assert.throws(() => ctx.getAuthTag());

  if (rng.randomRange(0, 2))
    ctx.update(Buffer.alloc(0));

  return Buffer.concat([
    ctx.update(data),
    ctx.final()
  ]);
}

function encipher(name, key, iv, data) {
  const ctx = new Cipher(name);
  const gcm = name.endsWith('-GCM');
  return _encipher(ctx, gcm, key, iv, data);
}

function decipher(name, key, iv, data) {
  const ctx = new Decipher(name);
  const gcm = name.endsWith('-GCM');
  return _decipher(ctx, gcm, key, iv, data);
}

function encipher2(name, key, iv, data) {
  const ctx = new Cipher(name);
  const gcm = name.endsWith('-GCM');
  const expect = _encipher(ctx, gcm, key, iv, data);
  const out = _encipher(ctx, gcm, key, iv, data);

  assert.bufferEqual(out, expect);

  return out;
}

function decipher2(name, key, iv, data) {
  const ctx = new Decipher(name);
  const gcm = name.endsWith('-GCM');
  const expect = _decipher(ctx, gcm, key, iv, data);
  const out = _decipher(ctx, gcm, key, iv, data);

  assert.bufferEqual(out, expect);

  return out;
}

function encipher3(name, key, iv, data) {
  const ctx = new Cipher(name);
  const gcm = name.endsWith('-GCM');

  ctx.init(key, iv);
  ctx.update(data);

  return _encipher(ctx, gcm, key, iv, data);
}

function decipher3(name, key, iv, data) {
  const ctx = new Decipher(name);
  const gcm = name.endsWith('-GCM');

  ctx.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    const d = data.slice(0, -16);
    ctx.setAuthTag(tag);
    ctx.update(d);
  } else {
    ctx.update(data);
  }

  return _decipher(ctx, gcm, key, iv, data);
}

function encipherInc(name, key, iv, data) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Cipher(name);

  ctx.init(key, iv);

  const out = [];
  const buf = Buffer.alloc(1);

  for (let i = 0; i < data.length; i++) {
    buf[0] = data[i];
    out.push(ctx.update(buf));
  }

  out.push(ctx.final());
  out.push(gcm ? ctx.getAuthTag() : Buffer.alloc(0));

  if (gcm)
    assert.doesNotThrow(() => ctx.getAuthTag());
  else
    assert.throws(() => ctx.getAuthTag());

  ctx.destroy();

  return Buffer.concat(out);
}

function decipherInc(name, key, iv, data) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Decipher(name);

  ctx.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    data = data.slice(0, -16);
    ctx.setAuthTag(tag);
  }

  const out = [];
  const buf = Buffer.alloc(1);

  for (let i = 0; i < data.length; i++) {
    buf[0] = data[i];
    out.push(ctx.update(buf));
  }

  out.push(ctx.final());

  assert.throws(() => ctx.getAuthTag());

  ctx.destroy();

  return Buffer.concat(out);
}

function encipherRand(name, key, iv, data) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Cipher(name);

  ctx.init(key, iv);

  const out = [];
  const max = Math.max(2, data.length >>> 2);

  let i = 0;

  while (i < data.length) {
    const j = rng.randomRange(0, max);

    out.push(ctx.update(data.slice(i, i + j)));

    i += j;
  }

  out.push(ctx.final());
  out.push(gcm ? ctx.getAuthTag() : Buffer.alloc(0));

  return Buffer.concat(out);
}

function decipherRand(name, key, iv, data) {
  const gcm = name.endsWith('-GCM');
  const ctx = new Decipher(name);

  ctx.init(key, iv);

  if (gcm) {
    const tag = data.slice(-16);
    data = data.slice(0, -16);
    ctx.setAuthTag(tag);
  }

  const out = [];
  const max = Math.max(2, data.length >>> 2);

  let i = 0;

  while (i < data.length) {
    const j = rng.randomRange(0, max);

    out.push(ctx.update(data.slice(i, i + j)));

    i += j;
  }

  out.push(ctx.final());

  return Buffer.concat(out);
}

describe('Cipher', function() {
  for (const alg of algs) {
    describe(alg.name, function() {
      for (const id of alg.ids) {
        const gcm = id.endsWith('-GCM');
        const file = `${__dirname}/data/ciphers/${id.toLowerCase()}.json`;
        const text = fs.readFileSync(file, 'utf8');
        const vectors = JSON.parse(text);

        for (const [key_, iv_, data_, expect_] of vectors) {
          const key = Buffer.from(key_, 'hex');
          const iv = Buffer.from(iv_, 'hex');
          const data = Buffer.from(data_, 'hex');
          const expect = Buffer.from(expect_, 'hex');
          const hex = data_.slice(0, 32);

          it(`should encrypt and decrypt ${hex} with ${id}`, () => {
            assert.bufferEqual(encipher(id, key, iv, data), expect);
            assert.bufferEqual(decipher(id, key, iv, expect), data);
            assert.bufferEqual(encipher2(id, key, iv, data), expect);
            assert.bufferEqual(decipher2(id, key, iv, expect), data);
            assert.bufferEqual(encipher3(id, key, iv, data), expect);
            assert.bufferEqual(decipher3(id, key, iv, expect), data);
            assert.bufferEqual(encipherInc(id, key, iv, data), expect);
            assert.bufferEqual(decipherInc(id, key, iv, expect), data);
            assert.bufferEqual(encipherRand(id, key, iv, data), expect);
            assert.bufferEqual(decipherRand(id, key, iv, expect), data);

            if (!gcm) {
              assert.bufferEqual(encrypt(id, key, iv, data), expect);
              assert.bufferEqual(decrypt(id, key, iv, expect), data);
            }
          });
        }
      }
    });
  }
});

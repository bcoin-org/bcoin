'use strict';

const assert = require('bsert');
const zlib = require('zlib');
const random = require('../lib/random');

function isRandom(data, d) {
  assert(Buffer.isBuffer(data));
  assert(isFinite(d));

  let sum = 0;

  for (let i = 0; i < data.length; i++) {
    for (let j = 0; j < 8; j++)
      sum += (data[i] >>> (7 - j)) & 1;
  }

  const avg = sum / (data.length * 8);

  return avg >= (0.5 - d) && avg <= (0.5 + d);
}

describe('Random', function() {
  it('should generate random bytes', () => {
    assert.notBufferEqual(random.randomBytes(32), Buffer.alloc(32, 0x00));
  });

  it('should fill random bytes', () => {
    const bytes = Buffer.alloc(32, 0x00);
    const rand = Buffer.from(bytes);

    assert.strictEqual(random.randomFill(rand, 0, 32), rand);
    assert.notBufferEqual(rand, bytes);
  });

  it('should fill random bytes without args', () => {
    const bytes = Buffer.alloc(32, 0x00);
    const rand = Buffer.from(bytes);

    assert.strictEqual(random.randomFill(rand), rand);
    assert.notBufferEqual(rand, bytes);
  });

  it('should generate and fill zero random bytes', () => {
    const rand = Buffer.alloc(0);

    assert.bufferEqual(random.randomBytes(0), rand);
    assert.strictEqual(random.randomFill(rand), rand);
  });

  it('should get random int', () => {
    let n = random.randomInt();

    assert((n >>> 0) === n);

    for (let i = 0; i < 1000; i++) {
      n = random.randomInt();

      assert((n >>> 0) === n);

      if (n !== 0)
        break;
    }

    assert.notStrictEqual(n, 0);
  });

  it('should get random range', () => {
    assert.strictEqual(random.randomRange(0, 0), 0);
    assert.strictEqual(random.randomRange(0, 1), 0);

    for (let i = 0; i < 100; i++) {
      const n = random.randomRange(1, 100);

      assert((n >>> 0) === n);
      assert(n >= 1 && n < 100);
    }
  });

  it('should get a large number of bytes', () => {
    // The browser limits us at 65,536 bytes per call.
    // Make sure our RNG wrapper can exceed that.
    assert.strictEqual(random.randomBytes(65535).length, 65535);
    assert.strictEqual(random.randomBytes(65536).length, 65536);
    assert.strictEqual(random.randomBytes(65537).length, 65537);
    assert.strictEqual(random.randomBytes(1 << 17).length, 1 << 17);
  });

  it('should not be able to compress random bytes', () => {
    // Idea taken from golang:
    //   https://github.com/golang/go/blob/master/src/crypto/rand/rand_test.go
    //
    // Compression involves reducing redundancy. Random
    // data shouldn't have any significant redundancy.
    const rand = random.randomBytes(4e6);
    const defl = zlib.deflateRawSync(rand, { level: 5 });
    const perc = defl.length / rand.length;

    assert(perc >= 0.99, `Deflated data was %${perc.toFixed(2)} of original.`);

    // We can also check randomness by summing the one
    // bits and ensuring that they make up roughly 50%
    // of the data (we'll use a 2% margin of error).
    //
    // See also:
    //   https://wiki.openssl.org/index.php/Random_Numbers
    //   https://csrc.nist.gov/projects/random-bit-generation/
    assert(isRandom(rand, 0.02));
  });

  it('should not be able to compress random fill', () => {
    const rand = Buffer.alloc(4e6);

    random.randomFill(rand, 0, 4e6);

    const defl = zlib.deflateRawSync(rand, { level: 5 });
    const perc = defl.length / rand.length;

    assert(perc >= 0.99, `Deflated data was %${perc.toFixed(2)} of original.`);
    assert(isRandom(rand, 0.02));
  });

  it('should test distribution of randomRange()', () => {
    const array = new Uint16Array(4e6 / 2);
    const rand = Buffer.from(array.buffer, array.byteOffset, array.byteLength);

    for (let i = 0; i < array.length; i++)
      array[i] = random.randomRange(0, 0x10000);

    const defl = zlib.deflateRawSync(rand, { level: 5 });
    const perc = defl.length / rand.length;

    assert(perc >= 0.99, `Deflated data was %${perc.toFixed(2)} of original.`);
    assert(isRandom(rand, 0.02));
  });

  if (random._getEntropy) {
    it('should get OS entropy', () => {
      const bytes = Buffer.alloc(65536, 0x00);
      const rand = random._getEntropy(65536);
      const defl = zlib.deflateRawSync(rand, { level: 5 });
      const perc = defl.length / rand.length;

      assert.notBufferEqual(rand, bytes);
      assert(perc >= 0.99, `Deflated data was %${perc.toFixed(2)} of original.`);
      assert(isRandom(rand, 0.02));
    });
  }
});

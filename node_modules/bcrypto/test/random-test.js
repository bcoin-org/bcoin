/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const random = require('../lib/random');
const zero = Buffer.alloc(32, 0x00);
const bytes = Buffer.allocUnsafe(32);

for (let i = 0; i < 32; i++)
  bytes[i] = i;

describe('Random', function() {
  it('should generate random bytes', () => {
    const rand = Buffer.from(bytes);
    random.randomFill(rand, 0, 32);
    assert.notBufferEqual(rand, bytes);
  });

  it('should generate random bytes without args', () => {
    const rand = Buffer.from(bytes);
    random.randomFill(rand);
    assert.notBufferEqual(rand, bytes);
  });

  it('should generate random bytes (async)', async () => {
    const rand = Buffer.from(bytes);
    await random.randomFillAsync(rand, 0, 32);
    assert.notBufferEqual(rand, bytes);
  });

  it('should generate random bytes without args (async)', async () => {
    const rand = Buffer.from(bytes);
    await random.randomFillAsync(rand);
    assert.notBufferEqual(rand, bytes);
  });

  it('should get random bytes', () => {
    const rand = random.randomBytes(32);
    assert.notBufferEqual(rand, zero);
  });

  it('should get random bytes (async)', async () => {
    const rand = await random.randomBytes(32);
    assert.notBufferEqual(rand, zero);
  });

  it('should get random int', () => {
    const rand = random.randomInt();
    assert((rand >>> 0) === rand);
  });

  it('should get random range', () => {
    const rand = random.randomRange(1, 100);
    assert((rand >>> 0) === rand);
    assert(rand >= 1 && rand < 100);
  });
});

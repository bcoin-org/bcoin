'use strict';

const assert = require('bsert');
const box = require('../lib/secretbox');
const x25519 = require('../lib/x25519');
const random = require('../lib/random');

describe('Secret Box', function() {
  it('should seal and open box', () => {
    const key = Buffer.alloc(32, 1);
    const nonce = Buffer.alloc(24, 2);
    const msg = Buffer.alloc(64, 3);
    const sealed = box.seal(msg, key, nonce);
    const opened = box.open(sealed, key, nonce);

    const expect = '8442bc313f4626f1359e3b50122b6ce6fe66ddfe'
                 + '7d39d14e637eb4fd5b45beadab55198df6ab5368'
                 + '439792a23c87db70acb6156dc5ef957ac04f6276'
                 + 'cf6093b84be77ff0849cc33e34b7254d5a8f65ad';

    assert.bufferEqual(sealed, expect, 'hex');
    assert.bufferEqual(opened, msg);
  });

  it('should seal and open box (crypto_secretbox_xsalsa20poly1305)', () => {
    const priv1 = Buffer.alloc(32, 1);
    const priv2 = Buffer.alloc(32, 2);
    const pub1 = x25519.publicKeyCreate(priv1);
    const secret = x25519.derive(pub1, priv2);
    const key = box.derive(secret);
    const msg = Buffer.alloc(64, 3);
    const nonce = Buffer.alloc(24, 4);
    const sealed = box.seal(msg, key, nonce);
    const opened = box.open(sealed, key, nonce);

    const expect = '78ea30b19d2341ebbdba54180f821eec265cf863'
                 + '12549bea8a37652a8bb94f07b78a73ed1708085e'
                 + '6ddd0e943bbdeb8755079a37eb31d86163ce2411'
                 + '64a47629c0539f330b4914cd135b3855bc2a2dfc';

    assert.bufferEqual(sealed, expect, 'hex');
    assert.bufferEqual(opened, msg);
  });

  it('should encrypt random boxes', () => {
    const key = random.randomBytes(32);
    const nonce = random.randomBytes(24);

    let last = null;

    for (let len = 0; len < 128; len += 17) {
      const msg = random.randomBytes(len);
      const sealed = box.seal(msg, key, nonce);

      assert.notBufferEqual(sealed, msg);

      if (len > 0) {
        assert.notBufferEqual(sealed.slice(0, msg.length), msg);
        assert.notBufferEqual(sealed.slice(16, 16 + msg.length), msg);
      }

      const opened = box.open(sealed, key, nonce);

      assert.bufferEqual(opened, msg);

      last = sealed;
    }

    for (let i = 0; i < last.length; i++) {
      last[i] ^= 0x20;
      assert.throws(() => box.open(last, key, nonce));
      last[i] ^= 0x20;
    }

    box.open(last, key, nonce);
  });
});

'use strict';

const assert = require('bsert');
const box = require('../lib/box');
const ecies = require('../lib/ecies');
const x25519 = require('../lib/x25519');

describe('Box', function() {
  it('should seal and open box (crypto_secretbox_xsalsa20poly1305)', () => {
    const priv1 = Buffer.alloc(32, 1);
    const priv2 = Buffer.alloc(32, 2);
    const pub1 = x25519.publicKeyCreate(priv1);
    const pub2 = x25519.publicKeyCreate(priv2);
    const msg = Buffer.alloc(64, 3);
    const sealed = box.seal(msg, pub1, priv2);
    const opened = box.open(sealed, priv1);

    assert.bufferEqual(sealed.slice(0, 32), pub2);
    assert.bufferEqual(opened, msg);
    assert.bufferEqual(ecies.decrypt(x25519, null, sealed, priv1), msg);
  });

  it('should open box (crypto_secretbox_xsalsa20poly1305)', () => {
    const priv1 = Buffer.alloc(32, 1);
    const priv2 = Buffer.alloc(32, 2);
    const pub2 = x25519.publicKeyCreate(priv2);
    const msg = Buffer.alloc(64, 3);
    const nonce = Buffer.alloc(24, 4);

    const hex = '78ea30b19d2341ebbdba54180f821eec265cf863'
              + '12549bea8a37652a8bb94f07b78a73ed1708085e'
              + '6ddd0e943bbdeb8755079a37eb31d86163ce2411'
              + '64a47629c0539f330b4914cd135b3855bc2a2dfc';

    const sealed = Buffer.concat([pub2, nonce, Buffer.from(hex, 'hex')]);
    const opened = box.open(sealed, priv1);

    assert.bufferEqual(opened, msg);
    assert.bufferEqual(ecies.decrypt(x25519, null, sealed, priv1), msg);
  });
});

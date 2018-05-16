/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('./util/assert');
const sha256 = require('bcrypto/lib/sha256');

const KeyRing = require('../lib/primitives/keyring');
const key = sha256.digest(Buffer.from('private-key'));
const {sign, recover} = require('../lib/utils/message');

const msg = 'Message To Sign';

const uncompressed =
  'G87wcBTu5HXBjBUwpsu+2U9q/0oVqPROSSG0kXaQEK4J' +
  'AoZAUUtVagvd3AHfX7TS2bHEzDnbn7t/uiIcFeZznlI=';

const compressed =
  'H87wcBTu5HXBjBUwpsu+2U9q/0oVqPROSSG0kXaQEK4J' +
  'AoZAUUtVagvd3AHfX7TS2bHEzDnbn7t/uiIcFeZznlI=';

describe('Utils.message', function () {
  it('should sign message', () => {
    assert.strictEqual(
      sign(msg, KeyRing.fromKey(key, false)).toString('base64'),
      uncompressed
    );

    assert.strictEqual(
      sign(msg, KeyRing.fromKey(key, true)).toString('base64'),
      compressed
    );
  });

  it('should recover public key', () => {
    assert.strictEqual(
      recover(msg, Buffer.from(compressed, 'base64')).toString('base64'),
      KeyRing.fromKey(key, true).getPublicKey().toString('base64')
    );

    assert.strictEqual(
      recover(msg, Buffer.from(uncompressed, 'base64')).toString('base64'),
      KeyRing.fromKey(key, false).getPublicKey().toString('base64')
    );
  });
});

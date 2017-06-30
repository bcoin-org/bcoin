'use strict';

const assert = require('assert');
const keyring = require('../lib/primitives/keyring');

describe('Keyring Address', function() {
  let ukey = keyring.fromSecret('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss');
  let ckey = keyring.fromSecret('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1');

  it('check uncompressed public key', () => {
    assert.equal(
      '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b'
      + '8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235',
      ukey.getPublicKey('hex'));
  });

  it('check uncompressed public key to address', () => {
    assert.equal(
      '1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN',
      ukey.getKeyAddress('base58'));
  });

  it('check uncompressed secret', () => {
    assert.equal(
      '5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss',
      ukey.toSecret());
  });

  it('check compressed public key', () => {
    assert.equal(
      '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
      ckey.getPublicKey('hex'));
  });

  it('check compressed public key to address', () => {
    assert.equal(
      '1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV',
      ckey.getKeyAddress('base58'));
  });

  it('check compressed secret', () => {
    assert.equal(
      'L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1',
      ckey.toSecret());
  });
});

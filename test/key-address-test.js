`use strict`;
var assert = require('assert');
var keyring = require('../lib/primitives/keyring');

describe('Keyring Address', function () {
  let uncompressedlKey = keyring.fromSecret('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss');
  it('check uncompressed public key', function () {
    assert.equal('04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235', uncompressedlKey.getPublicKey('hex'));
  });
  it('ckeck uncompressed public key to address', function () {
    assert.equal('1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN', uncompressedlKey.getKeyAddress("base58"));
  });
  it('check uncompressed secret', function () {
    assert.equal('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss', uncompressedlKey.toSecret());
  });
  
  let compressedKey = keyring.fromSecret('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1');
  it('check compressed  public key', function () {
    assert.equal('03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd', compressedKey.getPublicKey('hex'));
    
  });
  it('check compressed public key to address', function () {
    assert.equal('1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV', compressedKey.getKeyAddress("base58"));
  });
  it('check compressed secret', function () {
    assert.equal('L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1', compressedKey.toSecret());
  });
  
  
});



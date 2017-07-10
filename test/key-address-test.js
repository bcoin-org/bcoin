'use strict';

var assert = require('assert');
var keyring = require('../lib/primitives/keyring');

describe('Keyring Address', function() {
  var ukey = keyring.fromSecret('6vrJ6bnKwaSuimkkRLpNNziSjqwZCG59kfFC9P2kjbUUs5Y6Cw9');
  var ckey = keyring.fromSecret('TAgaTiX4btdMhNY6eSU5N5jvc71o6hXKdhoeBzEk31AHykGDou8i');

  it('check uncompressed public key', function() {
    assert.equal(
      '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b'
      + '8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235',
      ukey.getPublicKey('hex'));
  });

  it('check uncompressed public key to address', function() {
    assert.equal(
      'Lbnu1x4UfToiiFGU8MvPrLpj2GSrtUrxFH',
      ukey.getKeyAddress('base58'));
  });

  it('check uncompressed secret', function() {
    assert.equal(
      '6vrJ6bnKwaSuimkkRLpNNziSjqwZCG59kfFC9P2kjbUUs5Y6Cw9',
      ukey.toSecret());
  });

  it('check compressed public key', function() {
    assert.equal(
      '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd',
      ckey.getPublicKey('hex'));
  });

  it('check compressed public key to address', function() {
    assert.equal(
      'LZGpRyQPybaDjbRGoB87YH2ebFnmKYmRui',
      ckey.getKeyAddress('base58'));
  });

  it('check compressed secret', function() {
    assert.equal(
      'TAgaTiX4btdMhNY6eSU5N5jvc71o6hXKdhoeBzEk31AHykGDou8i',
      ckey.toSecret());
  });
});

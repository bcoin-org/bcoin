'use strict';

var assert = require('assert');
var scrypt = require('../lib/crypto/crypto').scrypt;

describe('Scrypt', function() {
  it('should perform scrypt with N=16', function() {
    var pass = new Buffer('');
    var salt = new Buffer('');
    var result = scrypt(pass, salt, 16, 1, 1, 64);
    assert.equal(result.toString('hex'), ''
      + '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3f'
      + 'ede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628'
      + 'cf35e20c38d18906');
  });

  it('should perform scrypt with N=1024', function() {
    var pass = new Buffer('password');
    var salt = new Buffer('NaCl');
    var result = scrypt(pass, salt, 1024, 8, 16, 64);
    assert.equal(result.toString('hex'), ''
      + 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e773'
      + '76634b3731622eaf30d92e22a3886ff109279d9830dac727afb9'
      + '4a83ee6d8360cbdfa2cc0640');
  });

  it('should perform scrypt with N=16384', function() {
    var pass = new Buffer('pleaseletmein');
    var salt = new Buffer('SodiumChloride');
    var result = scrypt(pass, salt, 16384, 8, 1, 64);
    assert.equal(result.toString('hex'), ''
      + '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b54'
      + '3f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d'
      + '651e40dfcf017b45575887');
  });

  // Only enable if you want to wait a while.
  // it('should perform scrypt with N=1048576', function() {
  //   var pass = new Buffer('pleaseletmein');
  //   var salt = new Buffer('SodiumChloride');
  //   var result = scrypt(pass, salt, 1048576, 8, 1, 64);
  //   assert.equal(result.toString('hex'), ''
  //     + '2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5'
  //     + 'ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049'
  //     + 'e8a952fbcbf45c6fa77a41a4');
  // });
});

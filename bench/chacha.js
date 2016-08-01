'use strict';

var chachapoly = require('../lib/bcoin/chachapoly');
var bench = require('./bench');

console.log('note: rate measured in kb/s');

var chacha = new chachapoly.ChaCha20();
var iv = new Buffer('0102030405060708', 'hex');
chacha.init(iv, 0);
var data = new Buffer(32);
for (var i = 0; i < 32; i++)
  data[i] = i;
var end = bench('encrypt');
for (var i = 0; i < 1000000; i++)
  chacha.encrypt(data);
end(i * 32 / 1024);

var poly = new chachapoly.Poly1305();
var key = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');
poly.init(key);

var data = new Buffer(32);
for (var i = 0; i < 32; i++)
  data[i] = i & 0xff;

var end = bench('update');
for (var i = 0; i < 1000000; i++)
  poly.update(data);
end(i * 32 / 1024);

var end = bench('finish');
for (var i = 0; i < 1000000; i++) {
  poly.init(key);
  poly.update(data);
  poly.finish();
}
end(i * 32 / 1024);

// For reference:
var utils = require('../lib/bcoin/utils');
var end = bench('sha256');
for (var i = 0; i < 1000000; i++)
  utils.hash256(data);
end(i * 32 / 1024);

'use strict';

var chachapoly = require('../lib/bcoin/chachapoly');
var bench = require('./bench');

var chacha = new chachapoly.ChaCha20();
var iv = new Buffer('0102030405060708', 'hex');
chacha.init(iv, 0);
var data = new Buffer(32);
for (var i = 0; i < 32; i++)
  data[i] = i;
var end = bench('encrypt');
for (var i = 0; i < 1000000; i++)
  chacha.encrypt(data);
end(i);

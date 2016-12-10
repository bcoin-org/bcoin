'use strict';

var chachapoly = require('../lib/crypto/chachapoly');
var crypto = require('../lib/crypto/crypto');
var bench = require('./bench');
var i, chacha, iv, poly, key, data, end;

console.log('note: rate measured in kb/s');

chacha = new chachapoly.ChaCha20();
iv = new Buffer('0102030405060708', 'hex');
chacha.init(iv, 0);
data = new Buffer(32);
for (i = 0; i < 32; i++)
  data[i] = i;
end = bench('encrypt');
for (i = 0; i < 1000000; i++)
  chacha.encrypt(data);
end(i * 32 / 1024);

poly = new chachapoly.Poly1305();
key = new Buffer('000102030405060708090a0b0c0d0e0f', 'hex');
poly.init(key);

data = new Buffer(32);
for (i = 0; i < 32; i++)
  data[i] = i & 0xff;

end = bench('update');
for (i = 0; i < 1000000; i++)
  poly.update(data);
end(i * 32 / 1024);

end = bench('finish');
for (i = 0; i < 1000000; i++) {
  poly.init(key);
  poly.update(data);
  poly.finish();
}
end(i * 32 / 1024);

// For reference:
end = bench('sha256');
for (i = 0; i < 1000000; i++)
  crypto.hash256(data);
end(i * 32 / 1024);

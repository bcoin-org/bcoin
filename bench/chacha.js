'use strict';

var ChaCha20 = require('../lib/crypto/chacha20');
var Poly1305 = require('../lib/crypto/poly1305');
var digest = require('../lib/crypto/digest');
var bench = require('./bench');
var i, chacha, iv, poly, key, data, end;

console.log('note: rate measured in kb/s');

chacha = new ChaCha20();
key = Buffer.allocUnsafe(32);
key.fill(2);
iv = Buffer.from('0102030405060708', 'hex');
chacha.init(key, iv, 0);
data = Buffer.allocUnsafe(32);
for (i = 0; i < 32; i++)
  data[i] = i;
end = bench('encrypt');
for (i = 0; i < 1000000; i++)
  chacha.encrypt(data);
end(i * 32 / 1024);

poly = new Poly1305();
key = Buffer.allocUnsafe(32);
key.fill(2);
poly.init(key);

data = Buffer.allocUnsafe(32);
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
  digest.hash256(data);
end(i * 32 / 1024);

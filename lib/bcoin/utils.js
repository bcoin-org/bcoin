var utils = exports;

var assert = require('assert');
var bn = require('bn.js');
var hash = require('hash.js');


var base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZ' +
             'abcdefghijkmnopqrstuvwxyz';

utils.toBase58 = function toBase58(arr) {
  var n = new bn(arr, 16);

  // 58 ^ 4
  var mod = new bn(0xacad10);

  var res = '';
  do {
    var r = n.mod(mod);
    n = n.div(mod);

    var end = n.cmp(0) === 0;

    assert.equal(r.length, 1);
    r = r.words[0];

    for (var i = 0; i < 4; i++) {
      var c = r % 58;
      r = (r - c) / 58;

      if (c === 0 && r === 0 && end)
        break;
      res = base58[c] + res;
    }
    assert.equal(r, 0);
  } while (!end);

  // Add leading "zeroes"
  for (var i = 0; i < arr.length; i++) {
    if (arr[i] !== 0)
      break;
    res = '1' + res;
  }

  return res;
};

utils.fromBase58 = function fromBase58(str) {
  // Count leading "zeroes"
  for (var i = 0; i < str.length; i++)
    if (str[i] !== '1')
      break;
  zeroes = i;

  // Read 4-char words and add them to bignum
  var q = 1;
  var w = 0;
  var res = new bn(0);
  for (var i = zeroes; i < str.length; i++) {
    var c = base58.indexOf(str[i]);
    assert(c >= 0 && c < 58);

    q *= 58;
    w *= 58;
    w += c;
    if (i === str.length - 1 || q === 0xacad10) {
      res = res.mul(q).add(w);
      q = 1;
      w = 0;
    }
  }

  // Add leading "zeroes"
  var z = [];
  for (var i = 0; i < zeroes; i++)
    z.push(0);
  return z.concat(res.toArray());
};

utils.ripesha = function ripesha(data, enc) {
  return hash.ripemd160().update(utils.sha256(data, enc)).digest();
};

utils.checksum = function checksum(data, enc) {
  return utils.sha256(utils.sha256(data, enc)).slice(0, 4);
};

utils.sha256 = function sha256(data, enc) {
  return hash.sha256().update(data, enc).digest();
};

utils.readU32 = function readU32(arr, off) {
  if (!off)
    off = 0;
  var r = arr[off] |
          (arr[off + 1] << 8) |
          (arr[off + 2] << 16) |
          (arr[off + 3] << 24);
  if (r < 0)
    r += 0x100000000;
  return r;
};

utils.readU64 = function readU64(arr, off) {
  if (!off)
    off = 0;
  return utils.readU32(arr, off) + utils.readU32(arr, off + 4) * 0x100000000;
};

utils.writeU32 = function writeU32(dst, num, off) {
  if (!off)
    off = 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 3] = (num >>> 24) & 0xff;
};

utils.writeAscii = function writeAscii(dst, str, off) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    dst[off + i] = c & 0xff;
  }
  return i;
};

utils.copy = function copy(src, dst, off) {
  var len = Math.min(dst.length - off, src.length);
  for (var i = 0; i < len; i++)
    dst[i + off] = src[i];
  return i;
};

utils.stringify = function stringify(arr) {
  var res = '';
  for (var i = 0; i < arr.length; i++)
    res += String.fromCharCode(arr[i]);
  return res;
};

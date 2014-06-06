var utils = exports;

var bn = require('bn.js');
var hash = require('hash.js');

function toArray(msg, enc) {
  if (Array.isArray(msg))
    return msg.slice();
  if (!msg)
    return [];
  var res = [];
  if (typeof msg === 'string') {
    if (!enc) {
      for (var i = 0; i < msg.length; i++) {
        var c = msg.charCodeAt(i);
        var hi = c >> 8;
        var lo = c & 0xff;
        if (hi)
          res.push(hi, lo);
        else
          res.push(lo);
      }
    } else if (enc === 'hex') {
      msg = msg.replace(/[^a-z0-9]+/ig, '');
      if (msg.length % 2 !== 0)
        msg = '0' + msg;
      for (var i = 0; i < msg.length; i += 8) {
        var slice = msg.slice(i, i + 8);
        var num = parseInt(slice, 16);

        if (slice.length === 8)
          res.push((num >>> 24) & 0xff);
        if (slice.length >= 6)
          res.push((num >>> 16) & 0xff);
        if (slice.length >= 4)
          res.push((num >>> 8) & 0xff);
        res.push(num & 0xff);
      }
    }
  } else {
    for (var i = 0; i < msg.length; i++)
      res[i] = msg[i] | 0;
  }
  return res;
}
utils.toArray = toArray;

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

    var end = n.cmpn(0) === 0;

    utils.assert.equal(r.length, 1);
    r = r.words[0];

    for (var i = 0; i < 4; i++) {
      var c = r % 58;
      r = (r - c) / 58;

      if (c === 0 && r === 0 && end)
        break;
      res = base58[c] + res;
    }
    utils.assert.equal(r, 0);
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
  var zeroes = i;

  // Read 4-char words and add them to bignum
  var q = 1;
  var w = 0;
  var res = new bn(0);
  for (var i = zeroes; i < str.length; i++) {
    var c = base58.indexOf(str[i]);
    if (!(c >= 0 && c < 58))
      return [];

    q *= 58;
    w *= 58;
    w += c;
    if (i === str.length - 1 || q === 0xacad10) {
      res = res.mul(new bn(q)).add(new bn(w));
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
  return utils.dsha256(data, enc).slice(0, 4);
};

utils.sha256 = function sha256(data, enc) {
  return hash.sha256().update(data, enc).digest();
};

utils.dsha256 = function dsha256(data, enc) {
  return utils.sha256(utils.sha256(data, enc));
};

utils.readU16 = function readU16(arr, off) {
  if (!off)
    off = 0;
  return arr[off] | (arr[off + 1] << 8);
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

utils.writeU16 = function writeU16(dst, num, off) {
  if (!off)
    off = 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  return 2;
};

utils.writeU32 = function writeU32(dst, num, off) {
  if (!off)
    off = 0;
  dst[off] = num & 0xff;
  dst[off + 1] = (num >>> 8) & 0xff;
  dst[off + 2] = (num >>> 16) & 0xff;
  dst[off + 3] = (num >>> 24) & 0xff;
  return 4;
};

utils.writeU64 = function writeU64(dst, num, off) {
  if (!off)
    off = 0;

  num = new bn(num).maskn(64).toArray();
  while (num.length < 8)
    num.unshift(0);

  num.reverse().forEach(function(ch) {
    dst[off++] = ch;
  });

  var i = num.length;
  while (i--)
    dst[off++] = num[i];

  return 8;
};

utils.writeU16BE = function writeU16BE(dst, num, off) {
  if (!off)
    off = 0;
  dst[off] = (num >>> 8) & 0xff;
  dst[off + 1] = num & 0xff;
  return 2;
};

utils.writeU32BE = function writeU32BE(dst, num, off) {
  if (!off)
    off = 0;
  dst[off] = (num >>> 24) & 0xff;
  dst[off + 1] = (num >>> 16) & 0xff;
  dst[off + 2] = (num >>> 8) & 0xff;
  dst[off + 3] = num & 0xff;
  return 4;
};

utils.writeU64BE = function writeU64BE(dst, num, off) {
  if (!off)
    off = 0;

  num = new bn(num).maskn(64).toArray();
  while (num.length < 8)
    num.unshift(0);

  for (var i = 0; i < num.length; i++)
    dst[off++] = num[i];

  return 8;
};

utils.readU16BE = function readU16BE(arr, off) {
  if (!off)
    off = 0;
  return (arr[off] << 8) | arr[off + 1];
};

utils.readU32BE = function readU32BE(arr, off) {
  if (!off)
    off = 0;
  var r = (arr[off] << 24) |
          (arr[off + 1] << 16) |
          (arr[off + 2] << 8) |
          arr[off + 3];
  if (r < 0)
    r += 0x100000000;
  return r;
};

utils.readU64BE = function readU64BE(arr, off) {
  if (!off)
    off = 0;
  return utils.readU32BE(arr, off) * 0x100000000 + utils.readU32BE(arr, off + 4);
};

utils.writeAscii = function writeAscii(dst, str, off) {
  for (var i = 0; i < str.length; i++) {
    var c = str.charCodeAt(i);
    dst[off + i] = c & 0xff;
  }
  return i;
};

utils.copy = function copy(src, dst, off, force) {
  var len = src.length;
  if (!force)
    len = Math.min(dst.length - off, len);
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

function zero2(word) {
  if (word.length === 1)
    return '0' + word;
  else
    return word;
}

function toHex(msg) {
  if (typeof msg === 'string')
    return msg;

  var res = '';
  for (var i = 0; i < msg.length; i++)
    res += zero2(msg[i].toString(16));
  return res;
}
utils.toHex = toHex;

function binaryInsert(list, item, compare, search) {
  var start = 0,
      end = list.length;

  while (start < end) {
    var pos = (start + end) >> 1;
    var cmp = compare(item, list[pos]);

    if (cmp === 0) {
      start = pos;
      end = pos;
      break;
    } else if (cmp < 0) {
      end = pos;
    } else {
      start = pos + 1;
    }
  }

  if (!search)
    list.splice(start, 0, item);
  return start;
}
utils.binaryInsert = binaryInsert;

function bitsToTarget(bits) {
  var len = (bits >>> 24) & 0xff;
  var hi = (bits >>> 16) & 0xff;
  var mid = (bits >>> 8) & 0xff;
  var lo = bits & 0xff;

  var res = new Array(len);
  for (var i = 0; i < len - 3; i++)
    res[i] = 0;
  res[i++] = lo;
  res[i++] = mid;
  res[i++] = hi;

  if (hi === 0)
    res.pop();
  if (hi === 0 && mid === 0)
    res.pop();

  return res;
}
utils.bitsToTarget = bitsToTarget;

function testTarget(target, hash) {
  if (typeof target === 'number')
    target = bitsToTarget(target);
  hash = utils.toArray(hash, 'hex');

  for (var i = hash.length - 1; i >= target.length; i--)
    if (hash[i] !== 0)
      return false;

  for (; i >= 0; i--) {
    if (hash[i] === target[i])
      continue;
    if (hash[i] > target[i])
      return false;
    break;
  }

  return true;
}
utils.testTarget = testTarget;

utils.isEqual = function isEqual(a, b) {
  if (a.length !== b.length)
    return false;

  for (var i = 0; i < a.length; i++)
    if (a[i] !== b[i])
      return false;

  return true;
};

utils.nextTick = function nextTick(fn) {
  if (typeof setImmediate === 'function') {
    setImmediate(fn);
    return;
  }

  if (typeof process === 'object' && process.nextTick) {
    process.nextTick(fn);
    return;
  }

  setTimeout(fn, 1);
};

function RequestCache() {
  this.map = {};
  this.count = 0;
}
utils.RequestCache = RequestCache;

RequestCache.prototype.add = function add(id, cb) {
  if (this.map[id]) {
    this.map[id].push(cb);
    return false;
  } else {
    this.map[id] = [ cb ];
    this.count++;
    return true;
  }
};

RequestCache.prototype.fullfill = function fullfill(id, err, data) {
  if (!this.map[id])
    return;

  var cbs = this.map[id];
  delete this.map[id];
  this.count--;
  cbs.forEach(function(cb) {
    cb(err, data);
  });
};

utils.asyncify = function asyncify(fn) {
  return function _asynicifedFn(err, data1, data2) {
    utils.nextTick(function() {
      fn(err, data1, data2);
    });
  };
};

utils.revHex = function revHex(s) {
  var r = '';
  for (var i = 0; i < s.length; i += 2)
    r = s.slice(i, i + 2) + r;
  return r;
};

utils.assert = function assert(val, msg) {
  if (!val)
    throw new Error(msg || 'Assertion failed');
};

utils.assert.equal = function assertEqual(l, r, msg) {
  if (l != r)
    throw new Error(msg || ('Assertion failed: ' + l + ' != ' + r));
};

utils.toBTC = function toBTC(satoshi) {
  var m = new bn(10000000).mul(new bn(10));
  var lo = satoshi.mod(m);
  if (lo.cmpn(0) !== 0) {
    lo = lo.toString(10);
    while (lo.length < 8)
      lo = '0' + lo;
    lo = '.' + lo;
  } else {
    lo = '';
  }
  return satoshi.div(m).toString(10) + lo.replace(/0+$/, '');
};

utils.isIP = function(ip) {
  if (typeof ip !== 'string')
    return 0;

  if (~ip.indexOf('.'))
    return 4;

  if (~ip.indexOf(':'))
    return 6;

  return 0;
};

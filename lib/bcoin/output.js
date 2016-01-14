/**
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;

/**
 * Output
 */

function Output(options) {
  var tx = options.tx;
  var value;

  if (!(this instanceof Output))
    return new Output(options);

  if (!tx)
    throw new Error('No TX passed into Output.');

  value = options.value;

  if (typeof value === 'number' && (value | 0) === value)
    value = new bn(value);

  this.value = utils.satoshi(value || new bn(0));
  this.script = options.script ? options.script.slice() : [];

  // For safety: do not allow usage of
  // Numbers, do not allow negative values.
  assert(typeof value !== 'number');
  assert(!this.value.isNeg())
  assert(this.value.bitLength() <= 63);
  assert(!(this.value.toArray('be', 8)[0] & 0x80));

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

Output.prototype.__defineGetter__('data', function() {
  var data;

  if (this._data)
    return this._data;

  data = Output.getData(this);

  if (this.script.length && this.value.cmpn(0) !== 0)
    utils.hidden(this, '_data', data);

  return data;
});

Output.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Output.prototype.__defineGetter__('signature', function() {
  return this.signatures[0];
});

Output.prototype.__defineGetter__('key', function() {
  return this.keys[0];
});

Output.prototype.__defineGetter__('hash', function() {
  return this.data.scripthash || this.hashes[0];
});

Output.prototype.__defineGetter__('address', function() {
  return this.data.scriptaddress || this.addresses[0] || this._id;
});

Output.prototype.__defineGetter__('signatures', function() {
  return this.data.signatures || [];
});

Output.prototype.__defineGetter__('keys', function() {
  return this.data.keys || [];
});

Output.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes || [];
});

Output.prototype.__defineGetter__('addresses', function() {
  return this.data.addresses || [];
});

Output.prototype.__defineGetter__('scriptaddress', function() {
  return this.data.scriptaddress;
});

Output.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Output.prototype.__defineGetter__('n', function() {
  return this.data.n || this.m;
});

Output.prototype.__defineGetter__('lock', function() {
  var lock = bcoin.script.lockTime(this.script);
  if (!lock)
    return 0;
  return lock.toNumber();
});

Output.prototype.__defineGetter__('text', function() {
  return this.data.text;
});

Output.prototype.__defineGetter__('_id', function() {
  var data = [].concat(
    this.value.toArray(),
    bcoin.script.encode(this.script)
  );
  var hash = utils.toHex(utils.dsha256(data));
  return '[' + this.type + ':' + hash.slice(0, 7) + ']';
});

Output.prototype.__defineGetter__('addr', function() {
  return this.address;
});

Output.prototype.__defineGetter__('addrs', function() {
  return this.addresses;
});

Output.prototype.__defineGetter__('pub', function() {
  return this.key;
});

Output.prototype.__defineGetter__('pubs', function() {
  return this.keys;
});

Output.prototype.__defineGetter__('sig', function() {
  return this.signature;
});

Output.prototype.__defineGetter__('sigs', function() {
  return this.signatures;
});

Output.prototype.__defineGetter__('scriptaddr', function() {
  return this.scriptaddress;
});

// Schema and defaults for data object:
// {
//   type: null,
//   subtype: null,
//   side: 'output',
//   signatures: [],
//   keys: [],
//   hashes: [],
//   addresses: [],
//   redeem: null,
//   scripthash: null,
//   scriptaddress: null,
//   m: 0,
//   n: 0,
//   height: -1,
//   flags: null,
//   text: null,
//   lock: lock ? lock.toNumber() : 0,
//   value: output.value,
//   script: s,
//   seq: null,
//   prev: null,
//   index: null,
//   _script: null,
//   none: false
// }

Output.getData = function getData(output) {
  var s, sub, lock, def, key, hash, address, keys, data;

  if (Array.isArray(output)) {
    output = {
      script: output,
      value: new bn(0)
    };
  }

  if (!output || !output.script)
    return;

  s = output.script;
  sub = bcoin.script.subscript(output.script);
  lock = bcoin.script.lockTime(s);

  def = {
    side: 'output',
    value: output.value,
    script: s
  };

  if (lock) {
    sub = sub.slice(3);
    def.lock = lock.toNumber();
  }

  if (bcoin.script.isPubkey(s)) {
    key = sub[0];
    hash = utils.ripesha(key);
    address = bcoin.wallet.hash2addr(hash);
    return utils.merge(def, {
      type: 'pubkey',
      keys: [key],
      hashes: [hash],
      addresses: [address]
    });
  }

  if (bcoin.script.isPubkeyhash(s)) {
    hash = sub[2];
    address = bcoin.wallet.hash2addr(hash);
    return utils.merge(def, {
      type: 'pubkeyhash',
      hashes: [hash],
      addresses: [address]
    });
  }

  if (bcoin.script.isMultisig(s)) {
    keys = sub.slice(1, -2);
    hash = keys.map(function(key) {
      return utils.ripesha(key);
    });
    address = hash.map(function(hash) {
      return bcoin.wallet.hash2addr(hash);
    });
    return utils.merge(def, {
      type: 'multisig',
      keys: keys,
      hashes: hash,
      addresses: address,
      m: new bn(sub[0]).toNumber(),
      n: new bn(sub[sub.length - 2]).toNumber()
    });
  }

  if (bcoin.script.isScripthash(s)) {
    hash = sub[1];
    address = bcoin.wallet.hash2addr(hash, 'scripthash');
    return utils.merge(def, {
      type: 'scripthash',
      scripthash: hash,
      scriptaddress: address
    });
  }

  if (bcoin.script.isNulldata(s)) {
    data = bcoin.script.nulldata(s);
    return utils.merge(def, {
      type: 'nulldata',
      flags: data,
      text: utils.array2utf8(data),
      none: true
    });
  }

  return utils.merge(def, {
    type: 'unknown',
    none: true
  });
};

Output.prototype.inspect = function inspect() {
  return {
    type: this.type,
    address: this.address,
    keys: this.keys.map(utils.toHex),
    hashes: this.hashes.map(utils.toHex),
    addresses: this.addresses,
    m: this.m,
    n: this.n,
    text: this.text,
    lock: this.lock,
    value: utils.btc(this.value),
    script: bcoin.script.format(this.script)[0]
  };
};

/**
 * Expose
 */

module.exports = Output;

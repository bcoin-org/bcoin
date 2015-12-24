/**
 * output.js - output object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

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

Output.prototype.__defineGetter__('sig', function() {
  return this.data.sigs[0];
});

Output.prototype.__defineGetter__('pub', function() {
  return this.data.pubs[0];
});

Output.prototype.__defineGetter__('hash', function() {
  return this.data.hashes[0];
});

Output.prototype.__defineGetter__('addr', function() {
  return this.data.scriptaddr
    || this.data.addrs[0]
    || this._id(this.type);
});

Output.prototype.__defineGetter__('sigs', function() {
  return this.data.sigs;
});

Output.prototype.__defineGetter__('pubs', function() {
  return this.data.pubs;
});

Output.prototype.__defineGetter__('hashes', function() {
  return this.data.hashes;
});

Output.prototype.__defineGetter__('addrs', function() {
  return this.data.addrs;
});

Output.prototype.__defineGetter__('m', function() {
  return this.data.m || 1;
});

Output.prototype.__defineGetter__('n', function() {
  return this.data.n || this.data.m || 1;
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

Output.prototype._id = function _id(prefix) {
  var data = [].concat(
    this.value.toArray(),
    bcoin.script.encode(this.script)
  );
  var hash = utils.toHex(utils.dsha256(data));
  return '[' + prefix + ':' + hash.slice(0, 7) + ']';
};

Output.getData = function getData(output) {
  if (!output || !output.script)
    return;

  var s = output.script;
  var sub = bcoin.script.subscript(output.script);
  var lock = bcoin.script.lockTime(s);
  var schema, pub, hash, addr, pubs, ret;

  schema = {
    type: null,
    side: 'output',
    sigs: [],
    pubs: [],
    hashes: [],
    addrs: [],
    redeem: null,
    scripthash: null,
    scriptaddr: null,
    m: 0,
    n: 0,
    height: -1,
    flags: null,
    text: null,
    lock: lock ? lock.toNumber() : 0,
    value: new bn(0),
    script: s,
    seq: null,
    tx: null,
    index: null,
    _script: null,
    none: false
  };

  if (lock)
    sub = sub.slice(3);

  if (bcoin.script.isPubkey(s)) {
    pub = sub[0];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'pubkey',
      pubs: [pub],
      hashes: [hash],
      addrs: [addr],
      value: output.value
    });
  }

  if (bcoin.script.isPubkeyhash(s)) {
    hash = sub[2];
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'pubkeyhash',
      side: 'output',
      hashes: [hash],
      addrs: [addr],
      value: output.value
    });
  }

  pubs = bcoin.script.isMultisig(s);
  if (pubs) {
    hash = pubs.map(function(key) {
      return utils.ripesha(key);
    });
    addr = hash.map(function(hash) {
      return bcoin.wallet.hash2addr(hash);
    });
    return utils.merge(schema, {
      type: 'multisig',
      pubs: pubs,
      hashes: hash,
      addrs: addr,
      m: new bn(sub[0]).toNumber(),
      n: new bn(sub[sub.length - 2]).toNumber(),
      value: output.value
    });
  }

  if (bcoin.script.isScripthash(s)) {
    hash = utils.toHex(sub[1]);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    return utils.merge(schema, {
      type: 'scripthash',
      side: 'output',
      scripthash: hash,
      scriptaddr: addr,
      value: output.value
    });
  }

  if (bcoin.script.isColored(s)) {
    ret = bcoin.script.colored(s);
    return utils.merge(schema, {
      type: 'colored',
      flags: ret,
      text: utils.array2utf8(ret),
      value: output.value,
      none: true
    });
  }

  return utils.merge(schema, {
    type: 'unknown',
    none: true
  });
};

Output.prototype.inspect = function inspect() {
  return {
    type: this.type,
    addr: this.addr,
    pubs: this.pubs.map(utils.toHex),
    hashes: this.hashes.map(utils.toHex),
    addrs: this.addrs,
    redeem: this.type === 'scripthash'
      ? bcoin.script.format(this.data.redeem)[0]
      : null,
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

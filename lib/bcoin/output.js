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

Output.prototype.__defineGetter__('addr', function() {
  return this.data.addr;
});

Output.prototype.__defineGetter__('type', function() {
  return this.data.type;
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
    coinbase: null,
    height: -1,
    sig: null,
    pub: null,
    hash: null,
    addr: null,
    multisig: null,
    redeem: null,
    flags: null,
    text: null,
    value: new bn(0),
    lock: lock ? lock.toNumber() : 0,
    script: s,
    seq: null,
    tx: null,
    txid: null,
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
      pub: pub,
      hash: hash,
      addr: addr,
      value: output.value
    });
  }

  if (bcoin.script.isPubkeyhash(s)) {
    hash = sub[2];
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'pubkeyhash',
      side: 'output',
      hash: hash,
      addr: addr,
      value: output.value
    });
  }

  pubs = bcoin.script.isMultisig(s);
  if (pubs) {
    hash = utils.ripesha(pubs[0]);
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'multisig',
      pub: pubs[0],
      hash: hash,
      addr: addr,
      multisig: {
        m: new bn(sub[0]).toNumber(),
        n: new bn(sub[sub.length - 2]).toNumber(),
        sigs: null,
        pubs: pubs,
        hashes: pubs.map(function(key) {
          return utils.ripesha(key);
        }),
        addrs: pubs.map(function(key) {
          var hash = utils.ripesha(key);
          return bcoin.wallet.hash2addr(hash);
        })
      },
      value: output.value
    });
  }

  if (bcoin.script.isScripthash(s)) {
    hash = utils.toHex(sub[1]);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    return utils.merge(schema, {
      type: 'scripthash',
      side: 'output',
      hash: hash,
      addr: addr,
      multisig: {
        m: null,
        n: null,
        sigs: null,
        pubs: null,
        hashes: null,
        addrs: null
      },
      value: output.value
    });
  }

  if (bcoin.script.isColored(s)) {
    ret = bcoin.script.colored(s);
    return utils.merge(schema, {
      type: 'colored',
      addr: output._id('colored'),
      flags: ret,
      text: utils.array2utf8(ret),
      value: output.value,
      none: true
    });
  }

  return utils.merge(schema, {
    type: 'unknown',
    addr: output._id('unknown'),
    none: true
  });
};

Output.prototype.inspect = function inspect() {
  var multisig = this.data.multisig || null;
  var redeem = this.type === 'scripthash'
    ? bcoin.script.format(this.data.redeem)[0]
    : null;

  if (multisig) {
    multisig = {
      m: multisig.m,
      n: multisig.n,
      sigs: (multisig.sigs || []).map(utils.toHex),
      pubs: (multisig.pubs || []).map(utils.toHex),
      hashes: multisig.hashes || [],
      addrs: multisig.addrs || []
    };
  }

  return {
    type: this.type,
    addr: this.addr,
    text: this.text,
    lock: this.lock,
    script: bcoin.script.format(this.script)[0],
    value: utils.btc(this.value),
    multisig: multisig,
    redeem: redeem
  };
};

/**
 * Expose
 */

module.exports = Output;

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
    throw new Error('No TX passed into Input.');

  value = options.value;

  if (typeof value === 'number' && (value | 0) === value)
    value = new bn(value);

  this.value = utils.satoshi(value || new bn(0));
  this.script = options.script ? options.script.slice() : [];

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);
}

Output.prototype.__defineGetter__('data', function() {
  return Output.getData(this);
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
    return;
  return lock.toNumber();
});

Output.getData = function getData(output) {
  if (!output || !output.script) return;

  var s = output.script;
  var lock = bcoin.script.lockTime(s);
  var pub, hash, addr, pubs, ret;

  if (bcoin.script.isPubkey(s)) {
    pub = s[0];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash);
    return {
      type: 'pubkey',
      sig: null,
      pub: pub,
      hash: hash,
      addr: addr,
      value: output.value,
      script: s,
      lock: lock
    };
  }

  if (bcoin.script.isPubkeyhash(s)) {
    hash = s[2];
    addr = bcoin.wallet.hash2addr(hash);
    return {
      type: 'pubkeyhash',
      sig: null,
      pub: null,
      hash: hash,
      addr: addr,
      value: output.value,
      script: s,
      lock: lock
    };
  }

  pubs = bcoin.script.isMultisig(s);
  if (pubs) {
    hash = utils.ripesha(pubs[0]);
    addr = bcoin.wallet.hash2addr(hash);
    return {
      type: 'multisig',
      sig: null,
      pub: pubs[0],
      hash: hash,
      addr: addr,
      keys: pubs,
      multisig: {
        m: new bn(s[0]).toNumber(),
        n: new bn(s[s.length - 2]).toNumber(),
        keys: pubs,
        hashes: pubs.map(function(key) {
          return utils.ripesha(key);
        }),
        addrs: pubs.map(function(key) {
          var hash = utils.ripesha(key);
          return bcoin.wallet.hash2addr(hash);
        })
      },
      value: output.value,
      script: s,
      lock: lock
    };
  }

  if (bcoin.script.isScripthash(s)) {
    hash = utils.toHex(s[1]);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    return {
      type: 'scripthash',
      sig: null,
      pub: null,
      hash: hash,
      addr: addr,
      scripthash: {
        redeem: null,
        pub: null,
        hash: hash,
        addr: addr
      },
      value: output.value,
      script: s,
      lock: lock
    };
  }

  if (bcoin.script.isColored(s)) {
    ret = bcoin.script.colored(s);
    return {
      type: 'colored',
      addr: '[colored]',
      hash: '[colored]',
      data: ret,
      text: utils.array2ascii(ret),
      value: output.value,
      script: s,
      lock: lock,
      none: true
    };
  }

  return {
    type: 'unknown',
    addr: '[unknown]',
    hash: '[unknown]',
    value: new bn(0),
    script: s,
    lock: lock,
    none: true
  };
};

/**
 * Expose
 */

module.exports = Output;

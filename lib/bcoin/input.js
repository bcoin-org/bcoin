/**
 * input.js - input object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bn = require('bn.js');
var bcoin = require('../bcoin');
var utils = bcoin.utils;

/**
 * Input
 */

function Input(options) {
  var tx = options.tx;
  var lock;

  if (!(this instanceof Input))
    return new Input(options);

  if (!tx)
    throw new Error('No TX passed into Input.');

  this.out = {
    tx: options.out.tx || null,
    hash: options.out.hash || null,
    index: options.out.index
  };

  this.script = options.script ? options.script.slice() : [];
  this.seq = options.seq === undefined ? 0xffffffff : options.seq;

  if (options.script && options.script._raw)
    utils.hidden(this.script, '_raw', options.script._raw);

  if (this.output) {
    lock = this.lock;
    if (lock >= 0) {
      if (tx._lock === 0)
        tx.lock = Math.max(lock, tx.lock);
      if (!bcoin.script.spendable(this.output.script, tx.lock))
        throw new Error('Cannot spend ' + utils.revHex(this.out.hash));
    }
  }

  if (tx.lock !== 0) {
    if (options.seq === undefined)
      this.seq = 0;
  }
}

Input.prototype.__defineGetter__('data', function() {
  return Input.getData(this);
});

Input.prototype.__defineGetter__('addr', function() {
  return this.data.addr;
});

Input.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Input.prototype.__defineGetter__('lock', function() {
  if (!this.output)
    return;
  return this.output.lock;
});

Input.prototype.__defineGetter__('output', function() {
  if (!this.out.tx)
    return;
  return this.out.tx.outputs[this.out.index];
});

Input.prototype.__defineGetter__('value', function() {
  if (!this.output)
    return new bn(0);
  return this.output.value;
});

Input.prototype.__defineGetter__('tx', function() {
  return this.out.tx;
});

Input.getData = function getData(input) {
  if (!input || !input.script)
    return;

  var s = input.script;
  var sig, pub, hash, addr, redeem, data, output;

  if (!input.out) {
    return {
      type: 'unknown',
      addr: '[unknown]',
      hash: '[unknown]',
      value: new bn(0),
      script: s,
      seq: input.seq,
      none: true
    };
  }

  if (+input.out.hash === 0) {
    return {
      type: 'coinbase',
      addr: '[coinbase]',
      hash: '[coinbase]',
      value: new bn(0),
      script: s,
      seq: input.seq,
      none: true
    };
  }

  if (input.out.tx) {
    output = input.out.tx.outputs[input.out.index];
    return bcoin.output.getData(output);
  }

  if (bcoin.script.isPubkeyhashInput(s)) {
    sig = utils.toHex(s[0]);
    pub = s[1];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash);
    return {
      type: 'pubkeyhash',
      sig: sig,
      pub: pub,
      hash: hash,
      addr: addr,
      value: new bn(0),
      script: s,
      seq: input.seq
    };
  }

  if (bcoin.script.isScripthashInput(s)) {
    pub = s[s.length - 1];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    redeem = bcoin.script.decode(pub);
    data = bcoin.output.getData({
      script: redeem,
      value: new bn(0)
    });
    data.type = 'scripthash';
    data.pub = pub;
    data.hash = hash;
    data.addr = addr;
    data.scripthash = {
      redeem: redeem,
      pub: pub,
      hash: hash,
      addr: addr,
      m: data.multisig.m,
      n: data.multisig.n,
      keys: data.multisig.keys,
      hashes: data.multisig.hashes,
      addrs: data.multisig.addrs,
      script: redeem
    };
    data.script = s;
    data.seq = input.seq;
    return data;
  }

  return {
    type: 'unknown',
    addr: '[unknown]',
    hash: '[unknown]',
    value: new bn(0),
    script: s,
    seq: input.seq,
    none: true
  };
};

/**
 * Expose
 */

module.exports = Input;

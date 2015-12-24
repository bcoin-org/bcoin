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
    if (lock > 0) {
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
  var data;

  if (this._data)
    return this._data;

  data = Input.getData(this);

  if (this.script.length && this.out.tx)
    utils.hidden(this, '_data', data);

  return data;
});

Input.prototype.__defineGetter__('addr', function() {
  return this.data.addr;
});

Input.prototype.__defineGetter__('type', function() {
  return this.data.type;
});

Input.prototype.__defineGetter__('lock', function() {
  if (!this.output)
    return 0;
  return this.output.lock;
});

Input.prototype.__defineGetter__('text', function() {
  return this.data.text;
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
  var sub = bcoin.script.subscript(input.script);
  var schema, sig, pub, hash, addr, redeem, data, output;

  schema = {
    type: null,
    side: 'input',
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
    lock: 0,
    script: s,
    seq: input.seq,
    tx: null,
    txid: null,
    index: null,
    _script: null,
    none: false
  };

  if (bcoin.script.lockTime(sub))
    sub = sub.slice(3);

  if (!input.out) {
    return utils.merge(schema, {
      type: 'unknown',
      addr: '[unknown]',
      none: true
    });
  }

  if (+input.out.hash === 0) {
    data = bcoin.script.coinbase(input.script);
    return utils.merge(schema, {
      type: 'coinbase',
      coinbase: data,
      height: data.height || -1,
      addr: '[coinbase]',
      flags: data.flags,
      text: data.text.join(''),
      none: true
    });
  }

  if (input.out.tx) {
    output = input.out.tx.outputs[input.out.index];
    data = bcoin.output.getData(output);
    if (data.type === 'pubkey' || data.type === 'pubkeyhash') {
      data.sig = sub[0];
    } else if (data.type === 'multisig') {
      data.multisig.sigs = sub.slice(1);
      data.sig = data.multisig.sigs[0];
    } else if (data.type === 'scripthash') {
      data.multisig.sigs = sub.slice(1, -1);
      data.sig = data.multisig.sigs[0];
    }
    return utils.merge(data, {
      seq: input.seq,
      // tx: input.out.tx,
      txid: input.out.hash,
      index: input.out.index,
      _script: s
    });
  }

  if (bcoin.script.isPubkeyInput(s)) {
    return utils.merge(schema, {
      type: 'pubkey',
      sig: sub[0],
      addr: '[unknown]',
      none: true
    });
  }

  if (bcoin.script.isPubkeyhashInput(s)) {
    pub = sub[1];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash);
    return utils.merge(schema, {
      type: 'pubkeyhash',
      sig: sub[0],
      pub: pub,
      hash: hash,
      addr: addr
    });
  }

  if (bcoin.script.isScripthashInput(s)) {
    sig = sub.slice(1, -1);
    pub = sub[sub.length - 1];
    hash = utils.ripesha(pub);
    addr = bcoin.wallet.hash2addr(hash, 'scripthash');
    redeem = bcoin.script.decode(pub);
    data = bcoin.output.getData({
      script: redeem,
      value: new bn(0)
    });
    data.multisig.sig = sig;
    return utils.merge(data, {
      type: 'scripthash',
      side: 'input',
      sig: sig[0],
      hash: hash,
      addr: addr,
      redeem: redeem,
      script: s,
      seq: input.seq
    });
  }

  if (bcoin.script.isMultisigInput(s)) {
    sig = sub.slice(1);
    return utils.merge(schema, {
      type: 'multisig',
      sig: sub[0],
      addr: '[unknown]',
      multisig: {
        m: sig.length,
        n: null,
        sigs: sig,
        pubs: null,
        hashes: null,
        addrs: null
      },
      none: true
    });
  }

  return utils.merge(schema, {
    type: 'unknown',
    addr: '[unknown]',
    none: true
  });
};

Input.prototype.inspect = function inspect() {
  var output = this.output
    ? this.output.inspect()
    : { type: 'unknown', value: '0.0' };

  output.hash = this.out.hash;
  output.rhash = utils.revHex(this.out.hash);
  output.index = this.out.index;

  return {
    type: this.type,
    addr: this.addr,
    text: this.text,
    lock: this.lock,
    script: bcoin.script.format(this.script)[0],
    value: utils.btc(output.value),
    seq: this.seq,
    output: output
  };
};

/**
 * Expose
 */

module.exports = Input;

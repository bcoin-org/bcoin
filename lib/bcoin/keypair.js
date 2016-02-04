/**
 * keypair.js - keypair object for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var bn = require('bn.js');
var utils = bcoin.utils;
var assert = utils.assert;
var constants = bcoin.protocol.constants;
var network = bcoin.protocol.network;

/**
 * KeyPair
 */

function KeyPair(options) {
  if (!(this instanceof KeyPair))
    return new KeyPair(options);

  if (!options)
    options = {};

  if (options instanceof KeyPair)
    return options;

  if (options.key instanceof KeyPair)
    return options.key;

  this.options = options;
  this._key = options.key || null;
  this.hd = options.hd || null;
  this.compressed = options.compressed !== false;

  if (options.privateKey)
    options.priv = options.privateKey;

  if (options.publicKey)
    options.pub = options.publicKey;

  if (options.priv instanceof bcoin.hd.priv) {
    this.hd = options.priv;
    this._key = options.priv.pair;
  } else if (options.pub instanceof bcoin.hd.pub) {
    this.hd = options.pub;
    this._key = options.pub.pair;
  } else if (options.hd) {
    this.hd = typeof options.hd === 'object'
      ? bcoin.hd.priv(options.hd)
      : bcoin.hd.priv();
    this._key = this.hd.pair;
  } else if (options.key) {
    if ((options.key instanceof bcoin.hd.priv)
        || (options.key instanceof bcoin.hd.pub)) {
      this.hd = options.key;
      this._key = options.key.pair;
    } else {
      this._key = options.key;
    }
  } else if (options.priv || options.pub) {
    this._key = bcoin.ecdsa.keyPair({
      priv: options.priv,
      pub: options.pub
    });
  } else {
    this._key = bcoin.ecdsa.genKeyPair({
      pers: options.personalization,
      entropy: options.entropy
        || (options.passphrase ? utils.sha256(options.passphrase) : null)
    });
  }
}

KeyPair.prototype.__defineGetter__('priv', function() {
  return this._key.getPrivate();
});

KeyPair.prototype.__defineGetter__('pub', function() {
  return this._key.getPublic();
});

KeyPair.prototype.getPrivate = function getPrivate(enc) {
  var priv = this._key.getPrivate();

  if (!priv)
    return;

  priv = priv.toArray();

  if (enc === 'base58')
    return KeyPair.toSecret(priv, this.compressed);

  if (enc === 'hex')
    return utils.toHex(priv);

  return priv;
};

KeyPair.prototype.getPublic = function getPublic(enc) {
  var pub = this._key.getPublic(this.compressed, 'array');

  if (enc === 'base58')
    return utils.toBase58(pub);

  if (enc === 'hex')
    return utils.toHex(pub);

  return pub;
};

KeyPair.prototype.toSecret = function toSecret() {
  return KeyPair.toSecret(this.getPrivate(), this.compressed);
};

KeyPair.toSecret = function toSecret(priv, compressed) {
  var arr, chk;

  // We'll be using ncompressed public key as an address
  arr = [network.prefixes.privkey];

  // 0-pad key
  while (arr.length + priv.length < 33)
    arr.push(0);

  arr = arr.concat(priv);

  if (compressed)
    arr.push(1);

  chk = utils.checksum(arr);

  return utils.toBase58(arr.concat(chk));
};

KeyPair.fromSecret = function fromSecret(priv) {
  var key, compressed;

  key = utils.fromBase58(priv);
  assert(utils.isEqual(key.slice(-4), utils.checksum(key.slice(0, -4))));
  assert.equal(key[0], network.prefixes.privkey);

  key = key.slice(0, -4);
  if (key.length === 34) {
    assert.equal(key[33], 1);
    priv = key.slice(1, -1);
    compressed = true;
  } else {
    priv = key.slice(1);
    compressed = false;
  }

  return new KeyPair({
    priv: priv,
    compressed: compressed
  });
};

KeyPair.prototype.toJSON = function toJSON(encrypt) {
  var json = {
    v: 1,
    name: 'keypair',
    encrypted: encrypt ? true : false
  };

  if (this.hd) {
    if (this.hd.xprivkey) {
      if (this.hd.seed) {
        json.mnemonic = encrypt
          ? encrypt(this.hd.seed.mnemonic)
          : this.hd.seed.mnemonic;
        json.passphrase = encrypt
          ? encrypt(this.hd.seed.passphrase)
          : this.hd.seed.passphrase;
        return json;
      }
      json.xpriv = encrypt
        ? encrypt(this.hd.xprivkey)
        : this.hd.xprivkey;
      return json;
    }

    json.xpub = this.hd.xpubkey;

    return json;
  }

  if (this._key.priv) {
    json.priv = encrypt
      ? encrypt(this.getPrivate('base58'))
      : this.getPrivate('base58');
    return json;
  }

  json.pub = this.getPublic('hex');
  return json;
};

KeyPair.fromJSON = function fromJSON(json, decrypt) {
  var key, priv, pub, compressed, xprivkey;
  var path = {};

  assert.equal(json.v, 1);
  assert.equal(json.name, 'keypair');

  if (json.encrypted && !decrypt)
    throw new Error('Cannot decrypt address');

  if (json.mnemonic) {
    return new KeyPair({
      key: bcoin.hd.priv({
        seed: bcoin.hd.seed({
          mnemonic: json.encrypted
            ? decrypt(json.mnemonic)
            : json.mnemonic,
          passphrase: json.encrypted
            ? decrypt(json.passphrase)
            : json.passphrase
        })
      })
    });
  }

  if (json.xpriv) {
    xprivkey = json.xpriv;
    if (json.encrypted)
      xprivkey = decrypt(xprivkey);
    return new KeyPair({
      key: bcoin.hd.priv({
        xkey: xprivkey
      })
    });
  }

  if (json.xpub) {
    return new KeyPair({
      key: bcoin.hd.pub({
        xkey: json.xpub
      })
    });
  }

  if (json.priv) {
    priv = json.priv;
    if (json.encrypted)
      priv = decrypt(priv);

    key = KeyPair.fromSecret(json.priv);
    priv = key.priv;
    compressed = key.compressed;
    return new KeyPair({
      priv: priv,
      compressed: compressed
    });
  }

  if (json.pub) {
    pub = bcoin.utils.toArray(json.pub, 'hex');
    compressed = pub[0] !== 0x04;
    return new KeyPair({
      pub: pub,
      compressed: compressed
    });
  }

  assert(false);
};

/**
 * Expose
 */

module.exports = KeyPair;

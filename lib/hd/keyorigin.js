'use strict';

const assert = require('assert');
const common = require('./common');
const bio = require('bufio');
const hash160 = require('bcrypto/lib/hash160');
const WalletKey = require('../wallet/walletkey');

/**
 * Helper class to represent hd key path for arbitrary wallets.
 * @property {Number} fingerPrint - master key fingerprint (uint32)
 * @property {Array} path - bip32 derivation path in uint32 array
 */
class KeyOriginInfo {
  constructor(options) {
    this.fingerPrint = -1;
    this.path = [];
    if (options) {
      this.fromOptions(options);
    }
  }

  fromOptions(options) {
    assert(options, 'requires options');
    if (options.fingerPrint) {
      assert(
        (options.fingerPrint >>> 0) === options.fingerPrint,
        'fingerPrint must be uint32'
      );
      this.fingerPrint = options.fingerPrint;
    }
    if (options.path) {
      if (Array.isArray(options.path)) {
        assert(
          options.path.every(p => (p >>> 0) === p),
          'all path index must be uint32'
        );
        this.path = options.path;
      } else {
        this.path = common.parsePath(options.path, true);
      }
    }
    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  equals(keyInfo) {
    assert(KeyOriginInfo.isKeyOriginInfo(keyInfo));
    if (this.fingerPrint !== keyInfo.fingerPrint)
      return false;
    for (const i in this.path) {
      if (this.path[i] !== keyInfo.path[i])
        return false;
    }
    return true;
  }

  inspect() {
    return this.format();
  }

  format() {
    let path = 'm';
    for (const p of this.path) {
      const hardened = (p & common.HARDENED) ? '\'' : '';
      path += `/${p & 0x7fffffff}${hardened}`;
    }
    return {
      fingerPrint: this.fingerPrint,
      path
    };
  }

  static fromRaw(data) {
    return new this().fromRaw(data);
  }

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  };

  static fromReader(br) {
    return new this().fromReader(br);
  }

  fromReader(br) {
    this.fingerPrint = br.readU32BE();
    while (br.left()) {
      this.path.push(br.readU32());
    }
    return this;
  }

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  toWriter(bw) {
    bw.writeU32BE(this.fingerPrint);
    for (const p of this.path) {
      bw.writeU32(p);
    }
    return bw;
  }

  toJSON() {
    return {
      fingerPrint: this.fingerPrint,
      path: this.path
    };
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  fromJSON(json) {
    if (json.fingerPrint) {
      assert((json.fingerPrint >>> 0) === json.fingerPrint);
      this.fingerPrint = json.fingerPrint;
    }

    if (json.path) {
      if (Array.isArray(json.path) && json.path.length > 0) {
        for (const p of json.path) {
          assert((p >>> 0) === p);
          this.path.push(p);
        }
      } else {
        this.path = common.parsePath(json.path, true);
      }
    }

    return this;
  }

  static isKeyOriginInfo(obj) {
    return obj instanceof KeyOriginInfo;
  }

  clone() {
    const path = this.path.slice();
    return new KeyOriginInfo({fingerPrint: this.fingerPrint, path});
  }

  clear() {
    this.fingerPrint = -1;
    this.path = [];
  }

  getSize() {
    return 4 + this.path.length * 4;
  }

  static fromWalletKey(wk) {
    return new this().fromWalletKey(wk);
  }

  fromWalletKey(wk) {
    assert(WalletKey.isWalletKey(wk));
    const fp = hash160.digest(wk.publicKey);
    this.fingerPrint = fp.readUInt32BE(0, true);
    this.path.push(wk.account | common.HARDENED);
    this.path.push(wk.branch);
    this.path.push(wk.index);
    return this;
  }
}

module.exports = KeyOriginInfo;

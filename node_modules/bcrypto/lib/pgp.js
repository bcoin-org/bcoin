/*!
 * pgp.js - PGP for javascript
 * Copyright (c) 2018-2019, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcrypto
 *
 * Parts of this software are based on golang/crypto:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/crypto
 *
 * Resources:
 *   https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP
 *   https://tools.ietf.org/html/rfc4880
 *   https://github.com/golang/crypto/tree/master/openpgp
 *   https://github.com/gpg/gnupg/blob/master/common/openpgpdefs.h
 *   https://github.com/gpg/gnupg/blob/master/g10/parse-packet.c
 */

'use strict';

const assert = require('./internal/assert');
const bio = require('bufio');
const {PEMBlock} = require('./encoding/pem');
const {countLeft} = require('./encoding/util');
const cipher = require('./cipher');
const MD5 = require('./md5');
const SHA1 = require('./sha1');
const RIPEMD160 = require('./ripemd160');
const SHA224 = require('./sha224');
const SHA256 = require('./sha256');
const SHA384 = require('./sha384');
const SHA512 = require('./sha512');
const pgpdf = require('./internal/pgpdf');

/*
 * Constants
 */

const packetTypes = {
  NONE: 0,
  PUBKEY_ENC: 1,
  SIGNATURE: 2,
  SYMKEY_ENC: 3,
  ONEPASS_SIG: 4,
  PRIVATE_KEY: 5,
  PUBLIC_KEY: 6,
  PRIVATE_SUBKEY: 7,
  COMPRESSED: 8,
  ENCRYPTED: 9,
  MARKER: 10,
  PLAINTEXT: 11,
  RING_TRUST: 12,
  USER_ID: 13,
  PUBLIC_SUBKEY: 14,
  OLD_COMMENT: 16,
  ATTRIBUTE: 17,
  ENCRYPTED_MDC: 18,
  MDC: 19,
  ENCRYPTED_AEAD: 20
};

const packetTypesByVal = {
  0: 'NONE',
  1: 'PUBKEY_ENC',
  2: 'SIGNATURE',
  3: 'SYMKEY_ENC',
  4: 'ONEPASS_SIG',
  5: 'PRIVATE_KEY',
  6: 'PUBLIC_KEY',
  7: 'PRIVATE_SUBKEY',
  8: 'COMPRESSED',
  9: 'ENCRYPTED',
  10: 'MARKER',
  11: 'PLAINTEXT',
  12: 'RING_TRUST',
  13: 'USER_ID',
  14: 'PUBLIC_SUBKEY',
  16: 'OLD_COMMENT',
  17: 'ATTRIBUTE',
  18: 'ENCRYPTED_MDC',
  19: 'MDC',
  20: 'ENCRYPTED_AEAD'
};

const sigTypes = {
  BINARY: 0x00,
  TEXT: 0x01,
  GENERIC_CERT: 0x10,
  PERSONA_CERT: 0x11,
  CASUAL_CERT: 0x12,
  POSITIVE_CERT: 0x13,
  SUBKEY_BINDING: 0x18,
  PRIMARY_KEY_BINDING: 0x19,
  DIRECT_SIGNATURE: 0x1f,
  KEY_REVOCATION: 0x20,
  SUBKEY_REVOCATION: 0x28
};

const sigTypesByVal = {
  0x00: 'BINARY',
  0x01: 'TEXT',
  0x10: 'GENERIC_CERT',
  0x11: 'PERSONA_CERT',
  0x12: 'CASUAL_CERT',
  0x13: 'POSITIVE_CERT',
  0x18: 'SUBKEY_BINDING',
  0x19: 'PRIMARY_KEY_BINDING',
  0x1f: 'DIRECT_SIGNATURE',
  0x20: 'KEY_REVOCATION',
  0x28: 'SUBKEY_REVOCATION'
};

const keyTypes = {
  RSA: 1,
  RSA_ENCRYPT_ONLY: 2,
  RSA_SIGN_ONLY: 3,
  ELGAMAL: 16,
  DSA: 17,
  ECDH: 18,
  ECDSA: 19,
  ELGAMAL_LEGACY: 20,
  EDDSA: 22
};

const keyTypesByVal = {
  1: 'RSA',
  2: 'RSA_ENCRYPT_ONLY',
  3: 'RSA_SIGN_ONLY',
  16: 'ELGAMAL',
  17: 'DSA',
  18: 'ECDH',
  19: 'ECDSA',
  20: 'ELGAMAL_LEGACY',
  22: 'EDDSA'
};

const cipherTypes = {
  NONE: 0,
  IDEA: 1,
  DES3: 2,
  CAST5: 3,
  BLOWFISH: 4,
  AES128: 7,
  AES192: 8,
  AES256: 9,
  TWOFISH: 10,
  CAMELLIA128: 11,
  CAMELLIA192: 12,
  CAMELLIA256: 13
};

const cipherTypesByVal = {
  0: 'NONE',
  1: 'IDEA',
  2: 'DES3',
  3: 'CAST5',
  4: 'BLOWFISH',
  7: 'AES128',
  8: 'AES192',
  9: 'AES256',
  10: 'TWOFISH',
  11: 'CAMELLIA128',
  12: 'CAMELLIA192',
  13: 'CAMELLIA256'
};

const hashTypes = {
  MD5: 1,
  SHA1: 2,
  RIPEMD160: 3,
  SHA256: 8,
  SHA384: 9,
  SHA512: 10,
  SHA224: 11
};

const hashTypesByVal = {
  1: 'MD5',
  2: 'SHA1',
  3: 'RIPEMD160',
  8: 'SHA256',
  9: 'SHA384',
  10: 'SHA512',
  11: 'SHA224'
};

const hashToHash = {
  1: MD5,
  2: SHA1,
  3: RIPEMD160,
  8: SHA256,
  9: SHA384,
  10: SHA512,
  11: SHA224
};

const compressTypes = {
  NONE: 0,
  ZIP: 1,
  ZLIB: 2,
  BZIP2: 3
};

const compressTypesByVal = {
  0: 'NONE',
  1: 'ZIP',
  2: 'ZLIB',
  3: 'BZIP2'
};

const curveTypes = {
  NONE: 0,
  P256: 1,
  P384: 2,
  P521: 3,
  SECP256K1: 4,
  X25519: 5,
  BRAINPOOLP256: 6,
  BRAINPOOLP384: 7,
  BRAINPOOLP512: 8,
  ED25519: 9
};

const curveTypesByVal = {
  0: 'NONE',
  1: 'P256',
  2: 'P384',
  3: 'P521',
  4: 'SECP256K1',
  5: 'X25519',
  6: 'BRAINPOOLP256',
  7: 'BRAINPOOLP384',
  8: 'BRAINPOOLP512',
  9: 'ED25519'
};

const oids = {
  P256: Buffer.from('2a8648ce3d030107', 'hex'),
  P384: Buffer.from('2b81040022', 'hex'),
  P521: Buffer.from('2b81040023', 'hex'),
  SECP256K1: Buffer.from('2b8104000a', 'hex'),
  X25519: Buffer.from('2b060104019755010501', 'hex'),
  BRAINPOOLP256: Buffer.from('2b2403030208010107', 'hex'),
  BRAINPOOLP384: Buffer.from('2b240303020801010b', 'hex'),
  BRAINPOOLP512: Buffer.from('2b240303020801010d', 'hex'),
  ED25519: Buffer.from('2b06010401da470f01', 'hex')
};

const EMPTY = Buffer.alloc(0);

/**
 * PGP Message
 */

class PGPMessage extends bio.Struct {
  constructor() {
    super();
    this.packets = [];
  }

  getSize() {
    let size = 0;

    for (const pkt of this.packets)
      size += pkt.getSize();

    return size;
  }

  write(bw) {
    for (const pkt of this.packets)
      pkt.write(bw);

    return bw;
  }

  read(br) {
    while (br.left()) {
      const pkt = PGPPacket.read(br);
      this.packets.push(pkt);
    }

    return this;
  }

  toString(type = 'PGP MESSAGE') {
    assert(typeof type === 'string');

    const block = new PEMBlock();

    block.type = type;
    block.data = this.encode();

    return block.toString(true);
  }

  fromString(str) {
    const block = PEMBlock.fromString(str, true);

    if (block.type.substring(0, 4) !== 'PGP ')
      throw new Error('PEM type mismatch.');

    return this.decode(block.data);
  }

  format() {
    return {
      packets: this.packets
    };
  }
}

/**
 * PGP Packet
 */

class PGPPacket extends bio.Struct {
  constructor() {
    super();
    this.type = 0;
    this.body = new PGPUnknown();
  }

  getSize() {
    const len = this.body.getSize();

    let size = 0;

    size += 1;

    if (len < 192) {
      size += 1;
    } else if (len < 8384) {
      size += 2;
    } else {
      size += 5;
    }

    size += len;

    return size;
  }

  write(bw) {
    let len = this.body.getSize();

    bw.writeU8(0x80 | 0x40 | this.type);

    if (len < 192) {
      bw.writeU8(len);
    } else if (len < 8384) {
      len -= 192;
      bw.writeU8(192 + (len >>> 8));
      bw.writeU8(len & 0xff);
    } else {
      bw.writeU8(255);
      bw.writeU32BE(len);
    }

    this.body.write(bw);

    return bw;
  }

  read(br) {
    const ch = br.readU8();

    if ((ch & 0x80) === 0)
      throw new Error('Hi bit unset in PGP packet header.');

    let type = 0;
    let child = null;

    if ((ch & 0x40) === 0) {
      const t = (ch & 0x3f) >>> 2;
      const s = 1 << (ch & 3);

      let size = 0;

      switch (s) {
        case 1:
          size = br.readU8();
          break;
        case 2:
          size = br.readU16BE();
          break;
        case 4:
          size = br.readU32BE();
          break;
        case 8:
          size = br.left();
          break;
      }

      type = t;
      child = br.readChild(size);
    } else {
      const t = ch & 0x3f;
      const s = br.readU8();

      let size = 0;

      if (s < 192) {
        size = s;
      } else if (s < 224) {
        size = (s - 192) * 0x100;
        size += br.readU8() + 192;
      } else if (s < 255) {
        throw new Error('Cannot handle PGP partial length.');
      } else {
        size = br.readU32BE();
      }

      type = t;
      child = br.readChild(size);
    }

    this.type = type;

    switch (this.type) {
      case packetTypes.PUBKEY_ENC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SIGNATURE:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.SYMKEY_ENC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ONEPASS_SIG:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.PRIVATE_KEY:
        this.body = PGPPrivateKey.read(child);
        break;
      case packetTypes.PUBLIC_KEY:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.PRIVATE_SUBKEY:
        this.body = PGPPrivateKey.read(child);
        break;
      case packetTypes.COMPRESSED:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ENCRYPTED:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.MARKER:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.PLAINTEXT:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.RING_TRUST:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.USER_ID:
        this.body = PGPUserID.read(child);
        break;
      case packetTypes.PUBLIC_SUBKEY:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.OLD_COMMENT:
        this.body = PGPPublicKey.read(child);
        break;
      case packetTypes.ATTRIBUTE:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ENCRYPTED_MDC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.MDC:
        this.body = PGPUnknown.read(child);
        break;
      case packetTypes.ENCRYPTED_AEAD:
        this.body = PGPUnknown.read(child);
        break;
      default:
        this.body = PGPUnknown.read(child);
        break;
    }

    return this;
  }

  format() {
    return {
      type: packetTypesByVal[this.type] || 'UNKNOWN',
      body: this.body
    };
  }
}

/**
 * PGP Body
 */

class PGPBody extends bio.Struct {
  constructor() {
    super();
  }
}

/**
 * PGP Unknown
 */

class PGPUnknown extends PGPBody {
  constructor() {
    super();
    this.data = EMPTY;
  }

  getSize() {
    return this.data.length;
  }

  write(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  read(br) {
    this.data = br.readBytes(br.left());
    return this;
  }

  format() {
    return {
      data: this.data.toString('hex')
    };
  }
}

/**
 * PGP Public Key
 */

class PGPPublicKey extends PGPBody {
  constructor() {
    super();

    this.version = 4;
    this.algorithm = 0;
    this.expires = 0;
    this.timestamp = 0;

    // RSA
    this.n = new MPI();
    this.e = new MPI();

    // El Gamal
    this.p = new MPI();
    this.g = new MPI();
    this.y = new MPI();

    // DSA
    this.p;
    this.q = new MPI();
    this.g;
    this.y;

    // ECDH
    this.oid = EMPTY;
    this.point = new MPI();
    this.kdfHash = 0;
    this.kdfAlg = 0;

    // ECDSA
    this.oid;
    this.point;

    // Unknown
    this.data = EMPTY;
  }

  get curve() {
    if (this.oid.equals(oids.P256))
      return curveTypes.P256;

    if (this.oid.equals(oids.P384))
      return curveTypes.P384;

    if (this.oid.equals(oids.P521))
      return curveTypes.P521;

    if (this.oid.equals(oids.SECP256K1))
      return curveTypes.SECP256K1;

    if (this.oid.equals(oids.X25519))
      return curveTypes.X25519;

    if (this.oid.equals(oids.BRAINPOOLP256))
      return curveTypes.BRAINPOOLP256;

    if (this.oid.equals(oids.BRAINPOOLP384))
      return curveTypes.BRAINPOOLP384;

    if (this.oid.equals(oids.BRAINPOOLP512))
      return curveTypes.BRAINPOOLP512;

    if (this.oid.equals(oids.ED25519))
      return curveTypes.ED25519;

    return 0;
  }

  set curve(value) {
    switch (value) {
      case curveTypes.P256:
        this.oid = oids.P256;
        break;
      case curveTypes.P384:
        this.oid = oids.P384;
        break;
      case curveTypes.P521:
        this.oid = oids.P521;
        break;
      case curveTypes.SECP256K1:
        this.oid = oids.SECP256K1;
        break;
      case curveTypes.X25519:
        this.oid = oids.X25519;
        break;
      case curveTypes.BRAINPOOLP256:
        this.oid = oids.BRAINPOOLP256;
        break;
      case curveTypes.BRAINPOOLP384:
        this.oid = oids.BRAINPOOLP384;
        break;
      case curveTypes.BRAINPOOLP512:
        this.oid = oids.BRAINPOOLP512;
        break;
      case curveTypes.ED25519:
        this.oid = oids.ED25519;
        break;
    }
  }

  isRSA() {
    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY:
        return true;
    }
    return false;
  }

  isElgamal() {
    switch (this.algorithm) {
      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY:
        return true;
    }
    return false;
  }

  getSize() {
    let size = 0;

    size += 1;

    switch (this.version) {
      case 2:
      case 3: {
        size += 4;
        size += 2;
        size += 1;
        break;
      }

      case 4: {
        size += 4;
        size += 1;
        break;
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        size += this.n.getSize();
        size += this.e.getSize();
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        size += this.p.getSize();
        size += this.g.getSize();
        size += this.y.getSize();
        break;
      }

      case keyTypes.DSA: {
        size += this.p.getSize();
        size += this.q.getSize();
        size += this.g.getSize();
        size += this.y.getSize();
        break;
      }

      case keyTypes.ECDH: {
        size += 1;
        size += this.oid.length;
        size += this.point.getSize();
        size += 4;
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        size += 1;
        size += this.oid.length;
        size += this.point.getSize();
        break;
      }

      default: {
        size += this.data.length;
        break;
      }
    }

    return size;
  }

  write(bw) {
    bw.writeU8(this.version);

    switch (this.version) {
      case 2:
      case 3: {
        if (!this.isRSA())
          throw new Error('Unknown PGP key algorithm.');

        bw.writeU32BE(this.timestamp);
        bw.writeU16BE(this.expires);
        bw.writeU8(this.algorithm);

        break;
      }

      case 4: {
        bw.writeU32BE(this.timestamp);
        bw.writeU8(this.algorithm);
        break;
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.n.write(bw);
        this.e.write(bw);
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        this.p.write(bw);
        this.g.write(bw);
        this.y.write(bw);
        break;
      }

      case keyTypes.DSA: {
        this.p.write(bw);
        this.q.write(bw);
        this.g.write(bw);
        this.y.write(bw);
        break;
      }

      case keyTypes.ECDH: {
        bw.writeU8(this.oid.length);
        bw.writeBytes(this.oid);
        this.point.write(bw);
        bw.writeU8(3);
        bw.writeU8(0x01);
        bw.writeU8(this.kdfHash);
        bw.writeU8(this.kdfAlg);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        bw.writeU8(this.oid.length);
        bw.writeBytes(this.oid);
        this.point.write(bw);
        break;
      }

      default: {
        bw.writeBytes(this.data);
        break;
      }
    }

    return bw;
  }

  read(br) {
    this.version = br.readU8();

    switch (this.version) {
      case 2:
      case 3: {
        this.timestamp = br.readU32BE();
        this.expires = br.readU16BE();
        this.algorithm = br.readU8();

        if (!this.isRSA()) {
          if (this.version === 3 && this.isElgamal()) {
            this.expires = 0;
            this.version = 4;
          } else {
            throw new Error('Unknown PGP key algorithm.');
          }
        }

        break;
      }

      case 4: {
        this.timestamp = br.readU32BE();
        this.algorithm = br.readU8();
        break;
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.n.read(br);
        this.e.read(br);
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        this.p.read(br);
        this.g.read(br);
        this.y.read(br);
        break;
      }

      case keyTypes.DSA: {
        this.p.read(br);
        this.q.read(br);
        this.g.read(br);
        this.y.read(br);
        break;
      }

      case keyTypes.ECDH: {
        this.oid = br.readBytes(br.readU8());
        this.point.read(br);

        const size = br.readU8();

        if (size < 3 || size > br.left())
          throw new Error('Invalid ECDH params.');

        // Reserved.
        if (br.readU8() !== 0x01)
          throw new Error('Invalid ECDH reserved byte.');

        this.kdfHash = br.readU8();
        this.kdfAlg = br.readU8();

        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        this.oid = br.readBytes(br.readU8());
        this.point.read(br);
        break;
      }

      default: {
        this.data = br.readBytes(br.left());
        break;
      }
    }

    return this;
  }

  fingerprint() {
    switch (this.version) {
      case 2:
      case 3: {
        if (!this.isRSA())
          throw new Error('Unknown PGP key algorithm.');

        const data = bio.concat(this.n.data, this.e.data);
        return MD5.digest(data);
      }

      case 4: {
        const size = this.getSize();
        const bw = bio.write(3 + size);

        bw.writeU8(0x99);
        bw.writeU16BE(size);

        this.write(bw);

        return SHA1.digest(bw.render());
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }
  }

  id() {
    switch (this.version) {
      case 2:
      case 3: {
        if (!this.isRSA())
          throw new Error('Unknown PGP key algorithm.');

        if (this.n.data.length < 8)
          throw new Error('Unknown PGP key algorithm.');

        return this.n.data.slice(this.n.data.length - 8);
      }

      case 4: {
        return this.fingerprint().slice(12, 20);
      }

      default: {
        throw new Error('Unknown PGP key version.');
      }
    }
  }

  long() {
    return this.id();
  }

  short() {
    return this.id().slice(4, 8);
  }

  matches(id) {
    if (typeof id === 'string')
      id = decodeID(id);

    switch (id.length) {
      case 4:
        return this.short().equals(id);
      case 8:
        return this.long().equals(id);
      case 16:
      case 20:
        return this.fingerprint().equals(id);
      default:
        return false;
    }
  }

  keyHash() {
    let size = 6;

    if (this.version !== 4)
      size += 2;

    // Create a real key hash without any bullshit.
    const raw = this.encode().slice(size - 1);

    raw[0] = this.algorithm;

    return SHA256.digest(raw);
  }

  format() {
    const algorithm = keyTypesByVal[this.algorithm] || 'UNKNOWN';
    const version = this.version;
    const timestamp = this.timestamp;
    const expires = this.expires;

    switch (this.algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          n: this.n.data.toString('hex'),
          e: this.e.data.toString('hex')
        };
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          p: this.p.data.toString('hex'),
          g: this.g.data.toString('hex'),
          y: this.y.data.toString('hex')
        };
      }

      case keyTypes.DSA: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          p: this.p.data.toString('hex'),
          q: this.q.data.toString('hex'),
          g: this.g.data.toString('hex'),
          y: this.y.data.toString('hex')
        };
      }

      case keyTypes.ECDH: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          curve: curveTypesByVal[this.curve] || 'UNKNOWN',
          point: this.point.data.toString('hex'),
          kdfHash: this.kdfHash,
          kdfAlg: this.kdfAlg
        };
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          curve: curveTypesByVal[this.curve] || 'UNKNOWN',
          point: this.point.data.toString('hex')
        };
      }

      default: {
        return {
          version,
          algorithm,
          timestamp,
          expires,
          data: this.data.toString('hex')
        };
      }
    }
  }
}

/**
 * PGP Private Key
 */

class PGPPrivateKey extends PGPBody {
  constructor() {
    super();

    this.key = new PGPPublicKey();
    this.params = new CipherParams();
    this.data = EMPTY;
  }

  secret(passphrase) {
    let data = this.data;

    if (this.params.encrypted) {
      if (passphrase == null)
        throw new Error('Key requires a passphrase.');

      data = this.params.decrypt(data, passphrase);
    }

    return SecretKey.decode(data, this.key.algorithm);
  }

  getSize() {
    let size = 0;

    size += this.key.getSize();
    size += this.params.getSize();
    size += this.data.length;

    return size;
  }

  write(bw) {
    this.key.write(bw);
    this.params.write(bw);
    bw.writeBytes(this.data);
    return bw;
  }

  read(br) {
    this.key.read(br);
    this.params.read(br);
    this.data = br.readBytes(br.left());
    return this;
  }

  format() {
    let params = null;
    let data = null;

    if (this.params.encrypted) {
      params = this.params;
      data = this.data.toString('hex');
    } else {
      params = null;
      data = this.secret();
    }

    return {
      key: this.key,
      params,
      data
    };
  }
}

/**
 * Cipher Params
 */

class CipherParams extends bio.Struct {
  constructor() {
    super();
    this.encrypted = false;
    this.checksum = false;
    this.cipher = 0;
    this.s2k = new S2K();
    this.iv = EMPTY;
  }

  blockSize() {
    switch (this.cipher) {
      case cipherTypes.IDEA:
      case cipherTypes.DES3:
      case cipherTypes.CAST5:
      case cipherTypes.BLOWFISH:
        return 8;
      case cipherTypes.AES128:
      case cipherTypes.AES192:
      case cipherTypes.AES256:
      case cipherTypes.TWOFISH:
      case cipherTypes.CAMELLIA128:
      case cipherTypes.CAMELLIA192:
      case cipherTypes.CAMELLIA256:
        return 16;
      default:
        throw new Error('Unknown cipher type.');
    }
  }

  keySize() {
    switch (this.cipher) {
      case cipherTypes.IDEA:
        return 16;
      case cipherTypes.DES3:
        return 24;
      case cipherTypes.CAST5:
        return 16;
      case cipherTypes.BLOWFISH:
        return 16;
      case cipherTypes.AES128:
        return 16;
      case cipherTypes.AES192:
        return 24;
      case cipherTypes.AES256:
        return 32;
      case cipherTypes.TWOFISH:
        return 32;
      case cipherTypes.CAMELLIA128:
        return 16;
      case cipherTypes.CAMELLIA192:
        return 24;
      case cipherTypes.CAMELLIA256:
        return 32;
      default:
        throw new Error('Unknown cipher type.');
    }
  }

  algName() {
    switch (this.cipher) {
      case cipherTypes.IDEA:
        return 'IDEA-CFB';
      case cipherTypes.DES3:
        return 'DES-EDE3-CFB';
      case cipherTypes.CAST5:
        return 'CAST5-CFB';
      case cipherTypes.BLOWFISH:
        return 'BF-CFB';
      case cipherTypes.AES128:
        return 'AES-128-CFB';
      case cipherTypes.AES192:
        return 'AES-192-CFB';
      case cipherTypes.AES256:
        return 'AES-256-CFB';
      case cipherTypes.TWOFISH:
        return 'TWOFISH-256-CFB';
      case cipherTypes.CAMELLIA128:
        return 'CAMELLIA-128-CFB';
      case cipherTypes.CAMELLIA192:
        return 'CAMELLIA-192-CFB';
      case cipherTypes.CAMELLIA256:
        return 'CAMELLIA-256-CFB';
      default:
        throw new Error('Unknown cipher type.');
    }
  }

  derive(passphrase) {
    if (!this.encrypted)
      throw new Error('Cannot derive passphrase.');

    return this.s2k.derive(passphrase, this.keySize());
  }

  encipher(pt, key) {
    assert(Buffer.isBuffer(pt));

    const name = this.algName();
    const add = this.checksum ? 20 : 2;
    const padded = Buffer.alloc(pt.length + add);

    pt.copy(padded, 0);

    if (this.checksum) {
      SHA1.digest(pt).copy(padded, pt.length);
    } else {
      let sum = 0;

      for (let i = 0; i < pt.length; i++) {
        sum += pt[i];
        sum &= 0xffff;
      }

      bio.writeU16BE(padded, sum, pt.length);
    }

    return cipher.encrypt(name, key, this.iv, padded);
  }

  decipher(ct, key) {
    const name = this.algName();
    const padded = cipher.decrypt(name, key, this.iv, ct);

    if (this.checksum) {
      if (padded.length < 20)
        throw new Error('Truncated data.');

      const pt = padded.slice(0, -20);
      const chk = padded.slice(-20);
      const sum = SHA1.digest(pt);

      if (!sum.equals(chk))
        throw new Error('Invalid checksum.');

      return pt;
    }

    if (padded.length < 2)
      throw new Error('Truncated data.');

    const pt = padded.slice(0, -2);
    const chk = bio.readU16BE(padded, padded.length - 2);

    let sum = 0;

    for (let i = 0; i < pt.length; i++) {
      sum += pt[i];
      sum &= 0xffff;
    }

    if (sum !== chk)
      throw new Error('Invalid checksum.');

    return pt;
  }

  encrypt(data, passphrase) {
    const key = this.derive(passphrase);
    return this.encipher(data, key);
  }

  decrypt(data, passphrase) {
    const key = this.derive(passphrase);
    return this.decipher(data, key);
  }

  getSize() {
    let size = 0;

    if (this.encrypted) {
      size += 1;
      size += 1;
      size += this.s2k.getSize();
      size += this.iv.length;
    } else {
      size += 1;
    }

    return size;
  }

  write(bw) {
    if (this.encrypted) {
      assert(this.iv.length === this.blockSize());

      bw.writeU8(this.checksum ? 0xfe : 0xff);
      bw.writeU8(this.cipher);
      this.s2k.write(bw);
      bw.writeBytes(this.iv);
    } else {
      bw.writeU8(0x00);
    }

    return bw;
  }

  read(br) {
    const type = br.readU8();

    switch (type) {
      case 0x00:
        break;
      case 0xfe:
      case 0xff:
        this.encrypted = true;
        this.checksum = type === 0xfe;
        this.cipher = br.readU8();
        this.s2k.read(br);
        this.iv = br.readBytes(this.blockSize());
        break;
      default:
        throw new Error('Unknown S2K type.');
    }

    return this;
  }

  format() {
    return {
      encrypted: this.encrypted,
      checksum: this.checksum,
      cipher: cipherTypesByVal[this.cipher] || 'UNKNOWN',
      s2k: this.s2k,
      iv: this.iv.toString('hex')
    };
  }
}

/**
 * S2K
 */

class S2K extends bio.Struct {
  constructor() {
    super();
    this.mode = 0;
    this.hash = 0;
    this.count = 0;
    this.salt = EMPTY;
    this.serial = EMPTY;
  }

  derive(passphrase, size) {
    assert(typeof passphrase === 'string');
    assert((size >>> 0) === size);

    const {salt, count} = this;
    const input = Buffer.from(passphrase, 'binary');
    const hash = hashToHash[this.hash];

    if (!hash)
      throw new Error('Unknown hash.');

    switch (this.mode) {
      case 0:
        return pgpdf.deriveSimple(hash, input, size);
      case 1:
        return pgpdf.deriveSalted(hash, input, salt, size);
      case 3:
        return pgpdf.deriveIterated(hash, input, salt, count, size);
      default:
        throw new Error('Unknown S2K mode.');
    }
  }

  getSize() {
    let size = 2;

    switch (this.mode) {
      case 0:
        break;
      case 1:
        size += 8;
        break;
      case 3:
        size += 8;
        size += 1;
        break;
      case 1001:
        size += 3;
        size += 1;
        break;
      case 1002:
        size += 3;
        size += 1;
        size += 1;
        size += this.serial.length;
        break;
      default:
        throw new Error('Unknown S2K function.');
    }

    return size;
  }

  write(bw) {
    bw.writeU8(this.mode > 0xff ? 101 : this.mode);
    bw.writeU8(this.hash);

    switch (this.mode) {
      case 0:
        break;
      case 1:
        bw.writeBytes(this.salt);
        break;
      case 3:
        bw.writeBytes(this.salt);
        bw.writeU8(encodeCount(this.count));
        break;
      case 1001:
        bw.writeString('GNU', 'binary');
        bw.writeU8(1);
        break;
      case 1002:
        bw.writeString('GNU', 'binary');
        bw.writeU8(2);
        bw.writeU8(this.serial.length);
        bw.writeBytes(this.serial);
        break;
      default:
        throw new Error('Unknown S2K function.');
    }

    return bw;
  }

  read(br) {
    this.mode = br.readU8();
    this.hash = br.readU8();

    switch (this.mode) {
      case 0: {
        break;
      }

      case 1: {
        this.salt = br.readBytes(8);
        break;
      }

      case 3: {
        this.salt = br.readBytes(8);
        this.count = decodeCount(br.readU8());
        break;
      }

      case 101: {
        // GNU extensions.
        // See: https://github.com/handshake-org/hs-airdrop/issues/44
        const tag = br.readString(3, 'binary');

        if (tag !== 'GNU')
          throw new Error('Unknown S2K function.');

        this.mode = 1000 + br.readU8();

        switch (this.mode) {
          case 1001:
            // gnu-dummy
            break;
          case 1002:
            // gnu-divert-to-card
            this.serial = br.readBytes(Math.min(br.readU8(), 16));
            break;
          default:
            throw new Error('Unknown S2K function.');
        }

        break;
      }

      default: {
        throw new Error('Unknown S2K function.');
      }
    }

    return this;
  }

  format() {
    return {
      mode: this.mode,
      hash: hashTypesByVal[this.hash] || 'UNKNOWN',
      count: this.count,
      salt: this.salt.toString('hex'),
      serial: this.serial.toString('hex')
    };
  }
}

/**
 * Secret Key
 */

class SecretKey extends bio.Struct {
  constructor() {
    super();

    // RSA
    this.d = new MPI();
    this.q = new MPI();
    this.p = new MPI();
    this.qi = new MPI();

    // DSA
    this.x = new MPI();

    // El Gamal
    this.x;

    // ECDSA
    this.d;
  }

  getSize(algorithm) {
    assert((algorithm & 0xff) === algorithm);

    let size = 0;

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        size += this.d.getSize();
        size += this.q.getSize();
        size += this.p.getSize();
        size += this.qi.getSize();
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        size += this.x.getSize();
        break;
      }

      case keyTypes.DSA: {
        size += this.x.getSize();
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        size += this.d.getSize();
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return size;
  }

  write(bw, algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.d.write(bw);
        this.q.write(bw);
        this.p.write(bw);
        this.qi.write(bw);
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        this.x.write(bw);
        break;
      }

      case keyTypes.DSA: {
        this.x.write(bw);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        this.d.write(bw);
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return bw;
  }

  read(br, algorithm) {
    assert((algorithm & 0xff) === algorithm);

    switch (algorithm) {
      case keyTypes.RSA:
      case keyTypes.RSA_ENCRYPT_ONLY:
      case keyTypes.RSA_SIGN_ONLY: {
        this.d.read(br);
        this.q.read(br);
        this.p.read(br);
        this.qi.read(br);
        break;
      }

      case keyTypes.ELGAMAL:
      case keyTypes.ELGAMAL_LEGACY: {
        this.x.read(br);
        break;
      }

      case keyTypes.DSA: {
        this.x.read(br);
        break;
      }

      case keyTypes.ECDSA:
      case keyTypes.EDDSA: {
        this.d.read(br);
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return this;
  }

  format() {
    if (this.p.data.length > 0) {
      return {
        d: this.d.data.toString('hex'),
        q: this.q.data.toString('hex'),
        p: this.p.data.toString('hex'),
        qi: this.qi.data.toString('hex')
      };
    }

    if (this.x.data.length > 0) {
      return {
        x: this.x.data.toString('hex')
      };
    }

    if (this.d.data.length > 0) {
      return {
        d: this.d.data.toString('hex')
      };
    }

    return {
      d: this.d.data.toString('hex'),
      q: this.q.data.toString('hex'),
      p: this.p.data.toString('hex'),
      qi: this.qi.data.toString('hex'),
      x: this.x.data.toString('hex')
    };
  }
}

/**
 * PGP User ID
 */

class PGPUserID extends PGPBody {
  constructor() {
    super();
    this.id = '';
  }

  getSize() {
    return Buffer.byteLength(this.id, 'utf8');
  }

  write(bw) {
    bw.writeString(this.id, 'utf8');
    return bw;
  }

  read(br) {
    this.id = br.readString(br.left(), 'utf8');
    return this;
  }

  format() {
    return {
      id: this.id
    };
  }
}

/**
 * MPI
 */

class MPI extends bio.Struct {
  constructor(data) {
    super();

    this.bits = 0;
    this.data = EMPTY;

    if (data != null)
      this.fromOptions(data);
  }

  get() {
    return this.data;
  }

  set(data) {
    return this.fromOptions(data);
  }

  fromOptions(data) {
    assert(Buffer.isBuffer(data));
    this.bits = countLeft(data);
    this.data = data;
    return this;
  }

  getSize() {
    return 2 + this.data.length;
  }

  write(bw) {
    bw.writeU16BE(this.bits);
    bw.writeBytes(this.data);
    return bw;
  }

  read(br) {
    if (br.left() === 0)
      return this;

    const bits = br.readU16BE();
    const size = (bits + 7) >>> 3;
    const s = Math.min(size, br.left());
    const data = br.readBytes(s);

    this.bits = bits;
    this.data = data;

    return this;
  }
}

/*
 * ID Parsing
 */

function encodeID(raw) {
  assert(Buffer.isBuffer(raw));

  switch (raw.length) {
    case 4:
    case 8:
    case 16:
    case 20:
      break;
    default:
      throw new Error('Invalid PGP key id/fingerprint.');
  }

  const id = raw.toString('hex');

  return `0x${id.toUpperCase()}`;
}

function decodeID(id) {
  assert(typeof id === 'string');

  id = id.replace(/[\t ]/g, '');

  if (id.length >= 2
      && id.charCodeAt(0) === 0x30
      && (id.charCodeAt(1) | 0x20) === 0x78) {
    id = id.substring(2);
  }

  if (id.length > 40)
    throw new Error('Invalid PGP key id/fingerprint.');

  const raw = Buffer.from(id, 'hex');

  if (raw.length !== (id.length >>> 1))
    throw new Error('Invalid PGP key id/fingerprint.');

  switch (raw.length) {
    case 4:
    case 8:
    case 16:
    case 20:
      break;
    default:
      throw new Error('Invalid PGP key id/fingerprint.');
  }

  return raw;
}

/*
 * Helpers
 */

function encodeCount(i) {
  assert((i >>> 0) === i);

  if (i < 1024 || i > 65011712)
    throw new RangeError('Invalid iteration count.');

  for (let j = 0; j < 256; j++) {
    const c = decodeCount(j);

    if (c >= i)
      return j;
  }

  return 255;
}

function decodeCount(c) {
  assert((c & 0xff) === c);
  return (16 + (c & 15)) << ((c >>> 4) + 6);
}

/*
 * Expose
 */

exports.packetTypes = packetTypes;
exports.packetTypesByVal = packetTypesByVal;
exports.sigTypes = sigTypes;
exports.sigTypesByVal = sigTypesByVal;
exports.keyTypes = keyTypes;
exports.keyTypesByVal = keyTypesByVal;
exports.cipherTypes = cipherTypes;
exports.cipherTypesByVal = cipherTypesByVal;
exports.hashTypes = hashTypes;
exports.hashTypesByVal = hashTypesByVal;
exports.compressTypes = compressTypes;
exports.compressTypesByVal = compressTypesByVal;
exports.curveTypes = curveTypes;
exports.curveTypesByVal = curveTypesByVal;
exports.oids = oids;

exports.PGPMessage = PGPMessage;
exports.PGPPacket = PGPPacket;
exports.PGPBody = PGPBody;
exports.PGPUnknown = PGPUnknown;
exports.PGPPublicKey = PGPPublicKey;
exports.PGPPrivateKey = PGPPrivateKey;
exports.CipherParams = CipherParams;
exports.S2K = S2K;
exports.SecretKey = SecretKey;
exports.PGPUserID = PGPUserID;
exports.MPI = MPI;
exports.encodeID = encodeID;
exports.decodeID = decodeID;

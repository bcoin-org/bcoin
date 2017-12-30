/*!
 * packets.js - packets for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

/**
 * @module net/packets
 */

const assert = require('assert');
const bio = require('bufio');
const {BloomFilter} = require('bfilter');
const common = require('./common');
const util = require('../utils/util');
const bip152 = require('./bip152');
const NetAddress = require('./netaddress');
const consensus = require('../protocol/consensus');
const Headers = require('../primitives/headers');
const InvItem = require('../primitives/invitem');
const MemBlock = require('../primitives/memblock');
const MerkleBlock = require('../primitives/merkleblock');
const TX = require('../primitives/tx');
const {encoding} = bio;
const DUMMY = Buffer.alloc(0);

/**
 * Packet types.
 * @enum {Number}
 * @default
 */

exports.types = {
  VERSION: 0,
  VERACK: 1,
  PING: 2,
  PONG: 3,
  GETADDR: 4,
  ADDR: 5,
  INV: 6,
  GETDATA: 7,
  NOTFOUND: 8,
  GETBLOCKS: 9,
  GETHEADERS: 10,
  HEADERS: 11,
  SENDHEADERS: 12,
  BLOCK: 13,
  TX: 14,
  REJECT: 15,
  MEMPOOL: 16,
  FILTERLOAD: 17,
  FILTERADD: 18,
  FILTERCLEAR: 19,
  MERKLEBLOCK: 20,
  FEEFILTER: 21,
  SENDCMPCT: 22,
  CMPCTBLOCK: 23,
  GETBLOCKTXN: 24,
  BLOCKTXN: 25,
  ENCINIT: 26,
  ENCACK: 27,
  AUTHCHALLENGE: 28,
  AUTHREPLY: 29,
  AUTHPROPOSE: 30,
  UNKNOWN: 31,
  // Internal
  INTERNAL: 32,
  DATA: 33
};

/**
 * Packet types by value.
 * @const {Object}
 * @default
 */

exports.typesByVal = [
  'VERSION',
  'VERACK',
  'PING',
  'PONG',
  'GETADDR',
  'ADDR',
  'INV',
  'GETDATA',
  'NOTFOUND',
  'GETBLOCKS',
  'GETHEADERS',
  'HEADERS',
  'SENDHEADERS',
  'BLOCK',
  'TX',
  'REJECT',
  'MEMPOOL',
  'FILTERLOAD',
  'FILTERADD',
  'FILTERCLEAR',
  'MERKLEBLOCK',
  'FEEFILTER',
  'SENDCMPCT',
  'CMPCTBLOCK',
  'GETBLOCKTXN',
  'BLOCKTXN',
  'ENCINIT',
  'ENCACK',
  'AUTHCHALLENGE',
  'AUTHREPLY',
  'AUTHPROPOSE',
  'UNKNOWN',
  // Internal
  'INTERNAL',
  'DATA'
];

/**
 * Base Packet
 */

class Packet {
  /**
   * Create a base packet.
   * @constructor
   */

  constructor() {
    this.type = -1;
    this.cmd = '';
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 0;
  }

  /**
   * Serialize packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    return bw;
  }

  /**
   * Serialize packet.
   * @returns {Buffer}
   */

  toRaw() {
    return DUMMY;
  }

  /**
   * Inject properties from buffer reader.
   * @param {BufferReader} br
   */

  fromReader(br) {
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this;
  }
}

/**
 * Version Packet
 * @extends Packet
 * @property {Number} version - Protocol version.
 * @property {Number} services - Service bits.
 * @property {Number} time - Timestamp of discovery.
 * @property {NetAddress} local - Our address.
 * @property {NetAddress} remote - Their address.
 * @property {Buffer} nonce
 * @property {String} agent - User agent string.
 * @property {Number} height - Chain height.
 * @property {Boolean} noRelay - Whether transactions
 * should be relayed immediately.
 */

class VersionPacket extends Packet {
  /**
   * Create a version packet.
   * @constructor
   * @param {Object?} options
   * @param {Number} options.version - Protocol version.
   * @param {Number} options.services - Service bits.
   * @param {Number} options.time - Timestamp of discovery.
   * @param {NetAddress} options.local - Our address.
   * @param {NetAddress} options.remote - Their address.
   * @param {Buffer} options.nonce
   * @param {String} options.agent - User agent string.
   * @param {Number} options.height - Chain height.
   * @param {Boolean} options.noRelay - Whether transactions
   * should be relayed immediately.
   */

  constructor(options) {
    super();

    this.cmd = 'version';
    this.type = exports.types.VERSION;

    this.version = common.PROTOCOL_VERSION;
    this.services = common.LOCAL_SERVICES;
    this.time = util.now();
    this.remote = new NetAddress();
    this.local = new NetAddress();
    this.nonce = common.ZERO_NONCE;
    this.agent = common.USER_AGENT;
    this.height = 0;
    this.noRelay = false;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    if (options.version != null)
      this.version = options.version;

    if (options.services != null)
      this.services = options.services;

    if (options.time != null)
      this.time = options.time;

    if (options.remote)
      this.remote.fromOptions(options.remote);

    if (options.local)
      this.local.fromOptions(options.local);

    if (options.nonce)
      this.nonce = options.nonce;

    if (options.agent)
      this.agent = options.agent;

    if (options.height != null)
      this.height = options.height;

    if (options.noRelay != null)
      this.noRelay = options.noRelay;

    return this;
  }

  /**
   * Instantiate version packet from options.
   * @param {Object} options
   * @returns {VersionPacket}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 20;
    size += this.remote.getSize(false);
    size += this.local.getSize(false);
    size += 8;
    size += encoding.sizeVarString(this.agent, 'ascii');
    size += 5;
    return size;
  }

  /**
   * Write version packet to buffer writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeI32(this.version);
    bw.writeU32(this.services);
    bw.writeU32(0);
    bw.writeI64(this.time);
    this.remote.toWriter(bw, false);
    this.local.toWriter(bw, false);
    bw.writeBytes(this.nonce);
    bw.writeVarString(this.agent, 'ascii');
    bw.writeI32(this.height);
    bw.writeU8(this.noRelay ? 0 : 1);
    return bw;
  }

  /**
   * Serialize version packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.version = br.readI32();
    this.services = br.readU32();

    // Note: hi service bits
    // are currently unused.
    br.readU32();

    this.time = br.readI64();
    this.remote.fromReader(br, false);

    if (br.left() > 0) {
      this.local.fromReader(br, false);
      this.nonce = br.readBytes(8);
    }

    if (br.left() > 0)
      this.agent = br.readVarString('ascii', 256);

    if (br.left() > 0)
      this.height = br.readI32();

    if (br.left() > 0)
      this.noRelay = br.readU8() === 0;

    if (this.version === 10300)
      this.version = 300;

    assert(this.version >= 0, 'Version is negative.');
    assert(this.time >= 0, 'Timestamp is negative.');

    // No idea why so many peers do this.
    if (this.height < 0)
      this.height = 0;

    return this;
  }

  /**
   * Instantiate version packet from buffer reader.
   * @param {BufferReader} br
   * @returns {VersionPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate version packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {VersionPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data, enc);
  }
}

/**
 * Verack Packet
 * @extends Packet
 */

class VerackPacket extends Packet {
  /**
   * Create a `verack` packet.
   * @constructor
   */

  constructor() {
    super();
    this.cmd = 'verack';
    this.type = exports.types.VERACK;
  }

  /**
   * Instantiate verack packet from serialized data.
   * @param {BufferReader} br
   * @returns {VerackPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate verack packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {VerackPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Ping Packet
 * @extends Packet
 * @property {BN|null} nonce
 */

class PingPacket extends Packet {
  /**
   * Create a `ping` packet.
   * @constructor
   * @param {BN?} nonce
   */

  constructor(nonce) {
    super();

    this.cmd = 'ping';
    this.type = exports.types.PING;

    this.nonce = nonce || null;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.nonce ? 8 : 0;
  }

  /**
   * Serialize ping packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Serialize ping packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.nonce)
      bw.writeBytes(this.nonce);
    return bw;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    if (br.left() >= 8)
      this.nonce = br.readBytes(8);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate ping packet from serialized data.
   * @param {BufferReader} br
   * @returns {PingPacket}
   */

  static fromReader(br) {
    return new this().fromRaw(br);
  }

  /**
   * Instantiate ping packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {PingPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Pong Packet
 * @extends Packet
 * @property {BN} nonce
 */

class PongPacket extends Packet {
  /**
   * Create a `pong` packet.
   * @constructor
   * @param {BN?} nonce
   */

  constructor(nonce) {
    super();

    this.cmd = 'pong';
    this.type = exports.types.PONG;

    this.nonce = nonce || common.ZERO_NONCE;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 8;
  }

  /**
   * Serialize pong packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.nonce);
    return bw;
  }

  /**
   * Serialize pong packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(8)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.nonce = br.readBytes(8);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate pong packet from buffer reader.
   * @param {BufferReader} br
   * @returns {VerackPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate pong packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {VerackPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * GetAddr Packet
 * @extends Packet
 */

class GetAddrPacket extends Packet {
  /**
   * Create a `getaddr` packet.
   * @constructor
   */

  constructor() {
    super();
    this.cmd = 'getaddr';
    this.type = exports.types.GETADDR;
  }

  /**
   * Instantiate getaddr packet from buffer reader.
   * @param {BufferReader} br
   * @returns {GetAddrPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate getaddr packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {GetAddrPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Addr Packet
 * @extends Packet
 * @property {NetAddress[]} items
 */

class AddrPacket extends Packet {
  /**
   * Create a `addr` packet.
   * @constructor
   * @param {(NetAddress[])?} items
   */

  constructor(items) {
    super();

    this.cmd = 'addr';
    this.type = exports.types.ADDR;

    this.items = items || [];
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += encoding.sizeVarint(this.items.length);
    size += 30 * this.items.length;
    return size;
  }

  /**
   * Serialize addr packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeVarint(this.items.length);

    for (const item of this.items)
      item.toWriter(bw, true);

    return bw;
  }

  /**
   * Serialize addr packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    const br = bio.read(data);
    const count = br.readVarint();

    for (let i = 0; i < count; i++)
      this.items.push(NetAddress.fromReader(br, true));

    return this;
  }

  /**
   * Instantiate addr packet from Buffer reader.
   * @param {BufferReader} br
   * @returns {AddrPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate addr packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {AddrPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Inv Packet
 * @extends Packet
 * @property {InvItem[]} items
 */

class InvPacket extends Packet {
  /**
   * Create a `inv` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super();

    this.cmd = 'inv';
    this.type = exports.types.INV;

    this.items = items || [];
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += encoding.sizeVarint(this.items.length);
    size += 36 * this.items.length;
    return size;
  }

  /**
   * Serialize inv packet to writer.
   * @param {Buffer} bw
   */

  toWriter(bw) {
    assert(this.items.length <= 50000);

    bw.writeVarint(this.items.length);

    for (const item of this.items)
      item.toWriter(bw);

    return bw;
  }

  /**
   * Serialize inv packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    const count = br.readVarint();

    assert(count <= 50000, 'Inv item count too high.');

    for (let i = 0; i < count; i++)
      this.items.push(InvItem.fromReader(br));

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate inv packet from buffer reader.
   * @param {BufferReader} br
   * @returns {InvPacket}
   */

  static fromReader(br) {
    return new this().fromRaw(br);
  }

  /**
   * Instantiate inv packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {InvPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * GetData Packet
 * @extends InvPacket
 */

class GetDataPacket extends InvPacket {
  /**
   * Create a `getdata` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super(items);
    this.cmd = 'getdata';
    this.type = exports.types.GETDATA;
  }

  /**
   * Instantiate getdata packet from buffer reader.
   * @param {BufferReader} br
   * @returns {GetDataPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate getdata packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {GetDataPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * NotFound Packet
 * @extends InvPacket
 */

class NotFoundPacket extends InvPacket {
  /**
   * Create a `notfound` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super(items);
    this.cmd = 'notfound';
    this.type = exports.types.NOTFOUND;
  }

  /**
   * Instantiate notfound packet from buffer reader.
   * @param {BufferReader} br
   * @returns {NotFoundPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate notfound packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {NotFoundPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * GetBlocks Packet
 * @extends Packet
 * @property {Hash[]} locator
 * @property {Hash|null} stop
 */

class GetBlocksPacket extends Packet {
  /**
   * Create a `getblocks` packet.
   * @constructor
   * @param {Hash[]} locator
   * @param {Hash?} stop
   */

  constructor(locator, stop) {
    super();

    this.cmd = 'getblocks';
    this.type = exports.types.GETBLOCKS;

    this.version = common.PROTOCOL_VERSION;
    this.locator = locator || [];
    this.stop = stop || null;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 4;
    size += encoding.sizeVarint(this.locator.length);
    size += 32 * this.locator.length;
    size += 32;
    return size;
  }

  /**
   * Serialize getblocks packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    assert(this.locator.length <= 50000, 'Too many block hashes.');

    bw.writeU32(this.version);
    bw.writeVarint(this.locator.length);

    for (const hash of this.locator)
      bw.writeHash(hash);

    bw.writeHash(this.stop || consensus.ZERO_HASH);

    return bw;
  }

  /**
   * Serialize getblocks packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.version = br.readU32();

    const count = br.readVarint();

    assert(count <= 50000, 'Too many block hashes.');

    for (let i = 0; i < count; i++)
      this.locator.push(br.readHash('hex'));

    this.stop = br.readHash('hex');

    if (this.stop === consensus.NULL_HASH)
      this.stop = null;

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate getblocks packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {GetBlocksPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * GetHeader Packets
 * @extends GetBlocksPacket
 */

class GetHeadersPacket extends GetBlocksPacket {
  /**
   * Create a `getheaders` packet.
   * @constructor
   * @param {Hash[]} locator
   * @param {Hash?} stop
   */

  constructor(locator, stop) {
    super(locator, stop);
    this.cmd = 'getheaders';
    this.type = exports.types.GETHEADERS;
  }

  /**
   * Instantiate getheaders packet from buffer reader.
   * @param {BufferReader} br
   * @returns {GetHeadersPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate getheaders packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {GetHeadersPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Headers Packet
 * @extends Packet
 * @property {Headers[]} items
 */

class HeadersPacket extends Packet {
  /**
   * Create a `headers` packet.
   * @constructor
   * @param {(Headers[])?} items
   */

  constructor(items) {
    super();

    this.cmd = 'headers';
    this.type = exports.types.HEADERS;

    this.items = items || [];
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += encoding.sizeVarint(this.items.length);

    for (const item of this.items)
      size += item.getSize();

    return size;
  }

  /**
   * Serialize headers packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    assert(this.items.length <= 2000, 'Too many headers.');

    bw.writeVarint(this.items.length);

    for (const item of this.items)
      item.toWriter(bw);

    return bw;
  }

  /**
   * Serialize headers packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    const count = br.readVarint();

    assert(count <= 2000, 'Too many headers.');

    for (let i = 0; i < count; i++)
      this.items.push(Headers.fromReader(br));

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate headers packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {VerackPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * SendHeaders Packet
 * @extends Packet
 */

class SendHeadersPacket extends Packet {
  /**
   * Create a `sendheaders` packet.
   * @constructor
   */

  constructor() {
    super();
    this.cmd = 'sendheaders';
    this.type = exports.types.SENDHEADERS;
  }

  /**
   * Instantiate sendheaders packet from buffer reader.
   * @param {BufferReader} br
   * @returns {SendHeadersPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate sendheaders packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {SendHeadersPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Block Packet
 * @extends Packet
 * @property {Block} block
 * @property {Boolean} witness
 */

class BlockPacket extends Packet {
  /**
   * Create a `block` packet.
   * @constructor
   * @param {Block|null} block
   * @param {Boolean?} witness
   */

  constructor(block, witness) {
    super();

    this.cmd = 'block';
    this.type = exports.types.BLOCK;

    this.block = block || new MemBlock();
    this.witness = witness || false;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    if (this.witness)
      return this.block.getSize();
    return this.block.getBaseSize();
  }

  /**
   * Serialize block packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.witness)
      return this.block.toWriter(bw);
    return this.block.toNormalWriter(bw);
  }

  /**
   * Serialize block packet.
   * @returns {Buffer}
   */

  toRaw() {
    if (this.witness)
      return this.block.toRaw();
    return this.block.toNormal();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.block.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.block.fromRaw(data);
    return this;
  }

  /**
   * Instantiate block packet from buffer reader.
   * @param {BufferReader} br
   * @returns {BlockPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate block packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {BlockPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * TX Packet
 * @extends Packet
 * @property {TX} block
 * @property {Boolean} witness
 */

class TXPacket extends Packet {
  /**
   * Create a `tx` packet.
   * @constructor
   * @param {TX|null} tx
   * @param {Boolean?} witness
   */

  constructor(tx, witness) {
    super();

    this.cmd = 'tx';
    this.type = exports.types.TX;

    this.tx = tx || new TX();
    this.witness = witness || false;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    if (this.witness)
      return this.tx.getSize();
    return this.tx.getBaseSize();
  }

  /**
   * Serialize tx packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.witness)
      return this.tx.toWriter(bw);
    return this.tx.toNormalWriter(bw);
  }

  /**
   * Serialize tx packet.
   * @returns {Buffer}
   */

  toRaw() {
    if (this.witness)
      return this.tx.toRaw();
    return this.tx.toNormal();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.tx.fromRaw(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.tx.fromRaw(data);
    return this;
  }

  /**
   * Instantiate tx packet from buffer reader.
   * @param {BufferReader} br
   * @returns {TXPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate tx packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {TXPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Reject Packet
 * @extends Packet
 * @property {(Number|String)?} code - Code
 * (see {@link RejectPacket.codes}).
 * @property {String?} msg - Message.
 * @property {String?} reason - Reason.
 * @property {(Hash|Buffer)?} data - Transaction or block hash.
 */

class RejectPacket extends Packet {
  /**
   * Create reject packet.
   * @constructor
   */

  constructor(options) {
    super();

    this.cmd = 'reject';
    this.type = exports.types.REJECT;

    this.message = '';
    this.code = RejectPacket.codes.INVALID;
    this.reason = '';
    this.hash = null;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    let code = options.code;

    if (options.message)
      this.message = options.message;

    if (code != null) {
      if (typeof code === 'string')
        code = RejectPacket.codes[code.toUpperCase()];

      if (code >= RejectPacket.codes.INTERNAL)
        code = RejectPacket.codes.INVALID;

      this.code = code;
    }

    if (options.reason)
      this.reason = options.reason;

    if (options.hash)
      this.hash = options.hash;

    return this;
  }

  /**
   * Instantiate reject packet from options.
   * @param {Object} options
   * @returns {RejectPacket}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Get uint256le hash if present.
   * @returns {Hash}
   */

  rhash() {
    return this.hash ? util.revHex(this.hash) : null;
  }

  /**
   * Get symbolic code.
   * @returns {String}
   */

  getCode() {
    const code = RejectPacket.codesByVal[this.code];

    if (!code)
      return this.code.toString(10);

    return code.toLowerCase();
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += encoding.sizeVarString(this.message, 'ascii');
    size += 1;
    size += encoding.sizeVarString(this.reason, 'ascii');

    if (this.hash)
      size += 32;

    return size;
  }

  /**
   * Serialize reject packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    assert(this.message.length <= 12);
    assert(this.reason.length <= 111);

    bw.writeVarString(this.message, 'ascii');
    bw.writeU8(this.code);
    bw.writeVarString(this.reason, 'ascii');

    if (this.hash)
      bw.writeHash(this.hash);

    return bw;
  }

  /**
   * Serialize reject packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.message = br.readVarString('ascii', 12);
    this.code = br.readU8();
    this.reason = br.readVarString('ascii', 111);

    switch (this.message) {
      case 'block':
      case 'tx':
        this.hash = br.readHash('hex');
        break;
      default:
        this.hash = null;
        break;
    }

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate reject packet from buffer reader.
   * @param {BufferReader} br
   * @returns {RejectPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate reject packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {RejectPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data, enc);
  }

  /**
   * Inject properties from reason message and object.
   * @private
   * @param {Number} code
   * @param {String} reason
   * @param {String?} msg
   * @param {Hash?} hash
   */

  fromReason(code, reason, msg, hash) {
    if (typeof code === 'string')
      code = RejectPacket.codes[code.toUpperCase()];

    if (!code)
      code = RejectPacket.codes.INVALID;

    if (code >= RejectPacket.codes.INTERNAL)
      code = RejectPacket.codes.INVALID;

    this.message = '';
    this.code = code;
    this.reason = reason;

    if (msg) {
      assert(hash);
      this.message = msg;
      this.hash = hash;
    }

    return this;
  }

  /**
   * Instantiate reject packet from reason message.
   * @param {Number} code
   * @param {String} reason
   * @param {String?} msg
   * @param {Hash?} hash
   * @returns {RejectPacket}
   */

  static fromReason(code, reason, msg, hash) {
    return new this().fromReason(code, reason, msg, hash);
  }

  /**
   * Instantiate reject packet from verify error.
   * @param {VerifyError} err
   * @param {(TX|Block)?} obj
   * @returns {RejectPacket}
   */

  static fromError(err, obj) {
    return this.fromReason(err.code, err.reason, obj);
  }

  /**
   * Inspect reject packet.
   * @returns {String}
   */

  inspect() {
    const code = RejectPacket.codesByVal[this.code] || this.code;
    const hash = this.hash ? util.revHex(this.hash) : null;
    return '<Reject:'
      + ` msg=${this.message}`
      + ` code=${code}`
      + ` reason=${this.reason}`
      + ` hash=${hash}`
      + '>';
  }
}

/**
 * Reject codes. Note that `internal` and higher
 * are not meant for use on the p2p network.
 * @enum {Number}
 * @default
 */

RejectPacket.codes = {
  MALFORMED: 0x01,
  INVALID: 0x10,
  OBSOLETE: 0x11,
  DUPLICATE: 0x12,
  NONSTANDARD: 0x40,
  DUST: 0x41,
  INSUFFICIENTFEE: 0x42,
  CHECKPOINT: 0x43,
  // Internal codes (NOT FOR USE ON NETWORK)
  INTERNAL: 0x100,
  HIGHFEE: 0x101,
  ALREADYKNOWN: 0x102,
  CONFLICT: 0x103
};

/**
 * Reject codes by value.
 * @const {Object}
 */

RejectPacket.codesByVal = {
  0x01: 'MALFORMED',
  0x10: 'INVALID',
  0x11: 'OBSOLETE',
  0x12: 'DUPLICATE',
  0x40: 'NONSTANDARD',
  0x41: 'DUST',
  0x42: 'INSUFFICIENTFEE',
  0x43: 'CHECKPOINT',
  // Internal codes (NOT FOR USE ON NETWORK)
  0x100: 'INTERNAL',
  0x101: 'HIGHFEE',
  0x102: 'ALREADYKNOWN',
  0x103: 'CONFLICT'
};

/**
 * Mempool Packet
 * @extends Packet
 */

class MempoolPacket extends Packet {
  /**
   * Create a `mempool` packet.
   * @constructor
   */

  constructor() {
    super();
    this.cmd = 'mempool';
    this.type = exports.types.MEMPOOL;
  }

  /**
   * Instantiate mempool packet from buffer reader.
   * @param {BufferReader} br
   * @returns {VerackPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate mempool packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {VerackPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * FilterLoad Packet
 * @extends Packet
 */

class FilterLoadPacket extends Packet {
  /**
   * Create a `filterload` packet.
   * @constructor
   * @param {BloomFilter|null} filter
   */

  constructor(filter) {
    super();

    this.cmd = 'filterload';
    this.type = exports.types.FILTERLOAD;

    this.filter = filter || new BloomFilter();
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.filter.getSize();
  }

  /**
   * Serialize filterload packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    return this.filter.toWriter(bw);
  }

  /**
   * Serialize filterload packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.filter.toRaw();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.filter.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.filter.fromRaw(data);
    return this;
  }

  /**
   * Instantiate filterload packet from buffer reader.
   * @param {BufferReader} br
   * @returns {FilterLoadPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate filterload packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {FilterLoadPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }

  /**
   * Ensure the filter is within the size limits.
   * @returns {Boolean}
   */

  isWithinConstraints() {
    return this.filter.isWithinConstraints();
  }
}

/**
 * FilterAdd Packet
 * @extends Packet
 * @property {Buffer} data
 */

class FilterAddPacket extends Packet {
  /**
   * Create a `filteradd` packet.
   * @constructor
   * @param {Buffer?} data
   */

  constructor(data) {
    super();

    this.cmd = 'filteradd';
    this.type = exports.types.FILTERADD;

    this.data = data || DUMMY;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return encoding.sizeVarBytes(this.data);
  }

  /**
   * Serialize filteradd packet to writer.
   * @returns {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeVarBytes(this.data);
    return bw;
  }

  /**
   * Serialize filteradd packet.
   * @returns {Buffer}
   */

  toRaw() {
    const size = this.getSize();
    return this.toWriter(bio.write(size)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.data = br.readVarBytes();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate filteradd packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {FilterAddPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * FilterClear Packet
 * @extends Packet
 */

class FilterClearPacket extends Packet {
  /**
   * Create a `filterclear` packet.
   * @constructor
   */

  constructor() {
    super();
    this.cmd = 'filterclear';
    this.type = exports.types.FILTERCLEAR;
  }

  /**
   * Instantiate filterclear packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {FilterClearPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * MerkleBlock Packet
 * @extends Packet
 * @property {MerkleBlock} block
 */

class MerkleBlockPacket extends Packet {
  /**
   * Create a `merkleblock` packet.
   * @constructor
   * @param {MerkleBlock?} block
   */

  constructor(block) {
    super();

    this.cmd = 'merkleblock';
    this.type = exports.types.MERKLEBLOCK;

    this.block = block || new MerkleBlock();
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.block.getSize();
  }

  /**
   * Serialize merkleblock packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    return this.block.toWriter(bw);
  }

  /**
   * Serialize merkleblock packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.block.toRaw();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.block.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.block.fromRaw(data);
    return this;
  }

  /**
   * Instantiate merkleblock packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {MerkleBlockPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * FeeFilter Packet
 * @extends Packet
 * @property {Rate} rate
 */

class FeeFilterPacket extends Packet {
  /**
   * Create a `feefilter` packet.
   * @constructor
   * @param {Rate?} rate
   */

  constructor(rate) {
    super();

    this.cmd = 'feefilter';
    this.type = exports.types.FEEFILTER;

    this.rate = rate || 0;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 8;
  }

  /**
   * Serialize feefilter packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeI64(this.rate);
    return bw;
  }

  /**
   * Serialize feefilter packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(8)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.rate = br.readI64();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate feefilter packet from buffer reader.
   * @param {BufferReader} br
   * @returns {FeeFilterPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate feefilter packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {FeeFilterPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * SendCmpct Packet
 * @extends Packet
 * @property {Number} mode
 * @property {Number} version
 */

class SendCmpctPacket extends Packet {
  /**
   * Create a `sendcmpct` packet.
   * @constructor
   * @param {Number|null} mode
   * @param {Number|null} version
   */

  constructor(mode, version) {
    super();

    this.cmd = 'sendcmpct';
    this.type = exports.types.SENDCMPCT;

    this.mode = mode || 0;
    this.version = version || 1;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 9;
  }

  /**
   * Serialize sendcmpct packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeU8(this.mode);
    bw.writeU64(this.version);
    return bw;
  }

  /**
   * Serialize sendcmpct packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(9)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.mode = br.readU8();
    this.version = br.readU64();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate sendcmpct packet from buffer reader.
   * @param {BufferReader} br
   * @returns {SendCmpctPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate sendcmpct packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {SendCmpctPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * CmpctBlock Packet
 * @extends Packet
 * @property {Block} block
 * @property {Boolean} witness
 */

class CmpctBlockPacket extends Packet {
  /**
   * Create a `cmpctblock` packet.
   * @constructor
   * @param {Block|null} block
   * @param {Boolean|null} witness
   */

  constructor(block, witness) {
    super();

    this.cmd = 'cmpctblock';
    this.type = exports.types.CMPCTBLOCK;

    this.block = block || new bip152.CompactBlock();
    this.witness = witness || false;
  }

  /**
   * Serialize cmpctblock packet.
   * @returns {Buffer}
   */

  getSize() {
    if (this.witness)
      return this.block.getSize(true);
    return this.block.getSize(false);
  }

  /**
   * Serialize cmpctblock packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.witness)
      return this.block.toWriter(bw);
    return this.block.toNormalWriter(bw);
  }

  /**
   * Serialize cmpctblock packet.
   * @returns {Buffer}
   */

  toRaw() {
    if (this.witness)
      return this.block.toRaw();
    return this.block.toNormal();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.block.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.block.fromRaw(data);
    return this;
  }

  /**
   * Instantiate cmpctblock packet from buffer reader.
   * @param {BufferReader} br
   * @returns {CmpctBlockPacket}
   */

  static fromReader(br) {
    return new this().fromRaw(br);
  }

  /**
   * Instantiate cmpctblock packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {CmpctBlockPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * GetBlockTxn Packet
 * @extends Packet
 * @property {TXRequest} request
 */

class GetBlockTxnPacket extends Packet {
  /**
   * Create a `getblocktxn` packet.
   * @constructor
   * @param {TXRequest?} request
   */

  constructor(request) {
    super();

    this.cmd = 'getblocktxn';
    this.type = exports.types.GETBLOCKTXN;

    this.request = request || new bip152.TXRequest();
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.request.getSize();
  }

  /**
   * Serialize getblocktxn packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    return this.request.toWriter(bw);
  }

  /**
   * Serialize getblocktxn packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.request.toRaw();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.request.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.request.fromRaw(data);
    return this;
  }

  /**
   * Instantiate getblocktxn packet from buffer reader.
   * @param {BufferReader} br
   * @returns {GetBlockTxnPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate getblocktxn packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {GetBlockTxnPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * BlockTxn Packet
 * @extends Packet
 * @property {TXResponse} response
 * @property {Boolean} witness
 */

class BlockTxnPacket extends Packet {
  /**
   * Create a `blocktxn` packet.
   * @constructor
   * @param {TXResponse?} response
   * @param {Boolean?} witness
   */

  constructor(response, witness) {
    super();

    this.cmd = 'blocktxn';
    this.type = exports.types.BLOCKTXN;

    this.response = response || new bip152.TXResponse();
    this.witness = witness || false;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    if (this.witness)
      return this.response.getSize(true);
    return this.response.getSize(false);
  }

  /**
   * Serialize blocktxn packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    if (this.witness)
      return this.response.toWriter(bw);
    return this.response.toNormalWriter(bw);
  }

  /**
   * Serialize blocktxn packet.
   * @returns {Buffer}
   */

  toRaw() {
    if (this.witness)
      return this.response.toRaw();
    return this.response.toNormal();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.response.fromReader(br);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    this.response.fromRaw(data);
    return this;
  }

  /**
   * Instantiate blocktxn packet from buffer reader.
   * @param {BufferReader} br
   * @returns {BlockTxnPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate blocktxn packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {BlockTxnPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Encinit Packet
 * @extends Packet
 * @property {Buffer} publicKey
 * @property {Number} cipher
 */

class EncinitPacket extends Packet {
  /**
   * Create an `encinit` packet.
   * @constructor
   * @param {Buffer|null} publicKey
   * @param {Number|null} cipher
   */

  constructor(publicKey, cipher) {
    super();

    this.cmd = 'encinit';
    this.type = exports.types.ENCINIT;

    this.publicKey = publicKey || common.ZERO_KEY;
    this.cipher = cipher || 0;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 34;
  }

  /**
   * Serialize encinit packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.publicKey);
    bw.writeU8(this.cipher);
    return bw;
  }

  /**
   * Serialize encinit packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.toWriter(bio.write(34)).render();
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.publicKey = br.readBytes(33);
    this.cipher = br.readU8();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate getblocks packet from buffer reader.
   * @param {BufferReader} br
   * @returns {EncinitPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate getblocks packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {EncinitPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Encack Packet
 * @extends Packet
 * @property {Buffer} publicKey
 */

class EncackPacket extends Packet {
  /**
   * Create a `encack` packet.
   * @constructor
   * @param {Buffer?} publicKey
   */

  constructor(publicKey) {
    super();

    this.cmd = 'encack';
    this.type = exports.types.ENCACK;

    this.publicKey = publicKey || common.ZERO_KEY;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 33;
  }

  /**
   * Serialize encack packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.publicKey);
    return bw;
  }

  /**
   * Serialize encack packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.publicKey;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.publicKey = br.readBytes(33);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate encack packet from buffer reader.
   * @param {BufferReader} br
   * @returns {EncackPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate encack packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {EncackPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * AuthChallenge Packet
 * @extends Packet
 * @property {Buffer} hash
 */

class AuthChallengePacket extends Packet {
  /**
   * Create an `authchallenge` packet.
   * @constructor
   * @param {Buffer?} hash
   */

  constructor(hash) {
    super();

    this.cmd = 'authchallenge';
    this.type = exports.types.AUTHCHALLENGE;

    this.hash = hash || consensus.ZERO_HASH;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 32;
  }

  /**
   * Serialize authchallenge packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.hash);
    return bw;
  }

  /**
   * Serialize authchallenge packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.hash;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.hash = br.readHash();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate authchallenge packet from buffer reader.
   * @param {BufferReader} br
   * @returns {AuthChallengePacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate authchallenge packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {AuthChallengePacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * AuthReply Packet
 * @extends Packet
 * @property {Buffer} signature
 */

class AuthReplyPacket extends Packet {
  /**
   * Create a `authreply` packet.
   * @constructor
   * @param {Buffer?} signature
   */

  constructor(signature) {
    super();

    this.cmd = 'authreply';
    this.type = exports.types.AUTHREPLY;

    this.signature = signature || common.ZERO_SIG;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 64;
  }

  /**
   * Serialize authreply packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.signature);
    return bw;
  }

  /**
   * Serialize authreply packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.signature;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.signature = br.readBytes(64);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate authreply packet from buffer reader.
   * @param {BufferReader} br
   * @returns {AuthReplyPacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate authreply packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {AuthReplyPacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * AuthPropose Packet
 * @extends Packet
 * @property {Hash} hash
 */

class AuthProposePacket extends Packet {
  /**
   * Create a `authpropose` packet.
   * @constructor
   * @param {Hash?} hash
   */

  constructor(hash) {
    super();

    this.cmd = 'authpropose';
    this.type = exports.types.AUTHPROPOSE;

    this.hash = hash || consensus.ZERO_HASH;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 32;
  }

  /**
   * Serialize authpropose packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.hash);
    return bw;
  }

  /**
   * Serialize authpropose packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.hash;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  fromReader(br) {
    this.hash = br.readHash();
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(data) {
    return this.fromReader(bio.read(data));
  }

  /**
   * Instantiate authpropose packet from buffer reader.
   * @param {BufferReader} br
   * @returns {AuthProposePacket}
   */

  static fromReader(br) {
    return new this().fromReader(br);
  }

  /**
   * Instantiate authpropose packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {AuthProposePacket}
   */

  static fromRaw(data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(data);
  }
}

/**
 * Unknown Packet
 * @extends Packet
 * @property {String} cmd
 * @property {Buffer} data
 */

class UnknownPacket extends Packet {
  /**
   * Create an unknown packet.
   * @constructor
   * @param {String|null} cmd
   * @param {Buffer|null} data
   */

  constructor(cmd, data) {
    super();

    this.cmd = cmd;
    this.type = exports.types.UNKNOWN;
    this.data = data;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.data.length;
  }

  /**
   * Serialize unknown packet to writer.
   * @param {BufferWriter} bw
   */

  toWriter(bw) {
    bw.writeBytes(this.data);
    return bw;
  }

  /**
   * Serialize unknown packet.
   * @returns {Buffer}
   */

  toRaw() {
    return this.data;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  fromRaw(cmd, data) {
    assert(Buffer.isBuffer(data));
    this.cmd = cmd;
    this.data = data;
    return this;
  }

  /**
   * Instantiate unknown packet from serialized data.
   * @param {Buffer} data
   * @param {String?} enc
   * @returns {UnknownPacket}
   */

  static fromRaw(cmd, data, enc) {
    if (typeof data === 'string')
      data = Buffer.from(data, enc);
    return new this().fromRaw(cmd, data);
  }
}

/**
 * Parse a payload.
 * @param {String} cmd
 * @param {Buffer} data
 * @returns {Packet}
 */

exports.fromRaw = function fromRaw(cmd, data) {
  switch (cmd) {
    case 'version':
      return VersionPacket.fromRaw(data);
    case 'verack':
      return VerackPacket.fromRaw(data);
    case 'ping':
      return PingPacket.fromRaw(data);
    case 'pong':
      return PongPacket.fromRaw(data);
    case 'getaddr':
      return GetAddrPacket.fromRaw(data);
    case 'addr':
      return AddrPacket.fromRaw(data);
    case 'inv':
      return InvPacket.fromRaw(data);
    case 'getdata':
      return GetDataPacket.fromRaw(data);
    case 'notfound':
      return NotFoundPacket.fromRaw(data);
    case 'getblocks':
      return GetBlocksPacket.fromRaw(data);
    case 'getheaders':
      return GetHeadersPacket.fromRaw(data);
    case 'headers':
      return HeadersPacket.fromRaw(data);
    case 'sendheaders':
      return SendHeadersPacket.fromRaw(data);
    case 'block':
      return BlockPacket.fromRaw(data);
    case 'tx':
      return TXPacket.fromRaw(data);
    case 'reject':
      return RejectPacket.fromRaw(data);
    case 'mempool':
      return MempoolPacket.fromRaw(data);
    case 'filterload':
      return FilterLoadPacket.fromRaw(data);
    case 'filteradd':
      return FilterAddPacket.fromRaw(data);
    case 'filterclear':
      return FilterClearPacket.fromRaw(data);
    case 'merkleblock':
      return MerkleBlockPacket.fromRaw(data);
    case 'feefilter':
      return FeeFilterPacket.fromRaw(data);
    case 'sendcmpct':
      return SendCmpctPacket.fromRaw(data);
    case 'cmpctblock':
      return CmpctBlockPacket.fromRaw(data);
    case 'getblocktxn':
      return GetBlockTxnPacket.fromRaw(data);
    case 'blocktxn':
      return BlockTxnPacket.fromRaw(data);
    case 'encinit':
      return EncinitPacket.fromRaw(data);
    case 'encack':
      return EncackPacket.fromRaw(data);
    case 'authchallenge':
      return AuthChallengePacket.fromRaw(data);
    case 'authreply':
      return AuthReplyPacket.fromRaw(data);
    case 'authpropose':
      return AuthProposePacket.fromRaw(data);
    default:
      return UnknownPacket.fromRaw(cmd, data);
  }
};

/*
 * Expose
 */

exports.Packet = Packet;
exports.VersionPacket = VersionPacket;
exports.VerackPacket = VerackPacket;
exports.PingPacket = PingPacket;
exports.PongPacket = PongPacket;
exports.GetAddrPacket = GetAddrPacket;
exports.AddrPacket = AddrPacket;
exports.InvPacket = InvPacket;
exports.GetDataPacket = GetDataPacket;
exports.NotFoundPacket = NotFoundPacket;
exports.GetBlocksPacket = GetBlocksPacket;
exports.GetHeadersPacket = GetHeadersPacket;
exports.HeadersPacket = HeadersPacket;
exports.SendHeadersPacket = SendHeadersPacket;
exports.BlockPacket = BlockPacket;
exports.TXPacket = TXPacket;
exports.RejectPacket = RejectPacket;
exports.MempoolPacket = MempoolPacket;
exports.FilterLoadPacket = FilterLoadPacket;
exports.FilterAddPacket = FilterAddPacket;
exports.FilterClearPacket = FilterClearPacket;
exports.MerkleBlockPacket = MerkleBlockPacket;
exports.FeeFilterPacket = FeeFilterPacket;
exports.SendCmpctPacket = SendCmpctPacket;
exports.CmpctBlockPacket = CmpctBlockPacket;
exports.GetBlockTxnPacket = GetBlockTxnPacket;
exports.BlockTxnPacket = BlockTxnPacket;
exports.EncinitPacket = EncinitPacket;
exports.EncackPacket = EncackPacket;
exports.AuthChallengePacket = AuthChallengePacket;
exports.AuthReplyPacket = AuthReplyPacket;
exports.AuthProposePacket = AuthProposePacket;
exports.UnknownPacket = UnknownPacket;

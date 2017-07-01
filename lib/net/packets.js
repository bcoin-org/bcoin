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

const common = require('./common');
const util = require('../utils/util');
const assert = require('assert');
const Bloom = require('../utils/bloom');
const bip152 = require('./bip152');
const NetAddress = require('../primitives/netaddress');
const Headers = require('../primitives/headers');
const InvItem = require('../primitives/invitem');
const MemBlock = require('../primitives/memblock');
const MerkleBlock = require('../primitives/merkleblock');
const TX = require('../primitives/tx');
const BufferReader = require('../utils/reader');
const StaticWriter = require('../utils/staticwriter');
const encoding = require('../utils/encoding');
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
  INTERNAL: 100,
  DATA: 101
};

/**
 * Packet types by value.
 * @const {Object}
 * @default
 */

exports.typesByVal = util.revMap(exports.types);

/**
 * Base Packet
 * @constructor
 */

function Packet() {}

Packet.prototype.type = -1;
Packet.prototype.cmd = '';

/**
 * Get serialization size.
 * @returns {Number}
 */

Packet.prototype.getSize = function getSize() {
  return 0;
};

/**
 * Serialize packet to writer.
 * @param {BufferWriter} bw
 */

Packet.prototype.toWriter = function toWriter(bw) {
  return bw;
};

/**
 * Serialize packet.
 * @returns {Buffer}
 */

Packet.prototype.toRaw = function toRaw() {
  return DUMMY;
};

/**
 * Inject properties from buffer reader.
 * @param {BufferReader} br
 */

Packet.prototype.fromReader = function fromReader(br) {
  return this;
};

/**
 * Inject properties from serialized data.
 * @param {Buffer} data
 */

Packet.prototype.fromRaw = function fromRaw(data) {
  return this;
};

/**
 * Version Packet
 * @constructor
 * @param {Object?} options
 * @param {Number} options.version - Protocol version.
 * @param {Number} options.services - Service bits.
 * @param {Number} options.ts - Timestamp of discovery.
 * @param {NetAddress} options.local - Our address.
 * @param {NetAddress} options.remote - Their address.
 * @param {Buffer} options.nonce
 * @param {String} options.agent - User agent string.
 * @param {Number} options.height - Chain height.
 * @param {Boolean} options.noRelay - Whether transactions
 * should be relayed immediately.
 * @property {Number} version - Protocol version.
 * @property {Number} services - Service bits.
 * @property {Number} ts - Timestamp of discovery.
 * @property {NetAddress} local - Our address.
 * @property {NetAddress} remote - Their address.
 * @property {Buffer} nonce
 * @property {String} agent - User agent string.
 * @property {Number} height - Chain height.
 * @property {Boolean} noRelay - Whether transactions
 * should be relayed immediately.
 */

function VersionPacket(options) {
  if (!(this instanceof VersionPacket))
    return new VersionPacket(options);

  Packet.call(this);

  this.version = common.PROTOCOL_VERSION;
  this.services = common.LOCAL_SERVICES;
  this.ts = util.now();
  this.remote = new NetAddress();
  this.local = new NetAddress();
  this.nonce = encoding.ZERO_U64;
  this.agent = common.USER_AGENT;
  this.height = 0;
  this.noRelay = false;

  if (options)
    this.fromOptions(options);
}

util.inherits(VersionPacket, Packet);

VersionPacket.prototype.cmd = 'version';
VersionPacket.prototype.type = exports.types.VERSION;

/**
 * Inject properties from options.
 * @private
 * @param {Object} options
 */

VersionPacket.prototype.fromOptions = function fromOptions(options) {
  if (options.version != null)
    this.version = options.version;

  if (options.services != null)
    this.services = options.services;

  if (options.ts != null)
    this.ts = options.ts;

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
};

/**
 * Instantiate version packet from options.
 * @param {Object} options
 * @returns {VersionPacket}
 */

VersionPacket.fromOptions = function fromOptions(options) {
  return new VersionPacket().fromOptions(options);
};

/**
 * Get serialization size.
 * @returns {Number}
 */

VersionPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += 20;
  size += this.remote.getSize(false);
  size += this.local.getSize(false);
  size += 8;
  size += encoding.sizeVarString(this.agent, 'ascii');
  size += 5;
  return size;
};

/**
 * Write version packet to buffer writer.
 * @param {BufferWriter} bw
 */

VersionPacket.prototype.toWriter = function toWriter(bw) {
  bw.write32(this.version);
  bw.writeU32(this.services);
  bw.writeU32(0);
  bw.write64(this.ts);
  this.remote.toWriter(bw, false);
  this.local.toWriter(bw, false);
  bw.writeBytes(this.nonce);
  bw.writeVarString(this.agent, 'ascii');
  bw.write32(this.height);
  bw.writeU8(this.noRelay ? 0 : 1);
  return bw;
};

/**
 * Serialize version packet.
 * @returns {Buffer}
 */

VersionPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

VersionPacket.prototype.fromReader = function fromReader(br) {
  this.version = br.read32();
  this.services = br.readU32();

  // Note: hi service bits
  // are currently unused.
  br.readU32();

  this.ts = br.read53();
  this.remote.fromReader(br, false);

  if (br.left() > 0) {
    this.local.fromReader(br, false);
    this.nonce = br.readBytes(8);
  }

  if (br.left() > 0)
    this.agent = br.readVarString('ascii', 256);

  if (br.left() > 0)
    this.height = br.read32();

  if (br.left() > 0)
    this.noRelay = br.readU8() === 0;

  if (this.version === 10300)
    this.version = 300;

  assert(this.version >= 0, 'Version is negative.');
  assert(this.ts >= 0, 'Timestamp is negative.');

  // No idea why so many peers do this.
  if (this.height < 0)
    this.height = 0;

  return this;
};

/**
 * Instantiate version packet from buffer reader.
 * @param {BufferReader} br
 * @returns {VersionPacket}
 */

VersionPacket.fromReader = function fromReader(br) {
  return new VersionPacket().fromReader(br);
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

VersionPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate version packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VersionPacket}
 */

VersionPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new VersionPacket().fromRaw(data, enc);
};

/**
 * Represents a `verack` packet.
 * @constructor
 */

function VerackPacket() {
  if (!(this instanceof VerackPacket))
    return new VerackPacket();

  Packet.call(this);
}

util.inherits(VerackPacket, Packet);

VerackPacket.prototype.cmd = 'verack';
VerackPacket.prototype.type = exports.types.VERACK;

/**
 * Instantiate verack packet from serialized data.
 * @param {BufferReader} br
 * @returns {VerackPacket}
 */

VerackPacket.fromReader = function fromReader(br) {
  return new VerackPacket().fromReader(br);
};

/**
 * Instantiate verack packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VerackPacket}
 */

VerackPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new VerackPacket().fromRaw(data);
};

/**
 * Represents a `ping` packet.
 * @constructor
 * @param {BN?} nonce
 * @property {BN|null} nonce
 */

function PingPacket(nonce) {
  if (!(this instanceof PingPacket))
    return new PingPacket(nonce);

  Packet.call(this);

  this.nonce = nonce || null;
}

util.inherits(PingPacket, Packet);

PingPacket.prototype.cmd = 'ping';
PingPacket.prototype.type = exports.types.PING;

/**
 * Get serialization size.
 * @returns {Number}
 */

PingPacket.prototype.getSize = function getSize() {
  return this.nonce ? 8 : 0;
};

/**
 * Serialize ping packet.
 * @returns {Buffer}
 */

PingPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Serialize ping packet to writer.
 * @param {BufferWriter} bw
 */

PingPacket.prototype.toWriter = function toWriter(bw) {
  if (this.nonce)
    bw.writeBytes(this.nonce);
  return bw;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

PingPacket.prototype.fromReader = function fromReader(br) {
  if (br.left() >= 8)
    this.nonce = br.readBytes(8);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

PingPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate ping packet from serialized data.
 * @param {BufferReader} br
 * @returns {PingPacket}
 */

PingPacket.fromReader = function fromReader(br) {
  return new PingPacket().fromRaw(br);
};

/**
 * Instantiate ping packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {PingPacket}
 */

PingPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new PingPacket().fromRaw(data);
};

/**
 * Represents a `pong` packet.
 * @constructor
 * @param {BN?} nonce
 * @property {BN} nonce
 */

function PongPacket(nonce) {
  if (!(this instanceof PongPacket))
    return new PongPacket(nonce);

  Packet.call(this);

  this.nonce = nonce || encoding.ZERO_U64;
}

util.inherits(PongPacket, Packet);

PongPacket.prototype.cmd = 'pong';
PongPacket.prototype.type = exports.types.PONG;

/**
 * Get serialization size.
 * @returns {Number}
 */

PongPacket.prototype.getSize = function getSize() {
  return 8;
};

/**
 * Serialize pong packet to writer.
 * @param {BufferWriter} bw
 */

PongPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.nonce);
  return bw;
};

/**
 * Serialize pong packet.
 * @returns {Buffer}
 */

PongPacket.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(8)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

PongPacket.prototype.fromReader = function fromReader(br) {
  this.nonce = br.readBytes(8);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

PongPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate pong packet from buffer reader.
 * @param {BufferReader} br
 * @returns {VerackPacket}
 */

PongPacket.fromReader = function fromReader(br) {
  return new PongPacket().fromReader(br);
};

/**
 * Instantiate pong packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VerackPacket}
 */

PongPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new PongPacket().fromRaw(data);
};

/**
 * Represents a `getaddr` packet.
 * @constructor
 */

function GetAddrPacket() {
  if (!(this instanceof GetAddrPacket))
    return new GetAddrPacket();

  Packet.call(this);
}

util.inherits(GetAddrPacket, Packet);

GetAddrPacket.prototype.cmd = 'getaddr';
GetAddrPacket.prototype.type = exports.types.GETADDR;

/**
 * Instantiate getaddr packet from buffer reader.
 * @param {BufferReader} br
 * @returns {GetAddrPacket}
 */

GetAddrPacket.fromReader = function fromReader(br) {
  return new GetAddrPacket().fromReader(br);
};

/**
 * Instantiate getaddr packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetAddrPacket}
 */

GetAddrPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new GetAddrPacket().fromRaw(data);
};

/**
 * Represents a `addr` packet.
 * @constructor
 * @param {(NetAddress[])?} items
 * @property {NetAddress[]} items
 */

function AddrPacket(items) {
  if (!(this instanceof AddrPacket))
    return new AddrPacket(items);

  Packet.call(this);

  this.items = items || [];
}

util.inherits(AddrPacket, Packet);

AddrPacket.prototype.cmd = 'addr';
AddrPacket.prototype.type = exports.types.ADDR;

/**
 * Get serialization size.
 * @returns {Number}
 */

AddrPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarint(this.items.length);
  size += 30 * this.items.length;
  return size;
};

/**
 * Serialize addr packet to writer.
 * @param {BufferWriter} bw
 */

AddrPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarint(this.items.length);

  for (let item of this.items)
    item.toWriter(bw, true);

  return bw;
};

/**
 * Serialize addr packet.
 * @returns {Buffer}
 */

AddrPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AddrPacket.prototype.fromRaw = function fromRaw(data) {
  let br = new BufferReader(data);
  let count = br.readVarint();

  for (let i = 0; i < count; i++)
    this.items.push(NetAddress.fromReader(br, true));

  return this;
};

/**
 * Instantiate addr packet from Buffer reader.
 * @param {BufferReader} br
 * @returns {AddrPacket}
 */

AddrPacket.fromReader = function fromReader(br) {
  return new AddrPacket().fromReader(br);
};

/**
 * Instantiate addr packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {AddrPacket}
 */

AddrPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new AddrPacket().fromRaw(data);
};

/**
 * Represents a `inv` packet.
 * @constructor
 * @param {(InvItem[])?} items
 * @property {InvItem[]} items
 */

function InvPacket(items) {
  if (!(this instanceof InvPacket))
    return new InvPacket(items);

  Packet.call(this);

  this.items = items || [];
}

util.inherits(InvPacket, Packet);

InvPacket.prototype.cmd = 'inv';
InvPacket.prototype.type = exports.types.INV;

/**
 * Get serialization size.
 * @returns {Number}
 */

InvPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += encoding.sizeVarint(this.items.length);
  size += 36 * this.items.length;
  return size;
};

/**
 * Serialize inv packet to writer.
 * @param {Buffer} bw
 */

InvPacket.prototype.toWriter = function toWriter(bw) {
  assert(this.items.length <= 50000);

  bw.writeVarint(this.items.length);

  for (let item of this.items)
    item.toWriter(bw);

  return bw;
};

/**
 * Serialize inv packet.
 * @returns {Buffer}
 */

InvPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

InvPacket.prototype.fromReader = function fromReader(br) {
  let count = br.readVarint();

  assert(count <= 50000, 'Inv item count too high.');

  for (let i = 0; i < count; i++)
    this.items.push(InvItem.fromReader(br));

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

InvPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate inv packet from buffer reader.
 * @param {BufferReader} br
 * @returns {InvPacket}
 */

InvPacket.fromReader = function fromReader(br) {
  return new InvPacket().fromRaw(br);
};

/**
 * Instantiate inv packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {InvPacket}
 */

InvPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new InvPacket().fromRaw(data);
};

/**
 * Represents a `getdata` packet.
 * @extends InvPacket
 * @constructor
 * @param {(InvItem[])?} items
 */

function GetDataPacket(items) {
  if (!(this instanceof GetDataPacket))
    return new GetDataPacket(items);

  InvPacket.call(this, items);
}

util.inherits(GetDataPacket, InvPacket);

GetDataPacket.prototype.cmd = 'getdata';
GetDataPacket.prototype.type = exports.types.GETDATA;

/**
 * Instantiate getdata packet from buffer reader.
 * @param {BufferReader} br
 * @returns {GetDataPacket}
 */

GetDataPacket.fromReader = function fromReader(br) {
  return new GetDataPacket().fromReader(br);
};

/**
 * Instantiate getdata packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetDataPacket}
 */

GetDataPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new GetDataPacket().fromRaw(data);
};

/**
 * Represents a `notfound` packet.
 * @extends InvPacket
 * @constructor
 * @param {(InvItem[])?} items
 */

function NotFoundPacket(items) {
  if (!(this instanceof NotFoundPacket))
    return new NotFoundPacket(items);

  InvPacket.call(this, items);
}

util.inherits(NotFoundPacket, InvPacket);

NotFoundPacket.prototype.cmd = 'notfound';
NotFoundPacket.prototype.type = exports.types.NOTFOUND;

/**
 * Instantiate notfound packet from buffer reader.
 * @param {BufferReader} br
 * @returns {NotFoundPacket}
 */

NotFoundPacket.fromReader = function fromReader(br) {
  return new NotFoundPacket().fromReader(br);
};

/**
 * Instantiate notfound packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {NotFoundPacket}
 */

NotFoundPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new NotFoundPacket().fromRaw(data);
};

/**
 * Represents a `getblocks` packet.
 * @constructor
 * @param {Hash[]} locator
 * @param {Hash?} stop
 * @property {Hash[]} locator
 * @property {Hash|null} stop
 */

function GetBlocksPacket(locator, stop) {
  if (!(this instanceof GetBlocksPacket))
    return new GetBlocksPacket(locator, stop);

  Packet.call(this);

  this.version = common.PROTOCOL_VERSION;
  this.locator = locator || [];
  this.stop = stop || null;
}

util.inherits(GetBlocksPacket, Packet);

GetBlocksPacket.prototype.cmd = 'getblocks';
GetBlocksPacket.prototype.type = exports.types.GETBLOCKS;

/**
 * Get serialization size.
 * @returns {Number}
 */

GetBlocksPacket.prototype.getSize = function getSize() {
  let size = 0;
  size += 4;
  size += encoding.sizeVarint(this.locator.length);
  size += 32 * this.locator.length;
  size += 32;
  return size;
};

/**
 * Serialize getblocks packet to writer.
 * @param {BufferWriter} bw
 */

GetBlocksPacket.prototype.toWriter = function toWriter(bw) {
  assert(this.locator.length <= 50000, 'Too many block hashes.');

  bw.writeU32(this.version);
  bw.writeVarint(this.locator.length);

  for (let hash of this.locator)
    bw.writeHash(hash);

  bw.writeHash(this.stop || encoding.ZERO_HASH);

  return bw;
};

/**
 * Serialize getblocks packet.
 * @returns {Buffer}
 */

GetBlocksPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

GetBlocksPacket.prototype.fromReader = function fromReader(br) {
  let count;

  this.version = br.readU32();

  count = br.readVarint();

  assert(count <= 50000, 'Too many block hashes.');

  for (let i = 0; i < count; i++)
    this.locator.push(br.readHash('hex'));

  this.stop = br.readHash('hex');

  if (this.stop === encoding.NULL_HASH)
    this.stop = null;

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

GetBlocksPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate getblocks packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlocksPacket}
 */

GetBlocksPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new GetBlocksPacket().fromRaw(data);
};

/**
 * Represents a `getheaders` packet.
 * @extends GetBlocksPacket
 * @constructor
 * @param {Hash[]} locator
 * @param {Hash?} stop
 */

function GetHeadersPacket(locator, stop) {
  if (!(this instanceof GetHeadersPacket))
    return new GetHeadersPacket(locator, stop);

  GetBlocksPacket.call(this, locator, stop);
}

util.inherits(GetHeadersPacket, GetBlocksPacket);

GetHeadersPacket.prototype.cmd = 'getheaders';
GetHeadersPacket.prototype.type = exports.types.GETHEADERS;

/**
 * Instantiate getheaders packet from buffer reader.
 * @param {BufferReader} br
 * @returns {GetHeadersPacket}
 */

GetHeadersPacket.fromReader = function fromReader(br) {
  return new GetHeadersPacket().fromReader(br);
};

/**
 * Instantiate getheaders packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetHeadersPacket}
 */

GetHeadersPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new GetHeadersPacket().fromRaw(data);
};

/**
 * Represents a `headers` packet.
 * @constructor
 * @param {(Headers[])?} items
 * @property {Headers[]} items
 */

function HeadersPacket(items) {
  if (!(this instanceof HeadersPacket))
    return new HeadersPacket(items);

  Packet.call(this);

  this.items = items || [];
}

util.inherits(HeadersPacket, Packet);

HeadersPacket.prototype.cmd = 'headers';
HeadersPacket.prototype.type = exports.types.HEADERS;

/**
 * Get serialization size.
 * @returns {Number}
 */

HeadersPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += encoding.sizeVarint(this.items.length);

  for (let item of this.items)
    size += item.getSize();

  return size;
};

/**
 * Serialize headers packet to writer.
 * @param {BufferWriter} bw
 */

HeadersPacket.prototype.toWriter = function toWriter(bw) {
  assert(this.items.length <= 2000, 'Too many headers.');

  bw.writeVarint(this.items.length);

  for (let item of this.items)
    item.toWriter(bw);

  return bw;
};

/**
 * Serialize headers packet.
 * @returns {Buffer}
 */

HeadersPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

HeadersPacket.prototype.fromReader = function fromReader(br) {
  let count = br.readVarint();

  assert(count <= 2000, 'Too many headers.');

  for (let i = 0; i < count; i++)
    this.items.push(Headers.fromReader(br));

  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

HeadersPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate headers packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VerackPacket}
 */

HeadersPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new HeadersPacket().fromRaw(data);
};

/**
 * Represents a `sendheaders` packet.
 * @constructor
 */

function SendHeadersPacket() {
  if (!(this instanceof SendHeadersPacket))
    return new SendHeadersPacket();

  Packet.call(this);
}

util.inherits(SendHeadersPacket, Packet);

SendHeadersPacket.prototype.cmd = 'sendheaders';
SendHeadersPacket.prototype.type = exports.types.SENDHEADERS;

/**
 * Instantiate sendheaders packet from buffer reader.
 * @param {BufferReader} br
 * @returns {SendHeadersPacket}
 */

SendHeadersPacket.fromReader = function fromReader(br) {
  return new SendHeadersPacket().fromReader(br);
};

/**
 * Instantiate sendheaders packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {SendHeadersPacket}
 */

SendHeadersPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new SendHeadersPacket().fromRaw(data);
};

/**
 * Represents a `block` packet.
 * @constructor
 * @param {Block|null} block
 * @param {Boolean?} witness
 * @property {Block} block
 * @property {Boolean} witness
 */

function BlockPacket(block, witness) {
  if (!(this instanceof BlockPacket))
    return new BlockPacket(block, witness);

  Packet.call(this);

  this.block = block || new MemBlock();
  this.witness = witness || false;
}

util.inherits(BlockPacket, Packet);

BlockPacket.prototype.cmd = 'block';
BlockPacket.prototype.type = exports.types.BLOCK;

/**
 * Get serialization size.
 * @returns {Number}
 */

BlockPacket.prototype.getSize = function getSize() {
  if (this.witness)
    return this.block.getSize();
  return this.block.getBaseSize();
};

/**
 * Serialize block packet to writer.
 * @param {BufferWriter} bw
 */

BlockPacket.prototype.toWriter = function toWriter(bw) {
  if (this.witness)
    return this.block.toWriter(bw);
  return this.block.toNormalWriter(bw);
};

/**
 * Serialize block packet.
 * @returns {Buffer}
 */

BlockPacket.prototype.toRaw = function toRaw() {
  if (this.witness)
    return this.block.toRaw();
  return this.block.toNormal();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

BlockPacket.prototype.fromReader = function fromReader(br) {
  this.block.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

BlockPacket.prototype.fromRaw = function fromRaw(data) {
  this.block.fromRaw(data);
  return this;
};

/**
 * Instantiate block packet from buffer reader.
 * @param {BufferReader} br
 * @returns {BlockPacket}
 */

BlockPacket.fromReader = function fromReader(br) {
  return new BlockPacket().fromReader(br);
};

/**
 * Instantiate block packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {BlockPacket}
 */

BlockPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new BlockPacket().fromRaw(data);
};

/**
 * Represents a `tx` packet.
 * @constructor
 * @param {TX|null} tx
 * @param {Boolean?} witness
 * @property {TX} block
 * @property {Boolean} witness
 */

function TXPacket(tx, witness) {
  if (!(this instanceof TXPacket))
    return new TXPacket(tx, witness);

  Packet.call(this);

  this.tx = tx || new TX();
  this.witness = witness || false;
}

util.inherits(TXPacket, Packet);

TXPacket.prototype.cmd = 'tx';
TXPacket.prototype.type = exports.types.TX;

/**
 * Get serialization size.
 * @returns {Number}
 */

TXPacket.prototype.getSize = function getSize() {
  if (this.witness)
    return this.tx.getSize();
  return this.tx.getBaseSize();
};

/**
 * Serialize tx packet to writer.
 * @param {BufferWriter} bw
 */

TXPacket.prototype.toWriter = function toWriter(bw) {
  if (this.witness)
    return this.tx.toWriter(bw);
  return this.tx.toNormalWriter(bw);
};

/**
 * Serialize tx packet.
 * @returns {Buffer}
 */

TXPacket.prototype.toRaw = function toRaw() {
  if (this.witness)
    return this.tx.toRaw();
  return this.tx.toNormal();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

TXPacket.prototype.fromReader = function fromReader(br) {
  this.tx.fromRaw(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

TXPacket.prototype.fromRaw = function fromRaw(data) {
  this.tx.fromRaw(data);
  return this;
};

/**
 * Instantiate tx packet from buffer reader.
 * @param {BufferReader} br
 * @returns {TXPacket}
 */

TXPacket.fromReader = function fromReader(br) {
  return new TXPacket().fromReader(br);
};

/**
 * Instantiate tx packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {TXPacket}
 */

TXPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new TXPacket().fromRaw(data);
};

/**
 * Reject Packet
 * @constructor
 * @property {(Number|String)?} code - Code
 * (see {@link RejectPacket.codes}).
 * @property {String?} msg - Message.
 * @property {String?} reason - Reason.
 * @property {(Hash|Buffer)?} data - Transaction or block hash.
 */

function RejectPacket(options) {
  if (!(this instanceof RejectPacket))
    return new RejectPacket(options);

  Packet.call(this);

  this.message = '';
  this.code = RejectPacket.codes.INVALID;
  this.reason = '';
  this.hash = null;

  if (options)
    this.fromOptions(options);
}

util.inherits(RejectPacket, Packet);

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
  HIGHFEE: 0x100,
  ALREADYKNOWN: 0x101,
  CONFLICT: 0x102
};

/**
 * Reject codes by value.
 * @const {RevMap}
 */

RejectPacket.codesByVal = util.revMap(RejectPacket.codes);

RejectPacket.prototype.cmd = 'reject';
RejectPacket.prototype.type = exports.types.REJECT;

/**
 * Inject properties from options object.
 * @private
 * @param {Object} options
 */

RejectPacket.prototype.fromOptions = function fromOptions(options) {
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
};

/**
 * Instantiate reject packet from options.
 * @param {Object} options
 * @returns {RejectPacket}
 */

RejectPacket.fromOptions = function fromOptions(options) {
  return new RejectPacket().fromOptions(options);
};

/**
 * Get uint256le hash if present.
 * @returns {Hash}
 */

RejectPacket.prototype.rhash = function rhash() {
  return this.hash ? util.revHex(this.hash) : null;
};

/**
 * Get symbolic code.
 * @returns {String}
 */

RejectPacket.prototype.getCode = function getCode() {
  let code = RejectPacket.codesByVal[this.code];

  if (!code)
    return this.code + '';

  return code.toLowerCase();
};

/**
 * Get serialization size.
 * @returns {Number}
 */

RejectPacket.prototype.getSize = function getSize() {
  let size = 0;

  size += encoding.sizeVarString(this.message, 'ascii');
  size += 1;
  size += encoding.sizeVarString(this.reason, 'ascii');

  if (this.hash)
    size += 32;

  return size;
};

/**
 * Serialize reject packet to writer.
 * @param {BufferWriter} bw
 */

RejectPacket.prototype.toWriter = function toWriter(bw) {
  assert(this.message.length <= 12);
  assert(this.reason.length <= 111);

  bw.writeVarString(this.message, 'ascii');
  bw.writeU8(this.code);
  bw.writeVarString(this.reason, 'ascii');

  if (this.hash)
    bw.writeHash(this.hash);

  return bw;
};

/**
 * Serialize reject packet.
 * @returns {Buffer}
 */

RejectPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

RejectPacket.prototype.fromReader = function fromReader(br) {
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
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

RejectPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate reject packet from buffer reader.
 * @param {BufferReader} br
 * @returns {RejectPacket}
 */

RejectPacket.fromReader = function fromReader(br) {
  return new RejectPacket().fromReader(br);
};

/**
 * Instantiate reject packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {RejectPacket}
 */

RejectPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new RejectPacket().fromRaw(data, enc);
};

/**
 * Inject properties from reason message and object.
 * @private
 * @param {Number} code
 * @param {String} reason
 * @param {String?} msg
 * @param {Hash?} hash
 */

RejectPacket.prototype.fromReason = function fromReason(code, reason, msg, hash) {
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
};

/**
 * Instantiate reject packet from reason message.
 * @param {Number} code
 * @param {String} reason
 * @param {String?} msg
 * @param {Hash?} hash
 * @returns {RejectPacket}
 */

RejectPacket.fromReason = function fromReason(code, reason, msg, hash) {
  return new RejectPacket().fromReason(code, reason, msg, hash);
};

/**
 * Instantiate reject packet from verify error.
 * @param {VerifyError} err
 * @param {(TX|Block)?} obj
 * @returns {RejectPacket}
 */

RejectPacket.fromError = function fromError(err, obj) {
  return RejectPacket.fromReason(err.code, err.reason, obj);
};

/**
 * Inspect reject packet.
 * @returns {String}
 */

RejectPacket.prototype.inspect = function inspect() {
  let code = RejectPacket.codesByVal[this.code] || this.code;
  let hash = this.hash ? util.revHex(this.hash) : null;
  return '<Reject:'
    + ` msg=${this.message}`
    + ` code=${code}`
    + ` reason=${this.reason}`
    + ` hash=${hash}`
    + '>';
};

/**
 * Represents a `mempool` packet.
 * @constructor
 */

function MempoolPacket() {
  if (!(this instanceof MempoolPacket))
    return new MempoolPacket();

  Packet.call(this);
}

util.inherits(MempoolPacket, Packet);

MempoolPacket.prototype.cmd = 'mempool';
MempoolPacket.prototype.type = exports.types.MEMPOOL;

/**
 * Instantiate mempool packet from buffer reader.
 * @param {BufferReader} br
 * @returns {VerackPacket}
 */

MempoolPacket.fromReader = function fromReader(br) {
  return new MempoolPacket().fromReader(br);
};

/**
 * Instantiate mempool packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {VerackPacket}
 */

MempoolPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new MempoolPacket().fromRaw(data);
};

/**
 * Represents a `filterload` packet.
 * @constructor
 * @param {Bloom|null} filter
 */

function FilterLoadPacket(filter) {
  if (!(this instanceof FilterLoadPacket))
    return new FilterLoadPacket(filter);

  Packet.call(this);

  this.filter = filter || new Bloom();
}

util.inherits(FilterLoadPacket, Packet);

FilterLoadPacket.prototype.cmd = 'filterload';
FilterLoadPacket.prototype.type = exports.types.FILTERLOAD;

/**
 * Get serialization size.
 * @returns {Number}
 */

FilterLoadPacket.prototype.getSize = function getSize() {
  return this.filter.getSize();
};

/**
 * Serialize filterload packet to writer.
 * @param {BufferWriter} bw
 */

FilterLoadPacket.prototype.toWriter = function toWriter(bw) {
  return this.filter.toWriter(bw);
};

/**
 * Serialize filterload packet.
 * @returns {Buffer}
 */

FilterLoadPacket.prototype.toRaw = function toRaw() {
  return this.filter.toRaw();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

FilterLoadPacket.prototype.fromReader = function fromReader(br) {
  this.filter.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

FilterLoadPacket.prototype.fromRaw = function fromRaw(data) {
  this.filter.fromRaw(data);
  return this;
};

/**
 * Instantiate filterload packet from buffer reader.
 * @param {BufferReader} br
 * @returns {FilterLoadPacket}
 */

FilterLoadPacket.fromReader = function fromReader(br) {
  return new FilterLoadPacket().fromReader(br);
};

/**
 * Instantiate filterload packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {FilterLoadPacket}
 */

FilterLoadPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new FilterLoadPacket().fromRaw(data);
};

/**
 * Ensure the filter is within the size limits.
 * @returns {Boolean}
 */

FilterLoadPacket.prototype.isWithinConstraints = function isWithinConstraints() {
  return this.filter.isWithinConstraints();
};

/**
 * Represents a `filteradd` packet.
 * @constructor
 * @param {Buffer?} data
 * @property {Buffer} data
 */

function FilterAddPacket(data) {
  if (!(this instanceof FilterAddPacket))
    return new FilterAddPacket(data);

  Packet.call(this);

  this.data = data || DUMMY;
}

util.inherits(FilterAddPacket, Packet);

FilterAddPacket.prototype.cmd = 'filteradd';
FilterAddPacket.prototype.type = exports.types.FILTERADD;

/**
 * Get serialization size.
 * @returns {Number}
 */

FilterAddPacket.prototype.getSize = function getSize() {
  return encoding.sizeVarBytes(this.data);
};

/**
 * Serialize filteradd packet to writer.
 * @returns {BufferWriter} bw
 */

FilterAddPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeVarBytes(this.data);
  return bw;
};

/**
 * Serialize filteradd packet.
 * @returns {Buffer}
 */

FilterAddPacket.prototype.toRaw = function toRaw() {
  let size = this.getSize();
  return this.toWriter(new StaticWriter(size)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

FilterAddPacket.prototype.fromReader = function fromReader(br) {
  this.data = br.readVarBytes();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

FilterAddPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate filteradd packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {FilterAddPacket}
 */

FilterAddPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new FilterAddPacket().fromRaw(data);
};

/**
 * Represents a `filterclear` packet.
 * @constructor
 */

function FilterClearPacket() {
  if (!(this instanceof FilterClearPacket))
    return new FilterClearPacket();

  Packet.call(this);
}

util.inherits(FilterClearPacket, Packet);

FilterClearPacket.prototype.cmd = 'filterclear';
FilterClearPacket.prototype.type = exports.types.FILTERCLEAR;

/**
 * Instantiate filterclear packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {FilterClearPacket}
 */

FilterClearPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new FilterClearPacket().fromRaw(data);
};

/**
 * Represents a `merkleblock` packet.
 * @constructor
 * @param {MerkleBlock?} block
 * @property {MerkleBlock} block
 */

function MerkleBlockPacket(block) {
  if (!(this instanceof MerkleBlockPacket))
    return new MerkleBlockPacket(block);

  Packet.call(this);

  this.block = block || new MerkleBlock();
}

util.inherits(MerkleBlockPacket, Packet);

MerkleBlockPacket.prototype.cmd = 'merkleblock';
MerkleBlockPacket.prototype.type = exports.types.MERKLEBLOCK;

/**
 * Get serialization size.
 * @returns {Number}
 */

MerkleBlockPacket.prototype.getSize = function getSize() {
  return this.block.getSize();
};

/**
 * Serialize merkleblock packet to writer.
 * @param {BufferWriter} bw
 */

MerkleBlockPacket.prototype.toWriter = function toWriter(bw) {
  return this.block.toWriter(bw);
};

/**
 * Serialize merkleblock packet.
 * @returns {Buffer}
 */

MerkleBlockPacket.prototype.toRaw = function toRaw() {
  return this.block.toRaw();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

MerkleBlockPacket.prototype.fromReader = function fromReader(br) {
  this.block.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

MerkleBlockPacket.prototype.fromRaw = function fromRaw(data) {
  this.block.fromRaw(data);
  return this;
};

/**
 * Instantiate merkleblock packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {MerkleBlockPacket}
 */

MerkleBlockPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new MerkleBlockPacket().fromRaw(data);
};

/**
 * Represents a `feefilter` packet.
 * @constructor
 * @param {Rate?} rate
 * @property {Rate} rate
 */

function FeeFilterPacket(rate) {
  if (!(this instanceof FeeFilterPacket))
    return new FeeFilterPacket(rate);

  Packet.call(this);

  this.rate = rate || 0;
}

util.inherits(FeeFilterPacket, Packet);

FeeFilterPacket.prototype.cmd = 'feefilter';
FeeFilterPacket.prototype.type = exports.types.FEEFILTER;

/**
 * Get serialization size.
 * @returns {Number}
 */

FeeFilterPacket.prototype.getSize = function getSize() {
  return 8;
};

/**
 * Serialize feefilter packet to writer.
 * @param {BufferWriter} bw
 */

FeeFilterPacket.prototype.toWriter = function toWriter(bw) {
  bw.write64(this.rate);
  return bw;
};

/**
 * Serialize feefilter packet.
 * @returns {Buffer}
 */

FeeFilterPacket.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(8)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

FeeFilterPacket.prototype.fromReader = function fromReader(br) {
  this.rate = br.read64();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

FeeFilterPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate feefilter packet from buffer reader.
 * @param {BufferReader} br
 * @returns {FeeFilterPacket}
 */

FeeFilterPacket.fromReader = function fromReader(br) {
  return new FeeFilterPacket().fromReader(br);
};

/**
 * Instantiate feefilter packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {FeeFilterPacket}
 */

FeeFilterPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new FeeFilterPacket().fromRaw(data);
};

/**
 * Represents a `sendcmpct` packet.
 * @constructor
 * @param {Number|null} mode
 * @param {Number|null} version
 * @property {Number} mode
 * @property {Number} version
 */

function SendCmpctPacket(mode, version) {
  if (!(this instanceof SendCmpctPacket))
    return new SendCmpctPacket(mode, version);

  Packet.call(this);

  this.mode = mode || 0;
  this.version = version || 1;
}

util.inherits(SendCmpctPacket, Packet);

SendCmpctPacket.prototype.cmd = 'sendcmpct';
SendCmpctPacket.prototype.type = exports.types.SENDCMPCT;

/**
 * Get serialization size.
 * @returns {Number}
 */

SendCmpctPacket.prototype.getSize = function getSize() {
  return 9;
};

/**
 * Serialize sendcmpct packet to writer.
 * @param {BufferWriter} bw
 */

SendCmpctPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeU8(this.mode);
  bw.writeU64(this.version);
  return bw;
};

/**
 * Serialize sendcmpct packet.
 * @returns {Buffer}
 */

SendCmpctPacket.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(9)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

SendCmpctPacket.prototype.fromReader = function fromReader(br) {
  this.mode = br.readU8();
  this.version = br.readU53();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

SendCmpctPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate sendcmpct packet from buffer reader.
 * @param {BufferReader} br
 * @returns {SendCmpctPacket}
 */

SendCmpctPacket.fromReader = function fromReader(br) {
  return new SendCmpctPacket().fromReader(br);
};

/**
 * Instantiate sendcmpct packet from buffer reader.
 * @param {BufferReader} br
 * @returns {SendCmpctPacket}
 */

SendCmpctPacket.fromReader = function fromReader(br) {
  return new SendCmpctPacket().fromReader(br);
};

/**
 * Instantiate sendcmpct packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {SendCmpctPacket}
 */

SendCmpctPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new SendCmpctPacket().fromRaw(data);
};

/**
 * Represents a `cmpctblock` packet.
 * @constructor
 * @param {Block|null} block
 * @param {Boolean|null} witness
 * @property {Block} block
 * @property {Boolean} witness
 */

function CmpctBlockPacket(block, witness) {
  if (!(this instanceof CmpctBlockPacket))
    return new CmpctBlockPacket(block, witness);

  Packet.call(this);

  this.block = block || new bip152.CompactBlock();
  this.witness = witness || false;
}

util.inherits(CmpctBlockPacket, Packet);

CmpctBlockPacket.prototype.cmd = 'cmpctblock';
CmpctBlockPacket.prototype.type = exports.types.CMPCTBLOCK;

/**
 * Serialize cmpctblock packet.
 * @returns {Buffer}
 */

CmpctBlockPacket.prototype.getSize = function getSize() {
  if (this.witness)
    return this.block.getSize(true);
  return this.block.getSize(false);
};

/**
 * Serialize cmpctblock packet to writer.
 * @param {BufferWriter} bw
 */

CmpctBlockPacket.prototype.toWriter = function toWriter(bw) {
  if (this.witness)
    return this.block.toWriter(bw);
  return this.block.toNormalWriter(bw);
};

/**
 * Serialize cmpctblock packet.
 * @returns {Buffer}
 */

CmpctBlockPacket.prototype.toRaw = function toRaw() {
  if (this.witness)
    return this.block.toRaw();
  return this.block.toNormal();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

CmpctBlockPacket.prototype.fromReader = function fromReader(br) {
  this.block.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

CmpctBlockPacket.prototype.fromRaw = function fromRaw(data) {
  this.block.fromRaw(data);
  return this;
};

/**
 * Instantiate cmpctblock packet from buffer reader.
 * @param {BufferReader} br
 * @returns {CmpctBlockPacket}
 */

CmpctBlockPacket.fromReader = function fromReader(br) {
  return new CmpctBlockPacket().fromRaw(br);
};

/**
 * Instantiate cmpctblock packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {CmpctBlockPacket}
 */

CmpctBlockPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new CmpctBlockPacket().fromRaw(data);
};

/**
 * Represents a `getblocktxn` packet.
 * @constructor
 * @param {TXRequest?} request
 * @property {TXRequest} request
 */

function GetBlockTxnPacket(request) {
  if (!(this instanceof GetBlockTxnPacket))
    return new GetBlockTxnPacket(request);

  Packet.call(this);

  this.request = request || new bip152.TXRequest();
}

util.inherits(GetBlockTxnPacket, Packet);

GetBlockTxnPacket.prototype.cmd = 'getblocktxn';
GetBlockTxnPacket.prototype.type = exports.types.GETBLOCKTXN;

/**
 * Get serialization size.
 * @returns {Number}
 */

GetBlockTxnPacket.prototype.getSize = function getSize() {
  return this.request.getSize();
};

/**
 * Serialize getblocktxn packet to writer.
 * @param {BufferWriter} bw
 */

GetBlockTxnPacket.prototype.toWriter = function toWriter(bw) {
  return this.request.toWriter(bw);
};

/**
 * Serialize getblocktxn packet.
 * @returns {Buffer}
 */

GetBlockTxnPacket.prototype.toRaw = function toRaw() {
  return this.request.toRaw();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

GetBlockTxnPacket.prototype.fromReader = function fromReader(br) {
  this.request.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

GetBlockTxnPacket.prototype.fromRaw = function fromRaw(data) {
  this.request.fromRaw(data);
  return this;
};

/**
 * Instantiate getblocktxn packet from buffer reader.
 * @param {BufferReader} br
 * @returns {GetBlockTxnPacket}
 */

GetBlockTxnPacket.fromReader = function fromReader(br) {
  return new GetBlockTxnPacket().fromReader(br);
};

/**
 * Instantiate getblocktxn packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {GetBlockTxnPacket}
 */

GetBlockTxnPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new GetBlockTxnPacket().fromRaw(data);
};

/**
 * Represents a `blocktxn` packet.
 * @constructor
 * @param {TXResponse?} response
 * @param {Boolean?} witness
 * @property {TXResponse} response
 * @property {Boolean} witness
 */

function BlockTxnPacket(response, witness) {
  if (!(this instanceof BlockTxnPacket))
    return new BlockTxnPacket(response, witness);

  Packet.call(this);

  this.response = response || new bip152.TXResponse();
  this.witness = witness || false;
}

util.inherits(BlockTxnPacket, Packet);

BlockTxnPacket.prototype.cmd = 'blocktxn';
BlockTxnPacket.prototype.type = exports.types.BLOCKTXN;

/**
 * Get serialization size.
 * @returns {Number}
 */

BlockTxnPacket.prototype.getSize = function getSize() {
  if (this.witness)
    return this.response.getSize(true);
  return this.response.getSize(false);
};

/**
 * Serialize blocktxn packet to writer.
 * @param {BufferWriter} bw
 */

BlockTxnPacket.prototype.toWriter = function toWriter(bw) {
  if (this.witness)
    return this.response.toWriter(bw);
  return this.response.toNormalWriter(bw);
};

/**
 * Serialize blocktxn packet.
 * @returns {Buffer}
 */

BlockTxnPacket.prototype.toRaw = function toRaw() {
  if (this.witness)
    return this.response.toRaw();
  return this.response.toNormal();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

BlockTxnPacket.prototype.fromReader = function fromReader(br) {
  this.response.fromReader(br);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

BlockTxnPacket.prototype.fromRaw = function fromRaw(data) {
  this.response.fromRaw(data);
  return this;
};

/**
 * Instantiate blocktxn packet from buffer reader.
 * @param {BufferReader} br
 * @returns {BlockTxnPacket}
 */

BlockTxnPacket.fromReader = function fromReader(br) {
  return new BlockTxnPacket().fromReader(br);
};

/**
 * Instantiate blocktxn packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {BlockTxnPacket}
 */

BlockTxnPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new BlockTxnPacket().fromRaw(data);
};

/**
 * Represents a `encinit` packet.
 * @constructor
 * @param {Buffer|null} publicKey
 * @param {Number|null} cipher
 * @property {Buffer} publicKey
 * @property {Number} cipher
 */

function EncinitPacket(publicKey, cipher) {
  if (!(this instanceof EncinitPacket))
    return new EncinitPacket(publicKey, cipher);

  Packet.call(this);

  this.publicKey = publicKey || encoding.ZERO_KEY;
  this.cipher = cipher || 0;
}

util.inherits(EncinitPacket, Packet);

EncinitPacket.prototype.cmd = 'encinit';
EncinitPacket.prototype.type = exports.types.ENCINIT;

/**
 * Get serialization size.
 * @returns {Number}
 */

EncinitPacket.prototype.getSize = function getSize() {
  return 34;
};

/**
 * Serialize encinit packet to writer.
 * @param {BufferWriter} bw
 */

EncinitPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.publicKey);
  bw.writeU8(this.cipher);
  return bw;
};

/**
 * Serialize encinit packet.
 * @returns {Buffer}
 */

EncinitPacket.prototype.toRaw = function toRaw() {
  return this.toWriter(new StaticWriter(34)).render();
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

EncinitPacket.prototype.fromReader = function fromReader(br) {
  this.publicKey = br.readBytes(33);
  this.cipher = br.readU8();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

EncinitPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate getblocks packet from buffer reader.
 * @param {BufferReader} br
 * @returns {EncinitPacket}
 */

EncinitPacket.fromReader = function fromReader(br) {
  return new EncinitPacket().fromReader(br);
};

/**
 * Instantiate getblocks packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {EncinitPacket}
 */

EncinitPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new EncinitPacket().fromRaw(data);
};

/**
 * Represents a `encack` packet.
 * @constructor
 * @param {Buffer?} publicKey
 * @property {Buffer} publicKey
 */

function EncackPacket(publicKey) {
  if (!(this instanceof EncackPacket))
    return new EncackPacket(publicKey);

  Packet.call(this);

  this.publicKey = publicKey || encoding.ZERO_KEY;
}

util.inherits(EncackPacket, Packet);

EncackPacket.prototype.cmd = 'encack';
EncackPacket.prototype.type = exports.types.ENCACK;

/**
 * Get serialization size.
 * @returns {Number}
 */

EncackPacket.prototype.getSize = function getSize() {
  return 33;
};

/**
 * Serialize encack packet to writer.
 * @param {BufferWriter} bw
 */

EncackPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.publicKey);
  return bw;
};

/**
 * Serialize encack packet.
 * @returns {Buffer}
 */

EncackPacket.prototype.toRaw = function toRaw() {
  return this.publicKey;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

EncackPacket.prototype.fromReader = function fromReader(br) {
  this.publicKey = br.readBytes(33);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

EncackPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate encack packet from buffer reader.
 * @param {BufferReader} br
 * @returns {EncackPacket}
 */

EncackPacket.fromReader = function fromReader(br) {
  return new EncackPacket().fromReader(br);
};

/**
 * Instantiate encack packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {EncackPacket}
 */

EncackPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new EncackPacket().fromRaw(data);
};

/**
 * Represents a `authchallenge` packet.
 * @constructor
 * @param {Buffer?} hash
 * @property {Buffer} hash
 */

function AuthChallengePacket(hash) {
  if (!(this instanceof AuthChallengePacket))
    return new AuthChallengePacket(hash);

  Packet.call(this);

  this.hash = hash || encoding.ZERO_HASH;
}

util.inherits(AuthChallengePacket, Packet);

AuthChallengePacket.prototype.cmd = 'authchallenge';
AuthChallengePacket.prototype.type = exports.types.AUTHCHALLENGE;

/**
 * Get serialization size.
 * @returns {Number}
 */

EncackPacket.prototype.getSize = function getSize() {
  return 32;
};

/**
 * Serialize authchallenge packet to writer.
 * @param {BufferWriter} bw
 */

AuthChallengePacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.hash);
  return bw;
};

/**
 * Serialize authchallenge packet.
 * @returns {Buffer}
 */

AuthChallengePacket.prototype.toRaw = function toRaw() {
  return this.hash;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

AuthChallengePacket.prototype.fromReader = function fromReader(br) {
  this.hash = br.readHash();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AuthChallengePacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate authchallenge packet from buffer reader.
 * @param {BufferReader} br
 * @returns {AuthChallengePacket}
 */

AuthChallengePacket.fromReader = function fromReader(br) {
  return new AuthChallengePacket().fromReader(br);
};

/**
 * Instantiate authchallenge packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {AuthChallengePacket}
 */

AuthChallengePacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new AuthChallengePacket().fromRaw(data);
};

/**
 * Represents a `authreply` packet.
 * @constructor
 * @param {Buffer?} signature
 * @property {Buffer} signature
 */

function AuthReplyPacket(signature) {
  if (!(this instanceof AuthReplyPacket))
    return new AuthReplyPacket(signature);

  Packet.call(this);

  this.signature = signature || encoding.ZERO_SIG64;
}

util.inherits(AuthReplyPacket, Packet);

AuthReplyPacket.prototype.cmd = 'authreply';
AuthReplyPacket.prototype.type = exports.types.AUTHREPLY;

/**
 * Get serialization size.
 * @returns {Number}
 */

AuthReplyPacket.prototype.getSize = function getSize() {
  return 64;
};

/**
 * Serialize authreply packet to writer.
 * @param {BufferWriter} bw
 */

AuthReplyPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.signature);
  return bw;
};

/**
 * Serialize authreply packet.
 * @returns {Buffer}
 */

AuthReplyPacket.prototype.toRaw = function toRaw() {
  return this.signature;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

AuthReplyPacket.prototype.fromReader = function fromReader(br) {
  this.signature = br.readBytes(64);
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AuthReplyPacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate authreply packet from buffer reader.
 * @param {BufferReader} br
 * @returns {AuthReplyPacket}
 */

AuthReplyPacket.fromReader = function fromReader(br) {
  return new AuthReplyPacket().fromReader(br);
};

/**
 * Instantiate authreply packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {AuthReplyPacket}
 */

AuthReplyPacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new AuthReplyPacket().fromRaw(data);
};

/**
 * Represents a `authpropose` packet.
 * @constructor
 * @param {Hash?} hash
 * @property {Hash} hash
 */

function AuthProposePacket(hash) {
  if (!(this instanceof AuthProposePacket))
    return new AuthProposePacket(hash);

  Packet.call(this);

  this.hash = hash || encoding.ZERO_HASH;
}

util.inherits(AuthProposePacket, Packet);

AuthProposePacket.prototype.cmd = 'authpropose';
AuthProposePacket.prototype.type = exports.types.AUTHPROPOSE;

/**
 * Get serialization size.
 * @returns {Number}
 */

AuthProposePacket.prototype.getSize = function getSize() {
  return 32;
};

/**
 * Serialize authpropose packet to writer.
 * @param {BufferWriter} bw
 */

AuthProposePacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.hash);
  return bw;
};

/**
 * Serialize authpropose packet.
 * @returns {Buffer}
 */

AuthProposePacket.prototype.toRaw = function toRaw() {
  return this.hash;
};

/**
 * Inject properties from buffer reader.
 * @private
 * @param {BufferReader} br
 */

AuthProposePacket.prototype.fromReader = function fromReader(br) {
  this.hash = br.readHash();
  return this;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

AuthProposePacket.prototype.fromRaw = function fromRaw(data) {
  return this.fromReader(new BufferReader(data));
};

/**
 * Instantiate authpropose packet from buffer reader.
 * @param {BufferReader} br
 * @returns {AuthProposePacket}
 */

AuthProposePacket.fromReader = function fromReader(br) {
  return new AuthProposePacket().fromReader(br);
};

/**
 * Instantiate authpropose packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {AuthProposePacket}
 */

AuthProposePacket.fromRaw = function fromRaw(data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new AuthProposePacket().fromRaw(data);
};

/**
 * Represents an unknown packet.
 * @constructor
 * @param {String|null} cmd
 * @param {Buffer|null} data
 * @property {String} cmd
 * @property {Buffer} data
 */

function UnknownPacket(cmd, data) {
  if (!(this instanceof UnknownPacket))
    return new UnknownPacket(cmd, data);

  Packet.call(this);

  this.cmd = cmd;
  this.data = data;
}

util.inherits(UnknownPacket, Packet);

UnknownPacket.prototype.type = exports.types.UNKNOWN;

/**
 * Get serialization size.
 * @returns {Number}
 */

UnknownPacket.prototype.getSize = function getSize() {
  return this.data.length;
};

/**
 * Serialize unknown packet to writer.
 * @param {BufferWriter} bw
 */

UnknownPacket.prototype.toWriter = function toWriter(bw) {
  bw.writeBytes(this.data);
  return bw;
};

/**
 * Serialize unknown packet.
 * @returns {Buffer}
 */

UnknownPacket.prototype.toRaw = function toRaw() {
  return this.data;
};

/**
 * Inject properties from serialized data.
 * @private
 * @param {Buffer} data
 */

UnknownPacket.prototype.fromRaw = function fromRaw(cmd, data) {
  assert(Buffer.isBuffer(data));
  this.cmd = cmd;
  this.data = data;
  return this;
};

/**
 * Instantiate unknown packet from serialized data.
 * @param {Buffer} data
 * @param {String?} enc
 * @returns {UnknownPacket}
 */

UnknownPacket.fromRaw = function fromRaw(cmd, data, enc) {
  if (typeof data === 'string')
    data = Buffer.from(data, enc);
  return new UnknownPacket().fromRaw(cmd, data);
};

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

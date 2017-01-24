/*!
 * hostlist.js - address management for bcoin
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var assert = require('assert');
var util = require('../utils/util');
var IP = require('../utils/ip');
var co = require('../utils/co');
var Network = require('../protocol/network');
var NetAddress = require('../primitives/netaddress');
var List = require('../utils/list');
var murmur3 = require('../utils/murmur3');
var StaticWriter = require('../utils/staticwriter');
var Map = require('../utils/map');
var common = require('./common');
var dns = require('./dns');

/**
 * Host List
 * @constructor
 * @param {Object} options
 */

function HostList(options) {
  if (!(this instanceof HostList))
    return new HostList(options);

  this.network = Network.primary;
  this.logger = null;
  this.address = new NetAddress();
  this.proxyServer = null;
  this.resolve = dns.resolve;
  this.banTime = common.BAN_TIME;

  this.rawSeeds = this.network.seeds;
  this.dnsSeeds = [];
  this.rawNodes = [];
  this.dnsNodes = [];
  this.nodes = [];

  this.banned = {};

  this.map = {};
  this.fresh = [];
  this.used = [];

  this.totalFresh = 0;
  this.totalUsed = 0;

  this.maxBuckets = 20;
  this.maxEntries = 50;
  this.maxAddresses = this.maxBuckets * this.maxEntries;

  this.horizonDays = 30;
  this.retries = 3;
  this.minFailDays = 7;
  this.maxFailures = 10;
  this.maxRefs = 8;

  this._initOptions(options);
  this._init();
}

/**
 * Initialize options.
 * @private
 */

HostList.prototype._initOptions = function initOptions(options) {
  if (!options)
    return;

  if (options.network != null) {
    this.network = Network.get(options.network);
    this.rawSeeds = this.network.seeds;
  }

  if (options.logger != null) {
    assert(typeof options.logger === 'object');
    this.logger = options.logger;
  }

  if (options.address != null) {
    assert(options.address instanceof NetAddress);
    this.address = options.address;
  }

  if (options.proxyServer != null) {
    assert(typeof options.proxyServer === 'string');
    this.proxyServer = options.proxyServer;
  }

  if (options.resolve != null) {
    assert(typeof options.resolve === 'function');
    this.resolve = options.resolve;
  }

  if (options.banTime != null) {
    assert(options.banTime >= 0);
    this.banTime = options.banTime;
  }

  if (options.seeds) {
    assert(Array.isArray(options.seeds));
    this.rawSeeds = options.seeds;
  }

  if (options.nodes) {
    assert(Array.isArray(options.nodes));
    this.rawNodes = options.nodes;
  }
};

/**
 * Initialize list.
 * @private
 */

HostList.prototype._init = function init() {
  var i;

  for (i = 0; i < this.maxBuckets; i++)
    this.fresh.push(new Map());

  for (i = 0; i < this.maxBuckets; i++)
    this.used.push(new List());

  this.setSeeds(this.rawSeeds);
  this.setNodes(this.rawNodes);
};

/**
 * Get list size.
 * @returns {Number}
 */

HostList.prototype.size = function size() {
  return this.totalFresh + this.totalUsed;
};

/**
 * Test whether the host list is full.
 * @returns {Boolean}
 */

HostList.prototype.isFull = function isFull() {
  return this.size() >= this.maxAddresses;
};

/**
 * Reset host list.
 */

HostList.prototype.reset = function reset() {
  var i, bucket;

  this.map = {};

  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    bucket.reset();
  }

  for (i = 0; i < this.used.length; i++) {
    bucket = this.used[i];
    bucket.reset();
  }

  this.totalFresh = 0;
  this.totalUsed = 0;
};

/**
 * Mark a peer as banned.
 * @param {String} host
 */

HostList.prototype.ban = function ban(host) {
  this.banned[host] = util.now();
};

/**
 * Unban host.
 * @param {String} host
 */

HostList.prototype.unban = function unban(host) {
  delete this.banned[host];
};

/**
 * Clear banned hosts.
 */

HostList.prototype.clearBanned = function clearBanned() {
  this.banned = {};
};

/**
 * Test whether the host is banned.
 * @param {String} host
 * @returns {Boolean}
 */

HostList.prototype.isBanned = function isBanned(host) {
  var time = this.banned[host];

  if (time == null)
    return false;

  if (util.now() > time + this.banTime) {
    delete this.banned[host];
    return false;
  }

  return true;
};

/**
 * Allocate a new host.
 * @returns {HostEntry}
 */

HostList.prototype.getHost = function getHost() {
  var now = this.network.now();
  var buckets = null;
  var factor = 1;
  var index, key, bucket, entry, num;

  if (this.totalFresh > 0)
    buckets = this.fresh;

  if (this.totalUsed > 0) {
    if (this.totalFresh === 0 || util.random(0, 2) === 0)
      buckets = this.used;
  }

  if (!buckets)
    return;

  for (;;) {
    index = util.random(0, buckets.length);
    bucket = buckets[index];

    if (bucket.size === 0)
      continue;

    index = util.random(0, bucket.size);

    if (buckets === this.used) {
      entry = bucket.head;
      while (index--)
        entry = entry.next;
    } else {
      key = bucket.keys()[index];
      entry = bucket.get(key);
    }

    num = util.random(0, 1 << 30);

    if (num < factor * entry.chance(now) * (1 << 30))
      return entry;

    factor *= 1.2;
  }
};

/**
 * Get fresh bucket for host.
 * @private
 * @param {HostEntry} entry
 * @returns {Map}
 */

HostList.prototype.freshBucket = function freshBucket(entry) {
  var size = 0;
  var bw, hash, index;

  size += entry.addr.host.length;
  size += entry.src.host.length;

  bw = new StaticWriter(size);
  bw.writeString(entry.addr.host, 'ascii');
  bw.writeString(entry.src.host, 'ascii');

  hash = murmur3(bw.render(), 0xfba4c795);
  index = hash % this.fresh.length;

  return this.fresh[index];
};

/**
 * Get used bucket for host.
 * @private
 * @param {HostEntry} entry
 * @returns {List}
 */

HostList.prototype.usedBucket = function usedBucket(entry) {
  var data = new Buffer(entry.addr.host, 'ascii');
  var hash = murmur3(data, 0xfba4c795);
  var index = hash % this.used.length;
  return this.used[index];
};

/**
 * Add host to host list.
 * @param {NetAddress} addr
 * @param {NetAddress?} src
 * @returns {Boolean}
 */

HostList.prototype.add = function add(addr, src) {
  var now = this.network.now();
  var penalty = 2 * 60 * 60;
  var interval = 24 * 60 * 60;
  var factor = 1;
  var i, entry, bucket;

  if (this.isFull())
    return false;

  entry = this.map[addr.hostname];

  if (entry) {
    // No source means we're inserting
    // this ourselves. No penalty.
    if (!src)
      penalty = 0;

    // Update services.
    entry.addr.services |= addr.services;
    entry.addr.services >>>= 0;

    // Online?
    if (now - addr.ts < 24 * 60 * 60)
      interval = 60 * 60;

    // Periodically update time.
    if (entry.addr.ts < addr.ts - interval - penalty)
      entry.addr.ts = addr.ts;

    // Do not update if no new
    // information is present.
    if (entry.addr.ts && addr.ts <= entry.addr.ts)
      return false;

    // Do not update if the entry was
    // already in the "used" table.
    if (entry.used)
      return false;

    assert(entry.refCount > 0);

    // Do not update if the max
    // reference count is reached.
    if (entry.refCount === this.maxRefs)
      return false;

    assert(entry.refCount < this.maxRefs);

    // Stochastic test: previous refCount
    // N: 2^N times harder to increase it.
    for (i = 0; i < entry.refCount; i++)
      factor *= 2;

    if (util.random(0, factor) !== 0)
      return false;
  } else {
    if (!src)
      src = this.address;

    entry = new HostEntry(addr, src);

    this.totalFresh++;
  }

  bucket = this.freshBucket(entry);

  if (bucket.has(entry.key()))
    return false;

  if (bucket.size >= this.maxEntries)
    this.evictFresh(bucket);

  bucket.set(entry.key(), entry);
  entry.refCount++;

  this.map[entry.key()] = entry;

  return true;
};

/**
 * Evict a host from fresh bucket.
 * @param {Map} bucket
 */

HostList.prototype.evictFresh = function evictFresh(bucket) {
  var keys = bucket.keys();
  var i, key, entry, old;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = bucket.get(key);

    if (this.isStale(entry)) {
      bucket.remove(entry.key());

      if (--entry.refCount === 0) {
        delete this.map[entry.key()];
        this.totalFresh--;
      }

      continue;
    }

    if (!old) {
      old = entry;
      continue;
    }

    if (entry.addr.ts < old.addr.ts)
      old = entry;
  }

  if (!old)
    return;

  bucket.remove(old.key());

  if (--old.refCount === 0) {
    delete this.map[old.key()];
    this.totalFresh--;
  }
};

/**
 * Test whether a host is evictable.
 * @param {HostEntry} entry
 * @returns {Boolean}
 */

HostList.prototype.isStale = function isStale(entry) {
  var now = this.network.now();

  if (entry.lastAttempt && entry.lastAttempt >= now - 60)
    return false;

  if (entry.addr.ts > now + 10 * 60)
    return true;

  if (entry.addr.ts === 0)
    return true;

  if (now - entry.addr.ts > this.horizonDays * 24 * 60 * 60)
    return true;

  if (entry.lastSuccess === 0 && entry.attempts >= this.retries)
    return true;

  if (now - entry.lastSuccess > this.minFailDays * 24 * 60 * 60) {
    if (entry.attempts >= this.maxFailures)
      return true;
  }

  return false;
};

/**
 * Remove host from host list.
 * @param {String} hostname
 * @returns {NetAddress}
 */

HostList.prototype.remove = function remove(hostname) {
  var entry = this.map[hostname];
  var i, head, bucket;

  if (!entry)
    return;

  if (entry.used) {
    assert(entry.refCount === 0);

    head = entry;
    while (head.prev)
      head = head.prev;

    for (i = 0; i < this.used.length; i++) {
      bucket = this.used[i];
      if (bucket.head === head) {
        bucket.remove(entry);
        this.totalUsed--;
        break;
      }
    }

    assert(i < this.used.length);
  } else {
    for (i = 0; i < this.fresh.length; i++) {
      bucket = this.fresh[i];
      if (bucket.remove(entry.key()))
        entry.refCount--;
    }

    this.totalFresh--;
    assert(entry.refCount === 0);
  }

  delete this.map[entry.key()];

  return entry.addr;
};

/**
 * Mark host as failed.
 * @param {String} hostname
 */

HostList.prototype.markAttempt = function markAttempt(hostname) {
  var entry = this.map[hostname];
  var now = this.network.now();

  if (!entry)
    return;

  entry.attempts++;
  entry.lastAttempt = now;
};

/**
 * Mark host as successfully connected.
 * @param {String} hostname
 */

HostList.prototype.markSuccess = function markSuccess(hostname) {
  var entry = this.map[hostname];
  var now = this.network.now();

  if (!entry)
    return;

  if (now - entry.addr.ts > 20 * 60)
    entry.addr.ts = now;
};

/**
 * Mark host as successfully ack'd.
 * @param {String} hostname
 * @param {Number} services
 */

HostList.prototype.markAck = function markAck(hostname, services) {
  var entry = this.map[hostname];
  var now = this.network.now();
  var i, bucket, evicted, old, fresh;

  if (!entry)
    return;

  entry.addr.services |= services;
  entry.addr.services >>>= 0;

  entry.lastSuccess = now;
  entry.lastAttempt = now;
  entry.attempts = 0;

  if (entry.used)
    return;

  assert(entry.refCount > 0);

  // Remove from fresh.
  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    if (bucket.remove(entry.key())) {
      entry.refCount--;
      old = bucket;
    }
  }

  assert(old);
  assert(entry.refCount === 0);
  this.totalFresh--;

  // Find room in used bucket.
  bucket = this.usedBucket(entry);

  if (bucket.size < this.maxEntries) {
    entry.used = true;
    bucket.push(entry);
    this.totalUsed++;
    return;
  }

  // No room. Evict.
  evicted = this.evictUsed(bucket);
  fresh = this.freshBucket(evicted);

  // Move to entry's old bucket if no room.
  if (fresh.size >= this.maxEntries)
    fresh = old;

  // Swap to evicted's used bucket.
  entry.used = true;
  bucket.replace(evicted, entry);

  // Move evicted to fresh bucket.
  evicted.used = false;
  fresh.set(evicted.key(), evicted);
  assert(evicted.refCount === 0);
  evicted.refCount++;
  this.totalFresh++;
};

/**
 * Pick used for eviction.
 * @param {List} bucket
 */

HostList.prototype.evictUsed = function evictUsed(bucket) {
  var old = bucket.head;
  var entry;

  for (entry = bucket.head; entry; entry = entry.next) {
    if (entry.addr.ts < old.addr.ts)
      old = entry;
  }

  return old;
};

/**
 * Convert address list to array.
 * @returns {NetAddress[]}
 */

HostList.prototype.toArray = function toArray() {
  var keys = Object.keys(this.map);
  var out = [];
  var i, key, entry;

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    out.push(entry.addr);
  }

  assert.equal(out.length, this.size());

  return out;
};

/**
 * Add a preferred seed.
 * @param {String} host
 */

HostList.prototype.addSeed = function addSeed(host) {
  var addr = IP.fromHostname(host, this.network.port);

  if (addr.type === IP.types.DNS) {
    // Defer for resolution.
    this.dnsSeeds.push(addr);
    return;
  }

  addr = NetAddress.fromHost(addr.host, addr.port, this.network);

  this.add(addr);

  return addr;
};

/**
 * Add a priority node.
 * @param {String} host
 */

HostList.prototype.addNode = function addNode(host) {
  var addr = IP.fromHostname(host, this.network.port);

  if (addr.type === IP.types.DNS) {
    // Defer for resolution.
    this.dnsNodes.push(addr);
    return;
  }

  addr = NetAddress.fromHost(addr.host, addr.port, this.network);

  this.nodes.push(addr);
  this.add(addr);

  return addr;
};

/**
 * Set initial seeds.
 * @param {String[]} seeds
 */

HostList.prototype.setSeeds = function setSeeds(seeds) {
  var i, host;

  this.dnsSeeds.length = 0;

  for (i = 0; i < seeds.length; i++) {
    host = seeds[i];
    this.addSeed(host);
  }
};

/**
 * Set priority nodes.
 * @param {String[]} nodes
 */

HostList.prototype.setNodes = function setNodes(nodes) {
  var i, host;

  this.dnsNodes.length = 0;
  this.nodes.length = 0;

  for (i = 0; i < nodes.length; i++) {
    host = nodes[i];
    this.addNode(host);
  }
};

/**
 * Discover hosts from seeds and nodes.
 * @returns {Promise}
 */

HostList.prototype.discover = co(function* discover() {
  var jobs = [];
  var i, node, seed;

  for (i = 0; i < this.dnsSeeds.length; i++) {
    seed = this.dnsSeeds[i];
    jobs.push(this.populateSeed(seed));
  }

  for (i = 0; i < this.dnsNodes.length; i++) {
    node = this.dnsNodes[i];
    jobs.push(this.populateNode(node));
  }

  this.dnsNodes.length = 0;

  yield Promise.all(jobs);
});

/**
 * Lookup node's domain.
 * @param {Object} addr
 * @returns {Promise}
 */

HostList.prototype.populateNode = co(function* populateNode(addr) {
  var addrs = yield this.populate(addr);

  if (addrs.length === 0)
    return;

  this.nodes.push(addrs[0]);
  this.add(addrs[0]);
});

/**
 * Populate from seed.
 * @param {Object} seed
 * @returns {Promise}
 */

HostList.prototype.populateSeed = co(function* populateSeed(seed) {
  var addrs = yield this.populate(seed);
  var i, addr;

  for (i = 0; i < addrs.length; i++) {
    addr = addrs[i];
    this.add(addr);
  }
});

/**
 * Lookup hosts from dns host.
 * @param {Object} target
 * @returns {Promise}
 */

HostList.prototype.populate = co(function* populate(target) {
  var addrs = [];
  var i, addr, hosts, host;

  assert(target.type === IP.types.DNS, 'Resolved host passed.');

  if (this.logger)
    this.logger.info('Resolving host: %s.', target.host);

  try {
    hosts = yield this.resolve(target.host, this.proxyServer);
  } catch (e) {
    if (this.logger)
      this.logger.error(e);
    return addrs;
  }

  for (i = 0; i < hosts.length; i++) {
    host = hosts[i];
    addr = NetAddress.fromHost(host, target.port, this.network);
    addrs.push(addr);
  }

  return addrs;
});

/**
 * Convert host list to json-friendly object.
 * @returns {Object}
 */

HostList.prototype.toJSON = function toJSON() {
  var addrs = [];
  var fresh = [];
  var used = [];
  var i, keys, key, bucket, entry;

  keys = Object.keys(this.map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    addrs.push(entry.toJSON());
  }

  for (i = 0; i < this.fresh.length; i++) {
    bucket = this.fresh[i];
    keys = bucket.keys();
    fresh.push(keys);
  }

  for (i = 0; i < this.used.length; i++) {
    bucket = this.used[i];
    keys = [];
    for (entry = bucket.head; entry; entry = entry.next)
      keys.push(entry.key());
    used.push(keys);
  }

  return {
    version: 1,
    addrs: addrs,
    fresh: fresh,
    used: used
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @returns {HostList}
 */

HostList.prototype.fromJSON = function fromJSON(json) {
  var sources = {};
  var i, j, bucket, keys, key, addr, entry, src;

  assert(json && typeof json === 'object');
  assert(json.version === 1, 'Bad address serialization version.');

  assert(Array.isArray(json.addrs));

  for (i = 0; i < json.addrs.length; i++) {
    addr = json.addrs[i];
    entry = HostEntry.fromJSON(addr, this.network);
    src = sources[entry.src.hostname];

    // Save some memory.
    if (!src) {
      src = entry.src;
      sources[src.hostname] = src;
    }

    entry.src = src;

    this.map[entry.key()] = entry;
  }

  assert(Array.isArray(json.fresh));

  for (i = 0; i < json.fresh.length; i++) {
    keys = json.fresh[i];
    bucket = this.fresh[i];
    assert(bucket, 'No bucket available.');
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = this.map[key];
      assert(entry);
      if (entry.refCount === 0)
        this.totalFresh++;
      entry.refCount++;
      bucket.set(key, entry);
    }
  }

  assert(Array.isArray(json.used));

  for (i = 0; i < json.used.length; i++) {
    keys = json.used[i];
    bucket = this.used[i];
    assert(bucket, 'No bucket available.');
    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = this.map[key];
      assert(entry);
      assert(entry.refCount === 0);
      assert(!entry.used);
      entry.used = true;
      this.totalUsed++;
      bucket.push(entry);
    }
  }

  keys = Object.keys(this.map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = this.map[key];
    assert(entry.used || entry.refCount > 0);
  }

  return this;
};

/**
 * Instantiate host list from json object.
 * @param {Object} options
 * @param {Object} json
 * @returns {HostList}
 */

HostList.fromJSON = function fromJSON(options, json) {
  return new HostEntry(options).fromJSON(json);
};

/**
 * HostEntry
 * @constructor
 * @param {NetAddress} addr
 * @param {NetAddress} src
 */

function HostEntry(addr, src) {
  if (!(this instanceof HostEntry))
    return new HostEntry(addr, src);

  this.addr = addr || new NetAddress();
  this.src = src || new NetAddress();
  this.prev = null;
  this.next = null;
  this.used = false;
  this.refCount = 0;
  this.attempts = 0;
  this.lastSuccess = 0;
  this.lastAttempt = 0;

  if (addr)
    this.fromOptions(addr, src);
}

/**
 * Inject properties from options.
 * @private
 * @param {NetAddress} addr
 * @param {NetAddress} src
 * @returns {HostEntry}
 */

HostEntry.prototype.fromOptions = function fromOptions(addr, src) {
  assert(addr instanceof NetAddress);
  assert(src instanceof NetAddress);
  this.addr = addr;
  this.src = src;
  return this;
};

/**
 * Instantiate host entry from options.
 * @param {NetAddress} addr
 * @param {NetAddress} src
 * @returns {HostEntry}
 */

HostEntry.fromOptions = function fromOptions(addr, src) {
  return new HostEntry().fromOptions(addr, src);
};

/**
 * Get key suitable for a hash table (hostname).
 * @returns {String}
 */

HostEntry.prototype.key = function key() {
  return this.addr.hostname;
};

/**
 * Get host priority.
 * @param {Number} now
 * @returns {Number}
 */

HostEntry.prototype.chance = function _chance(now) {
  var attempts = this.attempts;
  var chance = 1;

  if (now - this.lastAttempt < 60 * 10)
    chance *= 0.01;

  chance *= Math.pow(0.66, Math.min(attempts, 8));

  return chance;
};

/**
 * Inspect host address.
 * @returns {Object}
 */

HostEntry.prototype.inspect = function inspect() {
  return {
    addr: this.addr,
    src: this.src,
    used: this.used,
    refCount: this.refCount,
    attempts: this.attempts,
    lastSuccess: util.date(this.lastSuccess),
    lastAttempt: util.date(this.lastAttempt)
  };
};

/**
 * Convert host entry to json-friendly object.
 * @returns {Object}
 */

HostEntry.prototype.toJSON = function toJSON() {
  return {
    addr: this.addr.hostname,
    src: this.src.hostname,
    services: this.addr.services.toString(2),
    ts: this.addr.ts,
    attempts: this.attempts,
    lastSuccess: this.lastSuccess,
    lastAttempt: this.lastAttempt
  };
};

/**
 * Inject properties from json object.
 * @private
 * @param {Object} json
 * @param {Network} network
 * @returns {HostEntry}
 */

HostEntry.prototype.fromJSON = function fromJSON(json, network) {
  assert(json && typeof json === 'object');
  assert(typeof json.addr === 'string');
  assert(typeof json.src === 'string');

  this.addr.fromHostname(json.addr, network);

  if (json.services != null) {
    assert(typeof json.services === 'string');
    assert(json.services.length > 0);
    assert(json.services.length <= 32);
    this.addr.services = parseInt(json.services, 2);
    assert(util.isUInt32(this.addr.services));
  }

  if (json.ts != null) {
    assert(util.isNumber(json.ts));
    assert(json.ts >= 0);
    this.addr.ts = json.ts;
  }

  if (json.src != null) {
    assert(typeof json.src === 'string');
    this.src.fromHostname(json.src, network);
  }

  if (json.attempts != null) {
    assert(util.isNumber(json.attempts));
    assert(json.attempts >= 0);
    this.attempts = json.attempts;
  }

  if (json.lastSuccess != null) {
    assert(util.isNumber(json.lastSuccess));
    assert(json.lastSuccess >= 0);
    this.lastSuccess = json.lastSuccess;
  }

  if (json.lastAttempt != null) {
    assert(util.isNumber(json.lastAttempt));
    assert(json.lastAttempt >= 0);
    this.lastAttempt = json.lastAttempt;
  }

  return this;
};

/**
 * Instantiate host entry from json object.
 * @param {Object} json
 * @param {Network} network
 * @returns {HostEntry}
 */

HostEntry.fromJSON = function fromJSON(json, network) {
  return new HostEntry().fromJSON(json, network);
};

/*
 * Expose
 */

module.exports = HostList;

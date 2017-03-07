/*!
 * hostlist.js - address management for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
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
var Map = require('../utils/map');
var common = require('./common');
var dns = require('./dns');
var fs = require('fs');

/**
 * Host List
 * @alias module:net.HostList
 * @constructor
 * @param {Object} options
 */

function HostList(options) {
  if (!(this instanceof HostList))
    return new HostList(options);

  this.network = Network.primary;
  this.logger = null;
  this.address = new NetAddress();
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

  this.filename = null;
  this.flushInterval = 120000;
  this.timer = null;

  this._initOptions(options);
  this._init();
}

/**
 * Serialization version.
 * @const {Number}
 * @default
 */

HostList.VERSION = 0;

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

  if (options.hostLocation != null) {
    assert(typeof options.hostLocation === 'string');
    this.filename = options.hostLocation;
  }

  if (options.flushInterval != null) {
    assert(options.flushInterval >= 0);
    this.flushInterval = options.flushInterval;
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
 * Open hostlist and read hosts file.
 * @method
 * @returns {Promise}
 */

HostList.prototype.open = co(function* open() {
  try {
    yield this.read();
  } catch (e) {
    if (this.logger) {
      this.logger.warning('Hosts deserialization failed.');
      this.logger.error(e);
    }
  }

  this.start();
});

/**
 * Close hostlist.
 * @method
 * @returns {Promise}
 */

HostList.prototype.close = co(function* close() {
  this.stop();
  yield this.flush();
});

/**
 * Start flush interval.
 */

HostList.prototype.start = function start() {
  if (!this.filename)
    return;

  assert(!this.timer);
  this.timer = setInterval(this.flush.bind(this), this.flushInterval);
};

/**
 * Stop flush interval.
 */

HostList.prototype.stop = function stop() {
  if (!this.filename)
    return;

  assert(this.timer != null);
  clearInterval(this.timer);
  this.timer = null;
};

/**
 * Read and initialie from hosts file.
 * @method
 * @returns {Promise}
 */

HostList.prototype.read = co(function* read() {
  var data, json;

  if (!this.filename)
    return;

  try {
    data = yield readFile(this.filename, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT')
      return;
    throw e;
  }

  json = JSON.parse(data);

  this.fromJSON(json);
});

/**
 * Flush addrs to hosts file.
 * @method
 * @returns {Promise}
 */

HostList.prototype.flush = co(function* flush() {
  var json, data;

  if (!this.filename)
    return;

  if (this.logger)
    this.logger.debug('Writing hosts to %s.', this.filename);

  json = this.toJSON();
  data = JSON.stringify(json);

  try {
    yield writeFile(this.filename, data, 'utf8');
  } catch (e) {
    if (this.logger) {
      this.logger.warning('Writing hosts failed.');
      this.logger.error(e);
    }
  }
});

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
  var addr = entry.addr;
  var src = entry.src;
  var data, hash, index;

  data = util.concat(addr.raw, src.raw);
  hash = murmur3(data, 0xfba4c795);
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
  var addr = entry.addr;
  var hash = murmur3(addr.raw, 0xfba4c795);
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

  assert(addr.port !== 0);

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
    if (this.isFull())
      return false;

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
 * @method
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
 * @method
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
 * @method
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
 * @method
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
    hosts = yield this.resolve(target.host);
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
    version: HostList.VERSION,
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
  var map = {};
  var fresh = [];
  var totalFresh = 0;
  var used = [];
  var totalUsed = 0;
  var i, j, bucket, keys, key, addr, entry, src;

  assert(json && typeof json === 'object');

  assert(json.version === HostList.VERSION,
    'Bad address serialization version.');

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

    map[entry.key()] = entry;
  }

  assert(Array.isArray(json.fresh));

  for (i = 0; i < json.fresh.length; i++) {
    keys = json.fresh[i];
    bucket = new Map();

    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = map[key];
      assert(entry);
      if (entry.refCount === 0)
        totalFresh++;
      entry.refCount++;
      bucket.set(key, entry);
    }

    assert(bucket.size <= this.maxEntries,
      'Bucket size mismatch.');

    fresh.push(bucket);
  }

  assert(fresh.length === this.fresh.length,
    'Buckets mismatch.');

  assert(Array.isArray(json.used));

  for (i = 0; i < json.used.length; i++) {
    keys = json.used[i];
    bucket = new List();

    for (j = 0; j < keys.length; j++) {
      key = keys[j];
      entry = map[key];
      assert(entry);
      assert(entry.refCount === 0);
      assert(!entry.used);
      entry.used = true;
      totalUsed++;
      bucket.push(entry);
    }

    assert(bucket.size <= this.maxEntries,
      'Bucket size mismatch.');

    used.push(bucket);
  }

  assert(used.length === this.used.length,
    'Buckets mismatch.');

  keys = Object.keys(map);

  for (i = 0; i < keys.length; i++) {
    key = keys[i];
    entry = map[key];
    assert(entry.used || entry.refCount > 0);
  }

  this.map = map;
  this.fresh = fresh;
  this.totalFresh = totalFresh;
  this.used = used;
  this.totalUsed = totalUsed;

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
 * @alias module:net.HostEntry
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
 * Helpers
 */

function readFile(filename, enc) {
  return new Promise(function(resolve, reject) {
    var err;

    if (fs.unsupported) {
      err = new Error('File not found.');
      err.code = 'ENOENT';
      return reject(err);
    }

    fs.readFile(filename, enc, co.wrap(resolve, reject));
  });
}

function writeFile(filename, data, enc) {
  return new Promise(function(resolve, reject) {
    if (fs.unsupported)
      return resolve();

    fs.writeFile(filename, data, enc, co.wrap(resolve, reject));
  });
}

/*
 * Expose
 */

module.exports = HostList;

/*!
 * hostlist.js - address management for bcoin
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const assert = require('assert');
const path = require('path');
const fs = require('bfile');
const IP = require('binet');
const dns = require('bdns');
const Logger = require('blgr');
const murmur3 = require('mrmr');
const List = require('blst');
const util = require('../utils/util');
const Network = require('../protocol/network');
const NetAddress = require('./netaddress');
const common = require('./common');
const seeds = require('./seeds');

/*
 * Constants
 */

const POOL32 = Buffer.allocUnsafe(32);

/**
 * Host List
 * @alias module:net.HostList
 */

class HostList {
  /**
   * Create a host list.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.options = new HostListOptions(options);
    this.network = this.options.network;
    this.logger = this.options.logger.context('hostlist');
    this.address = this.options.address;
    this.resolve = this.options.resolve;

    this.dnsSeeds = [];
    this.dnsNodes = [];

    this.map = new Map();
    this.fresh = [];
    this.totalFresh = 0;
    this.used = [];
    this.totalUsed = 0;
    this.nodes = [];
    this.local = new Map();
    this.banned = new Map();

    this.timer = null;
    this.needsFlush = false;
    this.flushing = false;

    this.init();
  }

  /**
   * Initialize list.
   * @private
   */

  init() {
    const options = this.options;
    const scores = HostList.scores;

    for (let i = 0; i < options.maxBuckets; i++)
      this.fresh.push(new Map());

    for (let i = 0; i < options.maxBuckets; i++)
      this.used.push(new List());

    this.setSeeds(options.seeds);
    this.setNodes(options.nodes);

    this.pushLocal(this.address, scores.MANUAL);
    this.addLocal(options.host, options.port, scores.BIND);

    const hosts = IP.getPublic();
    const port = this.address.port;

    for (const host of hosts)
      this.addLocal(host, port, scores.IF);
  }

  /**
   * Open hostlist and read hosts file.
   * @method
   * @returns {Promise}
   */

  async open() {
    try {
      await this.loadFile();
    } catch (e) {
      this.logger.warning('Hosts deserialization failed.');
      this.logger.error(e);
    }

    if (this.size() === 0)
      this.injectSeeds();

    await this.discoverNodes();

    this.start();
  }

  /**
   * Close hostlist.
   * @method
   * @returns {Promise}
   */

  async close() {
    this.stop();
    await this.flush();
    this.reset();
  }

  /**
   * Start flush interval.
   */

  start() {
    if (this.options.memory)
      return;

    if (!this.options.filename)
      return;

    assert(this.timer == null);
    this.timer = setInterval(() => this.flush(), this.options.flushInterval);
  }

  /**
   * Stop flush interval.
   */

  stop() {
    if (this.options.memory)
      return;

    if (!this.options.filename)
      return;

    assert(this.timer != null);
    clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * Read and initialize from hosts file.
   * @method
   * @returns {Promise}
   */

  injectSeeds() {
    const nodes = seeds.get(this.network.type);

    for (const node of nodes) {
      const addr = NetAddress.fromHostname(node, this.network);

      if (!addr.isRoutable())
        continue;

      if (!this.options.onion && addr.isOnion())
        continue;

      if (addr.port === 0)
        continue;

      this.add(addr);
    }
  }

  /**
   * Read and initialize from hosts file.
   * @method
   * @returns {Promise}
   */

  async loadFile() {
    const filename = this.options.filename;

    if (fs.unsupported)
      return;

    if (this.options.memory)
      return;

    if (!filename)
      return;

    let data;
    try {
      data = await fs.readFile(filename, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT')
        return;
      throw e;
    }

    const json = JSON.parse(data);

    this.fromJSON(json);
  }

  /**
   * Flush addrs to hosts file.
   * @method
   * @returns {Promise}
   */

  async flush() {
    const filename = this.options.filename;

    if (fs.unsupported)
      return;

    if (this.options.memory)
      return;

    if (!filename)
      return;

    if (!this.needsFlush)
      return;

    if (this.flushing)
      return;

    this.needsFlush = false;

    this.logger.debug('Writing hosts to %s.', filename);

    const json = this.toJSON();
    const data = JSON.stringify(json);

    this.flushing = true;

    try {
      await fs.writeFile(filename, data, 'utf8');
    } catch (e) {
      this.logger.warning('Writing hosts failed.');
      this.logger.error(e);
    }

    this.flushing = false;
  }

  /**
   * Get list size.
   * @returns {Number}
   */

  size() {
    return this.totalFresh + this.totalUsed;
  }

  /**
   * Test whether the host list is full.
   * @returns {Boolean}
   */

  isFull() {
    const max = this.options.maxBuckets * this.options.maxEntries;
    return this.size() >= max;
  }

  /**
   * Reset host list.
   */

  reset() {
    this.map.clear();

    for (const bucket of this.fresh)
      bucket.clear();

    for (const bucket of this.used)
      bucket.reset();

    this.totalFresh = 0;
    this.totalUsed = 0;

    this.nodes.length = 0;
  }

  /**
   * Mark a peer as banned.
   * @param {String} host
   */

  ban(host) {
    this.banned.set(host, util.now());
  }

  /**
   * Unban host.
   * @param {String} host
   */

  unban(host) {
    this.banned.delete(host);
  }

  /**
   * Clear banned hosts.
   */

  clearBanned() {
    this.banned.clear();
  }

  /**
   * Test whether the host is banned.
   * @param {String} host
   * @returns {Boolean}
   */

  isBanned(host) {
    const time = this.banned.get(host);

    if (time == null)
      return false;

    if (util.now() > time + this.options.banTime) {
      this.banned.delete(host);
      return false;
    }

    return true;
  }

  /**
   * Allocate a new host.
   * @returns {HostEntry}
   */

  getHost() {
    let buckets = null;

    if (this.totalFresh > 0)
      buckets = this.fresh;

    if (this.totalUsed > 0) {
      if (this.totalFresh === 0 || random(2) === 0)
        buckets = this.used;
    }

    if (!buckets)
      return null;

    const now = this.network.now();

    let factor = 1;

    for (;;) {
      const i = random(buckets.length);
      const bucket = buckets[i];

      if (bucket.size === 0)
        continue;

      let index = random(bucket.size);
      let entry;

      if (buckets === this.used) {
        entry = bucket.head;
        while (index--)
          entry = entry.next;
      } else {
        for (entry of bucket.values()) {
          if (index === 0)
            break;
          index -= 1;
        }
      }

      const num = random(1 << 30);

      if (num < factor * entry.chance(now) * (1 << 30))
        return entry;

      factor *= 1.2;
    }
  }

  /**
   * Get fresh bucket for host.
   * @private
   * @param {HostEntry} entry
   * @returns {Map}
   */

  freshBucket(entry) {
    const addr = entry.addr;
    const src = entry.src;
    const data = concat32(addr.raw, src.raw);
    const hash = murmur3.sum(data, 0xfba4c795);
    const index = hash % this.fresh.length;
    return this.fresh[index];
  }

  /**
   * Get used bucket for host.
   * @private
   * @param {HostEntry} entry
   * @returns {List}
   */

  usedBucket(entry) {
    const addr = entry.addr;
    const hash = murmur3.sum(addr.raw, 0xfba4c795);
    const index = hash % this.used.length;
    return this.used[index];
  }

  /**
   * Add host to host list.
   * @param {NetAddress} addr
   * @param {NetAddress?} src
   * @returns {Boolean}
   */

  add(addr, src) {
    assert(addr.port !== 0);

    let entry = this.map.get(addr.hostname);

    if (entry) {
      let penalty = 2 * 60 * 60;
      let interval = 24 * 60 * 60;

      // No source means we're inserting
      // this ourselves. No penalty.
      if (!src)
        penalty = 0;

      // Update services.
      entry.addr.services |= addr.services;
      entry.addr.services >>>= 0;

      // Online?
      const now = this.network.now();
      if (now - addr.time < 24 * 60 * 60)
        interval = 60 * 60;

      // Periodically update time.
      if (entry.addr.time < addr.time - interval - penalty) {
        entry.addr.time = addr.time;
        this.needsFlush = true;
      }

      // Do not update if no new
      // information is present.
      if (entry.addr.time && addr.time <= entry.addr.time)
        return false;

      // Do not update if the entry was
      // already in the "used" table.
      if (entry.used)
        return false;

      assert(entry.refCount > 0);

      // Do not update if the max
      // reference count is reached.
      if (entry.refCount === HostList.MAX_REFS)
        return false;

      assert(entry.refCount < HostList.MAX_REFS);

      // Stochastic test: previous refCount
      // N: 2^N times harder to increase it.
      let factor = 1;
      for (let i = 0; i < entry.refCount; i++)
        factor *= 2;

      if (random(factor) !== 0)
        return false;
    } else {
      if (this.isFull())
        return false;

      if (!src)
        src = this.address;

      entry = new HostEntry(addr, src);

      this.totalFresh += 1;
    }

    const bucket = this.freshBucket(entry);

    if (bucket.has(entry.key()))
      return false;

    if (bucket.size >= this.options.maxEntries)
      this.evictFresh(bucket);

    bucket.set(entry.key(), entry);
    entry.refCount += 1;

    this.map.set(entry.key(), entry);
    this.needsFlush = true;

    return true;
  }

  /**
   * Evict a host from fresh bucket.
   * @param {Map} bucket
   */

  evictFresh(bucket) {
    let old = null;

    for (const entry of bucket.values()) {
      if (this.isStale(entry)) {
        bucket.delete(entry.key());

        if (--entry.refCount === 0) {
          this.map.delete(entry.key());
          this.totalFresh -= 1;
        }

        continue;
      }

      if (!old) {
        old = entry;
        continue;
      }

      if (entry.addr.time < old.addr.time)
        old = entry;
    }

    if (!old)
      return;

    bucket.delete(old.key());

    if (--old.refCount === 0) {
      this.map.delete(old.key());
      this.totalFresh -= 1;
    }
  }

  /**
   * Test whether a host is evictable.
   * @param {HostEntry} entry
   * @returns {Boolean}
   */

  isStale(entry) {
    const now = this.network.now();

    if (entry.lastAttempt && entry.lastAttempt >= now - 60)
      return false;

    if (entry.addr.time > now + 10 * 60)
      return true;

    if (entry.addr.time === 0)
      return true;

    if (now - entry.addr.time > HostList.HORIZON_DAYS * 24 * 60 * 60)
      return true;

    if (entry.lastSuccess === 0 && entry.attempts >= HostList.RETRIES)
      return true;

    if (now - entry.lastSuccess > HostList.MIN_FAIL_DAYS * 24 * 60 * 60) {
      if (entry.attempts >= HostList.MAX_FAILURES)
        return true;
    }

    return false;
  }

  /**
   * Remove host from host list.
   * @param {String} hostname
   * @returns {NetAddress}
   */

  remove(hostname) {
    const entry = this.map.get(hostname);

    if (!entry)
      return null;

    if (entry.used) {
      let head = entry;

      assert(entry.refCount === 0);

      while (head.prev)
        head = head.prev;

      for (const bucket of this.used) {
        if (bucket.head === head) {
          bucket.remove(entry);
          this.totalUsed -= 1;
          head = null;
          break;
        }
      }

      assert(!head);
    } else {
      for (const bucket of this.fresh) {
        if (bucket.delete(entry.key()))
          entry.refCount -= 1;
      }

      this.totalFresh -= 1;
      assert(entry.refCount === 0);
    }

    this.map.delete(entry.key());

    return entry.addr;
  }

  /**
   * Mark host as failed.
   * @param {String} hostname
   */

  markAttempt(hostname) {
    const entry = this.map.get(hostname);
    const now = this.network.now();

    if (!entry)
      return;

    entry.attempts += 1;
    entry.lastAttempt = now;
  }

  /**
   * Mark host as successfully connected.
   * @param {String} hostname
   */

  markSuccess(hostname) {
    const entry = this.map.get(hostname);
    const now = this.network.now();

    if (!entry)
      return;

    if (now - entry.addr.time > 20 * 60)
      entry.addr.time = now;
  }

  /**
   * Mark host as successfully ack'd.
   * @param {String} hostname
   * @param {Number} services
   */

  markAck(hostname, services) {
    const entry = this.map.get(hostname);

    if (!entry)
      return;

    const now = this.network.now();

    entry.addr.services |= services;
    entry.addr.services >>>= 0;

    entry.lastSuccess = now;
    entry.lastAttempt = now;
    entry.attempts = 0;

    if (entry.used)
      return;

    assert(entry.refCount > 0);

    // Remove from fresh.
    let old = null;
    for (const bucket of this.fresh) {
      if (bucket.delete(entry.key())) {
        entry.refCount -= 1;
        old = bucket;
      }
    }

    assert(old);
    assert(entry.refCount === 0);
    this.totalFresh -= 1;

    // Find room in used bucket.
    const bucket = this.usedBucket(entry);

    if (bucket.size < this.options.maxEntries) {
      entry.used = true;
      bucket.push(entry);
      this.totalUsed += 1;
      return;
    }

    // No room. Evict.
    const evicted = this.evictUsed(bucket);

    let fresh = this.freshBucket(evicted);

    // Move to entry's old bucket if no room.
    if (fresh.size >= this.options.maxEntries)
      fresh = old;

    // Swap to evicted's used bucket.
    entry.used = true;
    bucket.replace(evicted, entry);

    // Move evicted to fresh bucket.
    evicted.used = false;
    fresh.set(evicted.key(), evicted);
    assert(evicted.refCount === 0);
    evicted.refCount += 1;
    this.totalFresh += 1;
  }

  /**
   * Pick used for eviction.
   * @param {List} bucket
   */

  evictUsed(bucket) {
    let old = bucket.head;

    for (let entry = bucket.head; entry; entry = entry.next) {
      if (entry.addr.time < old.addr.time)
        old = entry;
    }

    return old;
  }

  /**
   * Convert address list to array.
   * @returns {NetAddress[]}
   */

  toArray() {
    const out = [];

    for (const entry of this.map.values())
      out.push(entry.addr);

    assert.strictEqual(out.length, this.size());

    return out;
  }

  /**
   * Add a preferred seed.
   * @param {String} host
   */

  addSeed(host) {
    const ip = IP.fromHostname(host, this.network.port);

    if (ip.type === IP.types.DNS) {
      // Defer for resolution.
      this.dnsSeeds.push(ip);
      return null;
    }

    const addr = NetAddress.fromHost(ip.host, ip.port, this.network);

    this.add(addr);

    return addr;
  }

  /**
   * Add a priority node.
   * @param {String} host
   * @returns {NetAddress}
   */

  addNode(host) {
    const ip = IP.fromHostname(host, this.network.port);

    if (ip.type === IP.types.DNS) {
      // Defer for resolution.
      this.dnsNodes.push(ip);
      return null;
    }

    const addr = NetAddress.fromHost(ip.host, ip.port, this.network);

    this.nodes.push(addr);
    this.add(addr);

    return addr;
  }

  /**
   * Remove a priority node.
   * @param {String} host
   * @returns {Boolean}
   */

  removeNode(host) {
    const addr = IP.fromHostname(host, this.network.port);

    for (let i = 0; i < this.nodes.length; i++) {
      const node = this.nodes[i];

      if (node.host !== addr.host)
        continue;

      if (node.port !== addr.port)
        continue;

      this.nodes.splice(i, 1);

      return true;
    }

    return false;
  }

  /**
   * Set initial seeds.
   * @param {String[]} seeds
   */

  setSeeds(seeds) {
    this.dnsSeeds.length = 0;

    for (const host of seeds)
      this.addSeed(host);
  }

  /**
   * Set priority nodes.
   * @param {String[]} nodes
   */

  setNodes(nodes) {
    this.dnsNodes.length = 0;
    this.nodes.length = 0;

    for (const host of nodes)
      this.addNode(host);
  }

  /**
   * Add a local address.
   * @param {String} host
   * @param {Number} port
   * @param {Number} score
   * @returns {Boolean}
   */

  addLocal(host, port, score) {
    const addr = NetAddress.fromHost(host, port, this.network);
    addr.services = this.options.services;
    return this.pushLocal(addr, score);
  }

  /**
   * Add a local address.
   * @param {NetAddress} addr
   * @param {Number} score
   * @returns {Boolean}
   */

  pushLocal(addr, score) {
    if (!addr.isRoutable())
      return false;

    if (this.local.has(addr.hostname))
      return false;

    const local = new LocalAddress(addr, score);

    this.local.set(addr.hostname, local);

    return true;
  }

  /**
   * Get local address based on reachability.
   * @param {NetAddress?} src
   * @returns {NetAddress}
   */

  getLocal(src) {
    let bestReach = -1;
    let bestScore = -1;
    let bestDest = null;

    if (!src)
      src = this.address;

    if (this.local.size === 0)
      return null;

    for (const dest of this.local.values()) {
      const reach = src.getReachability(dest.addr);

      if (reach < bestReach)
        continue;

      if (reach > bestReach || dest.score > bestScore) {
        bestReach = reach;
        bestScore = dest.score;
        bestDest = dest.addr;
      }
    }

    bestDest.time = this.network.now();

    return bestDest;
  }

  /**
   * Mark local address as seen during a handshake.
   * @param {NetAddress} addr
   * @returns {Boolean}
   */

  markLocal(addr) {
    const local = this.local.get(addr.hostname);

    if (!local)
      return false;

    local.score += 1;

    return true;
  }

  /**
   * Discover hosts from seeds.
   * @method
   * @returns {Promise}
   */

  async discoverSeeds() {
    const jobs = [];

    for (const seed of this.dnsSeeds)
      jobs.push(this.populateSeed(seed));

    return Promise.all(jobs);
  }

  /**
   * Discover hosts from nodes.
   * @method
   * @returns {Promise}
   */

  async discoverNodes() {
    const jobs = [];

    for (const node of this.dnsNodes)
      jobs.push(this.populateNode(node));

    return Promise.all(jobs);
  }

  /**
   * Lookup node's domain.
   * @method
   * @param {Object} addr
   * @returns {Promise}
   */

  async populateNode(addr) {
    const addrs = await this.populate(addr);

    if (addrs.length === 0)
      return;

    this.nodes.push(addrs[0]);
    this.add(addrs[0]);
  }

  /**
   * Populate from seed.
   * @method
   * @param {Object} seed
   * @returns {Promise}
   */

  async populateSeed(seed) {
    const addrs = await this.populate(seed);

    for (const addr of addrs)
      this.add(addr);
  }

  /**
   * Lookup hosts from dns host.
   * @method
   * @param {Object} target
   * @returns {Promise}
   */

  async populate(target) {
    const addrs = [];

    assert(target.type === IP.types.DNS, 'Resolved host passed.');

    this.logger.info('Resolving host: %s.', target.host);

    let hosts;
    try {
      hosts = await this.resolve(target.host);
    } catch (e) {
      this.logger.error(e);
      return addrs;
    }

    for (const host of hosts) {
      const addr = NetAddress.fromHost(host, target.port, this.network);
      addrs.push(addr);
    }

    return addrs;
  }

  /**
   * Convert host list to json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    const addrs = [];
    const fresh = [];
    const used = [];

    for (const entry of this.map.values())
      addrs.push(entry.toJSON());

    for (const bucket of this.fresh) {
      const keys = [];
      for (const key of bucket.keys())
        keys.push(key);
      fresh.push(keys);
    }

    for (const bucket of this.used) {
      const keys = [];
      for (let entry = bucket.head; entry; entry = entry.next)
        keys.push(entry.key());
      used.push(keys);
    }

    return {
      version: HostList.VERSION,
      network: this.network.type,
      addrs: addrs,
      fresh: fresh,
      used: used
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @returns {HostList}
   */

  fromJSON(json) {
    const sources = new Map();
    const map = new Map();
    const fresh = [];
    const used = [];

    let totalFresh = 0;
    let totalUsed = 0;

    assert(json && typeof json === 'object');

    assert(!json.network || json.network === this.network.type,
      'Network mistmatch.');

    assert(json.version === HostList.VERSION,
      'Bad address serialization version.');

    assert(Array.isArray(json.addrs));

    for (const addr of json.addrs) {
      const entry = HostEntry.fromJSON(addr, this.network);

      let src = sources.get(entry.src.hostname);

      // Save some memory.
      if (!src) {
        src = entry.src;
        sources.set(src.hostname, src);
      }

      entry.src = src;

      map.set(entry.key(), entry);
    }

    assert(Array.isArray(json.fresh));
    assert(json.fresh.length <= this.options.maxBuckets,
      'Buckets mismatch.');

    for (const keys of json.fresh) {
      const bucket = new Map();

      for (const key of keys) {
        const entry = map.get(key);
        assert(entry);
        if (entry.refCount === 0)
          totalFresh += 1;
        entry.refCount += 1;
        bucket.set(key, entry);
      }

      assert(bucket.size <= this.options.maxEntries,
        'Bucket size mismatch.');

      fresh.push(bucket);
    }

    assert(fresh.length === this.fresh.length,
      'Buckets mismatch.');

    assert(Array.isArray(json.used));
    assert(json.used.length <= this.options.maxBuckets,
      'Buckets mismatch.');

    for (const keys of json.used) {
      const bucket = new List();

      for (const key of keys) {
        const entry = map.get(key);
        assert(entry);
        assert(entry.refCount === 0);
        assert(!entry.used);
        entry.used = true;
        totalUsed += 1;
        bucket.push(entry);
      }

      assert(bucket.size <= this.options.maxEntries,
        'Bucket size mismatch.');

      used.push(bucket);
    }

    assert(used.length === this.used.length,
      'Buckets mismatch.');

    for (const entry of map.values())
      assert(entry.used || entry.refCount > 0);

    this.map = map;
    this.fresh = fresh;
    this.totalFresh = totalFresh;
    this.used = used;
    this.totalUsed = totalUsed;

    return this;
  }

  /**
   * Instantiate host list from json object.
   * @param {Object} options
   * @param {Object} json
   * @returns {HostList}
   */

  static fromJSON(options, json) {
    return new this(options).fromJSON(json);
  }
}

/**
 * Number of days before considering
 * an address stale.
 * @const {Number}
 * @default
 */

HostList.HORIZON_DAYS = 30;

/**
 * Number of retries (without success)
 * before considering an address stale.
 * @const {Number}
 * @default
 */

HostList.RETRIES = 3;

/**
 * Number of days after reaching
 * MAX_FAILURES to consider an
 * address stale.
 * @const {Number}
 * @default
 */

HostList.MIN_FAIL_DAYS = 7;

/**
 * Maximum number of failures
 * allowed before considering
 * an address stale.
 * @const {Number}
 * @default
 */

HostList.MAX_FAILURES = 10;

/**
 * Maximum number of references
 * in fresh buckets.
 * @const {Number}
 * @default
 */

HostList.MAX_REFS = 8;

/**
 * Serialization version.
 * @const {Number}
 * @default
 */

HostList.VERSION = 0;

/**
 * Local address scores.
 * @enum {Number}
 * @default
 */

HostList.scores = {
  NONE: 0,
  IF: 1,
  BIND: 2,
  UPNP: 3,
  DNS: 3,
  MANUAL: 4,
  MAX: 5
};

/**
 * Host Entry
 * @alias module:net.HostEntry
 */

class HostEntry {
  /**
   * Create a host entry.
   * @constructor
   * @param {NetAddress} addr
   * @param {NetAddress} src
   */

  constructor(addr, src) {
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

  fromOptions(addr, src) {
    assert(addr instanceof NetAddress);
    assert(src instanceof NetAddress);
    this.addr = addr;
    this.src = src;
    return this;
  }

  /**
   * Instantiate host entry from options.
   * @param {NetAddress} addr
   * @param {NetAddress} src
   * @returns {HostEntry}
   */

  static fromOptions(addr, src) {
    return new this().fromOptions(addr, src);
  }

  /**
   * Get key suitable for a hash table (hostname).
   * @returns {String}
   */

  key() {
    return this.addr.hostname;
  }

  /**
   * Get host priority.
   * @param {Number} now
   * @returns {Number}
   */

  chance(now) {
    let c = 1;

    if (now - this.lastAttempt < 60 * 10)
      c *= 0.01;

    c *= Math.pow(0.66, Math.min(this.attempts, 8));

    return c;
  }

  /**
   * Inspect host address.
   * @returns {Object}
   */

  inspect() {
    return {
      addr: this.addr,
      src: this.src,
      used: this.used,
      refCount: this.refCount,
      attempts: this.attempts,
      lastSuccess: util.date(this.lastSuccess),
      lastAttempt: util.date(this.lastAttempt)
    };
  }

  /**
   * Convert host entry to json-friendly object.
   * @returns {Object}
   */

  toJSON() {
    return {
      addr: this.addr.hostname,
      src: this.src.hostname,
      services: this.addr.services.toString(2),
      time: this.addr.time,
      attempts: this.attempts,
      lastSuccess: this.lastSuccess,
      lastAttempt: this.lastAttempt
    };
  }

  /**
   * Inject properties from json object.
   * @private
   * @param {Object} json
   * @param {Network} network
   * @returns {HostEntry}
   */

  fromJSON(json, network) {
    assert(json && typeof json === 'object');
    assert(typeof json.addr === 'string');
    assert(typeof json.src === 'string');

    this.addr.fromHostname(json.addr, network);

    if (json.services != null) {
      assert(typeof json.services === 'string');
      assert(json.services.length > 0);
      assert(json.services.length <= 32);
      const services = parseInt(json.services, 2);
      assert((services >>> 0) === services);
      this.addr.services = services;
    }

    if (json.time != null) {
      assert(Number.isSafeInteger(json.time));
      assert(json.time >= 0);
      this.addr.time = json.time;
    }

    if (json.src != null) {
      assert(typeof json.src === 'string');
      this.src.fromHostname(json.src, network);
    }

    if (json.attempts != null) {
      assert((json.attempts >>> 0) === json.attempts);
      this.attempts = json.attempts;
    }

    if (json.lastSuccess != null) {
      assert(Number.isSafeInteger(json.lastSuccess));
      assert(json.lastSuccess >= 0);
      this.lastSuccess = json.lastSuccess;
    }

    if (json.lastAttempt != null) {
      assert(Number.isSafeInteger(json.lastAttempt));
      assert(json.lastAttempt >= 0);
      this.lastAttempt = json.lastAttempt;
    }

    return this;
  }

  /**
   * Instantiate host entry from json object.
   * @param {Object} json
   * @param {Network} network
   * @returns {HostEntry}
   */

  static fromJSON(json, network) {
    return new this().fromJSON(json, network);
  }
}

/**
 * Local Address
 * @alias module:net.LocalAddress
 */

class LocalAddress {
  /**
   * Create a local address.
   * @constructor
   * @param {NetAddress} addr
   * @param {Number?} score
   */

  constructor(addr, score) {
    this.addr = addr;
    this.score = score || 0;
  }
}

/**
 * Host List Options
 * @alias module:net.HostListOptions
 */

class HostListOptions {
  /**
   * Create host list options.
   * @constructor
   * @param {Object?} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;
    this.resolve = dns.lookup;
    this.host = '0.0.0.0';
    this.port = this.network.port;
    this.services = common.LOCAL_SERVICES;
    this.onion = false;
    this.banTime = common.BAN_TIME;

    this.address = new NetAddress();
    this.address.services = this.services;
    this.address.time = this.network.now();

    this.seeds = this.network.seeds;
    this.nodes = [];

    this.maxBuckets = 20;
    this.maxEntries = 50;

    this.prefix = null;
    this.filename = null;
    this.memory = true;
    this.flushInterval = 120000;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    assert(options, 'Options are required.');

    if (options.network != null) {
      this.network = Network.get(options.network);
      this.seeds = this.network.seeds;
      this.address.port = this.network.port;
      this.port = this.network.port;
    }

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
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
      this.seeds = options.seeds;
    }

    if (options.nodes) {
      assert(Array.isArray(options.nodes));
      this.nodes = options.nodes;
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      const raw = IP.toBuffer(options.host);
      this.host = IP.toString(raw);
      if (IP.isRoutable(raw))
        this.address.setHost(this.host);
    }

    if (options.port != null) {
      assert(typeof options.port === 'number');
      assert(options.port > 0 && options.port <= 0xffff);
      this.port = options.port;
      this.address.setPort(this.port);
    }

    if (options.publicHost != null) {
      assert(typeof options.publicHost === 'string');
      this.address.setHost(options.publicHost);
    }

    if (options.publicPort != null) {
      assert(typeof options.publicPort === 'number');
      assert(options.publicPort > 0 && options.publicPort <= 0xffff);
      this.address.setPort(options.publicPort);
    }

    if (options.services != null) {
      assert(typeof options.services === 'number');
      this.services = options.services;
    }

    if (options.onion != null) {
      assert(typeof options.onion === 'boolean');
      this.onion = options.onion;
    }

    if (options.maxBuckets != null) {
      assert(typeof options.maxBuckets === 'number');
      this.maxBuckets = options.maxBuckets;
    }

    if (options.maxEntries != null) {
      assert(typeof options.maxEntries === 'number');
      this.maxEntries = options.maxEntries;
    }

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.filename = path.join(this.prefix, 'hosts.json');
    }

    if (options.filename != null) {
      assert(typeof options.filename === 'string');
      this.filename = options.filename;
    }

    if (options.flushInterval != null) {
      assert(options.flushInterval >= 0);
      this.flushInterval = options.flushInterval;
    }

    this.address.time = this.network.now();
    this.address.services = this.services;

    return this;
  }
}

/*
 * Helpers
 */

function concat32(left, right) {
  const data = POOL32;
  left.copy(data, 0);
  right.copy(data, 32);
  return data;
}

function random(max) {
  return Math.floor(Math.random() * max);
}

/*
 * Expose
 */

module.exports = HostList;

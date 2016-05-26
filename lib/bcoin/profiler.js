/*!
 * profiler.js - profiler for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/indutny/bcoin
 */

/**
 * @exports profiler
 */

var profiler = exports;

var bcoin = require('./env');
var utils = require('./utils');
var assert = utils.assert;
var fs, v8profiler;

function ensure() {
  if (v8profiler)
    return;

  if (bcoin.profile && !bcoin.isBrowser) {
    v8profiler = require('v8-' + 'profiler');
    fs = require('f' + 's');
  }
}

/**
 * A CPU profile.
 * @exports Profile
 * @constructor
 * @param {String?} name
 */

function Profile(name) {
  if (v8profiler && bcoin.profile) {
    name = 'profile-' + (name ? name + '-' : '') + Profile.uid++;
    bcoin.debug('Starting CPU profile: %s', name);
    this.profile = v8profiler.startProfiling(name, true);
    this.name = name;
  }
}

Profile.uid = 0;

/**
 * Stop profiling.
 */

Profile.prototype.stopProfiling = function stopProfiling() {
  if (!v8profiler)
    return;

  this.profile = v8profiler.stopProfiling(this.name);
};

/**
 * Free up profile.
 */

Profile.prototype.del = function del() {
  if (!v8profiler)
    return;

  this.profile['delete']();
};

/**
 * Save profile as json (.cpuprofile) to `prefix`.
 * @param {Function} callback
 */

Profile.prototype.save = function save(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!v8profiler)
    return callback();

  if (!this.profile)
    this.stopProfiling();

  bcoin.debug('Saving CPU profile: %s', this.name);

  return this.profile['export'](function(err, result) {
    var file;

    self.profile['delete']();
    delete self.profile;

    if (err)
      return callback(err);

    file = bcoin.prefix + '/' + self.name + '.cpuprofile';

    fs.writeFile(file, result, callback);
  });
};

/**
 * Memory Snapshot
 * @exports Snapshot
 * @constructor
 * @param {String?} name
 */

function Snapshot(name) {
  if (v8profiler && bcoin.profile) {
    name = 'snapshot-' + (name ? name + '-' : '') + Snapshot.uid++;
    bcoin.debug('Taking heap snapshot: %s', name);
    this.snapshot = v8profiler.takeSnapshot(name);
    this.name = name;
  }
}

Snapshot.uid = 0;

/**
 * Compare two snapshots.
 * @param {Snapshot}
 * @returns {Object}
 */

Snapshot.prototype.compare = function compare(other) {
  if (!v8profiler)
    return;

  assert(this.snapshot);

  return this.snapshot.compare(other.snapshot);
};

/**
 * Get header.
 * @returns {Object}
 */

Snapshot.prototype.getHeader = function getHeader() {
  if (!v8profiler)
    return;

  assert(this.snapshot);

  return this.snapshot.getHeader();
};

/**
 * Free up snapshot.
 */

Snapshot.prototype.del = function del() {
  if (!v8profiler)
    return;

  assert(this.snapshot);

  return this.snapshot['delete']();
};

/**
 * Save snapshot as json (.heapsnapshot) to `prefix`.
 * @param {Function} callback
 */

Snapshot.prototype.save = function save(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!v8profiler)
    return callback();

  assert(this.snapshot);

  bcoin.debug('Saving heap snapshot: %s', this.name);

  return this.snapshot['export'](function(err, result) {
    var file;

    self.snapshot['delete']();
    delete self.snapshot;

    if (err)
      return callback(err);

    file = bcoin.prefix + '/' + self.name + '.heapsnapshot';

    fs.writeFile(file, result, callback);
  });
};

/**
 * Create a new CPU profile and begin profiling.
 * @param {String?} name
 * @returns {Profile}
 */

profiler.startProfiling = function startProfiling(name) {
  ensure();
  return new Profile(name);
};

/**
 * Create a new memory snapshot.
 * @param {String?} name
 * @returns {Snapshot}
 */

profiler.takeSnapshot = function takeSnapshot(name) {
  ensure();
  return new Snapshot(name);
};

/**
 * Take a snapshot and save it to disk.
 * @param {String?} name
 * @param {Function?} callback
 */

profiler.snapshot = function snapshot(name, callback) {
  var snapshot, mem;

  ensure();

  if (typeof name === 'function') {
    callback = name;
    name = null;
  }

  if (bcoin.debugLogs) {
    mem = process.memoryUsage();
    bcoin.debug('Memory: rss=%dmb, js-heap=%d/%dmb native-heap=%dmb',
      utils.mb(mem.rss),
      utils.mb(mem.heapUsed),
      utils.mb(mem.heapTotal),
      utils.mb(mem.rss - mem.heapTotal));
  }

  if (!v8profiler || !bcoin.profile)
    return callback ? utils.nextTick(callback) : null;

  snapshot = new Snapshot(name);
  snapshot.save(callback);
};

/*!
 * profiler.js - profiler for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
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
    name = 'profile-' + (name ? name + '-' : '') + utils.ms();
    bcoin.debug('Starting CPU profile: %s', name);
    v8profiler.startProfiling(name, true);
    this.name = name;
    this.profile = null;
    this.finished = false;
  }
}

/**
 * Stop profiling.
 */

Profile.prototype.stop = function stop() {
  if (!v8profiler)
    return;

  assert(!this.finished);

  this.profile = v8profiler.stopProfiling(this.name);
};

/**
 * Free up profile.
 */

Profile.prototype.del = function del() {
  if (!v8profiler)
    return;

  assert(!this.finished);

  if (!this.profile)
    this.stop();

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

  assert(!this.finished);

  if (!this.profile)
    this.stop();

  bcoin.debug('Saving CPU profile: %s', this.name);

  return this.profile['export'](function(err, result) {
    var file;

    self.profile['delete']();
    self.profile = null;
    self.finished = true;

    if (err)
      return callback(err);

    file = bcoin.prefix
      + '/profiler/'
      + self.name
      + '.cpuprofile';

    bcoin.mkdir(file, true);

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
    name = 'snapshot-' + (name ? name + '-' : '') + utils.ms();
    bcoin.debug('Taking heap snapshot: %s', name);
    this.snapshot = v8profiler.takeSnapshot(name);
    this.name = name;
  }
}

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
    self.snapshot = null;

    if (err)
      return callback(err);

    file = bcoin.prefix
      + '/profiler/'
      + self.name
      + '.heapsnapshot';

    bcoin.mkdir(file, true);

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

  if (bcoin.debugLogs && process.memoryUsage) {
    mem = process.memoryUsage();
    bcoin.debug('Memory: rss=%dmb, js-heap=%d/%dmb native-heap=%dmb',
      utils.mb(mem.rss),
      utils.mb(mem.heapUsed),
      utils.mb(mem.heapTotal),
      utils.mb(mem.rss - mem.heapTotal));
  }

  if (!v8profiler || !bcoin.profile)
    return utils.asyncify(callback)();

  snapshot = new Snapshot(name);
  snapshot.save(callback);
};

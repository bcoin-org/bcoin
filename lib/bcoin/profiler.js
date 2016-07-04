/*!
 * profiler.js - profiler for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2016, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

var utils = require('./utils');
var assert = utils.assert;
var fs, v8profiler;

function ensure() {
  if (v8profiler)
    return;

  if (!utils.isBrowser) {
    v8profiler = require('v8-' + 'profiler');
    fs = require('f' + 's');
  }
}

/**
 * A CPU profile.
 * @exports Profile
 * @constructor
 * @param {String} prefix
 * @param {String?} name
 */

function Profile(prefix, name) {
  if (v8profiler) {
    name = 'profile-' + (name ? name + '-' : '') + utils.ms();
    v8profiler.startProfiling(name, true);
    this.prefix = prefix;
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

  return this.profile['export'](function(err, result) {
    var file;

    self.profile['delete']();
    self.profile = null;
    self.finished = true;

    if (err)
      return callback(err);

    file = self.prefix
      + '/profiler/'
      + self.name
      + '.cpuprofile';

    utils.mkdir(file, true);

    fs.writeFile(file, result, callback);
  });
};

/**
 * Memory Snapshot
 * @exports Snapshot
 * @constructor
 * @param {String} prefix
 * @param {String?} name
 */

function Snapshot(prefix, name) {
  if (v8profiler) {
    name = 'snapshot-' + (name ? name + '-' : '') + utils.ms();
    this.snapshot = v8profiler.takeSnapshot(name);
    this.prefix = prefix;
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

  return this.snapshot['export'](function(err, result) {
    var file;

    self.snapshot['delete']();
    self.snapshot = null;

    if (err)
      return callback(err);

    file = self.prefix
      + '/profiler/'
      + self.name
      + '.heapsnapshot';

    utils.mkdir(file, true);

    fs.writeFile(file, result, callback);
  });
};

/**
 * Profiler
 * @exports Profiler
 * @constructor
 * @param {String} prefix
 */

function Profiler(prefix) {
  if (!(this instanceof Profiler))
    return new Profiler(prefix);

  this.prefix = prefix || utils.HOME;
}

/**
 * Create a new CPU profile and begin profiling.
 * @param {String?} name
 * @returns {Profile}
 */

Profiler.prototype.startProfiling = function startProfiling(name) {
  ensure();
  return new Profile(this.prefix, name);
};

/**
 * Create a new memory snapshot.
 * @param {String?} name
 * @returns {Snapshot}
 */

Profiler.prototype.takeSnapshot = function takeSnapshot(name) {
  ensure();
  return new Snapshot(this.prefix, name);
};

/**
 * Take a snapshot and save it to disk.
 * @param {String?} name
 * @param {Function?} callback
 */

Profiler.prototype.snapshot = function snapshot(name, callback) {
  if (typeof name === 'function') {
    callback = name;
    name = null;
  }

  ensure();

  if (!v8profiler) {
    if (!callback)
      return;
    return utils.nextTick(callback);
  }

  this.takeSnapshot(name).save(callback);
};

/*
 * Expose
 */

module.exports = Profiler;

/**
 * profiler.js - profiler for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * https://github.com/indutny/bcoin
 */

var bcoin = require('../bcoin');
var utils = bcoin.utils;
var assert = utils.assert;
var fs = bcoin.fs;
var profiler;

if (bcoin.profile && !bcoin.isBrowser)
  profiler = require('v8-' + 'profiler');

if (profiler) {
  utils.nextTick(function() {
    utils.debug('Starting node with profiler enabled.');
  });
}

/**
 * Profile
 */

function Profile(name) {
  if (profiler) {
    name = 'profile-' + (name ? name + '-' : '') + Profile.uid++;
    this.profile = profiler.startProfiling(name, true);
    this.name = name;
    utils.debug('Starting CPU profile: %s', this.name);
  }
}

Profile.uid = 0;

Profile.prototype.stopProfiling = function stopProfiling() {
  if (!profiler)
    return;

  assert(this.profile);

  return this.profile.stopProfiling();
};

Profile.prototype.del = function del() {
  if (!profiler)
    return;

  assert(this.profile);

  return this.profile['delete']();
};

Profile.prototype.save = function save(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!profiler)
    return callback();

  assert(this.profile);

  utils.debug('Saving CPU profile: %s', this.name);

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
 * Snapshot
 */

function Snapshot(name) {
  if (profiler) {
    name = 'snapshot-' + (name ? name + '-' : '') + Snapshot.uid++;
    this.snapshot = profiler.takeSnapshot(name);
    this.name = name;
    utils.debug('Taking heap snapshot: %s', this.name);
  }
}

Snapshot.uid = 0;

Snapshot.prototype.compare = function compare(other) {
  if (!profiler)
    return;

  assert(this.snapshot);

  return this.snapshot.compare(other.snapshot);
};

Snapshot.prototype.getHeader = function getHeader() {
  if (!profiler)
    return;

  assert(this.snapshot);

  return this.snapshot.getHeader();
};

Snapshot.prototype.del = function del() {
  if (!profiler)
    return;

  assert(this.snapshot);

  return this.snapshot['delete']();
};

Snapshot.prototype.save = function save(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!profiler)
    return callback();

  assert(this.snapshot);

  utils.debug('Saving heap snapshot: %s', this.name);

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
 * Expose
 */

exports.startProfiling = function startProfiling(name) {
  return new Profile(name);
};

exports.takeSnapshot = function takeSnapshot(name) {
  return new Snapshot(name);
};

exports.snapshot = function snapshot(name, callback) {
  var snapshot;

  if (typeof name === 'function') {
    callback = name;
    name = null;
  }

  if (!profiler)
    return callback ? utils.nextTick(callback) : null;

  snapshot = new Snapshot(name);
  snapshot.save(callback);
};

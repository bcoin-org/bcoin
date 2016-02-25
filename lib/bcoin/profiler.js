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

/**
 * Profile
 */

function Profile(name) {
  if (profiler) {
    if (!name)
      name = '';
    name += '-' + Profile.uid++;
    this.profile = profiler.startProfiling(name, true);
    this.name = name;
  }
}

Profile.uid = 0;

Profile.prototype.stopProfiling = function stopProfiling(callback) {
  if (!profiler)
    return;

  assert(this.profile);

  this.profile.stopProfiling();
};

Profile.prototype.del = function del(callback) {
  if (!profiler)
    return;

  assert(this.profile);

  this.profile['delete']();
};

Profile.prototype.save = function save(callback) {
  var self = this;

  callback = utils.asyncify(callback);

  if (!profiler)
    return callback();

  assert(this.profile);

  this.profile['export'](function(err, result) {
    var file;

    if (err) {
      self.profile['delete']();
      delete self.profile;
      return callback(err);
    }

    file = bcoin.prefix + '/profile-' + self.name + '.json';

    fs.writeFile(file, result, function(err) {
      self.profile['delete']();
      delete self.profile;
      callback(err);
    });
  });
};

/**
 * Snapshot
 */

function Snapshot(name) {
  if (profiler) {
    if (!name)
      name = '';
    name += '-' + Snapshot.uid++;
    this.snapshot = profiler.takeSnapshot(name);
    this.name = name;
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

  this.snapshot['export'](function(err, result) {
    var file;

    if (err) {
      self.profile['delete']();
      delete self.profile;
      return callback(err);
    }

    file = bcoin.prefix + '/snapshot-' + self.name + '.json';

    fs.writeFile(file, result, function(err) {
      self.snapshot['delete']();
      delete self.snapshot;
      callback(err);
    });
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

  snapshot = new Snapshot(name);
  snapshot.save(callback);
};

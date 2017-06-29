/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

self.onmessage = function onmessage(event) {
  var env;

  self.onmessage = function() {};

  env = JSON.parse(event.data);

  self.importScripts(env.BCOIN_MASTER_URL);
  self.master.listen(env);
};

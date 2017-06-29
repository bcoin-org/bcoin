/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

self.onmessage = function onmessage(event) {
  var file = '/bcoin-master.js';
  var env;

  self.onmessage = function() {};

  env = JSON.parse(event.data);

  if (env.BCOIN_MASTER_URL)
    file = env.BCOIN_MASTER_URL;

  self.importScripts(file);
  self.master.listen(env);
};

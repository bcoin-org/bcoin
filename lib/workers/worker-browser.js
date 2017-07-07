/*!
 * worker.js - worker thread/process for bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * https://github.com/bcoin-org/bcoin
 */

'use strict';

const Master = require('./master');

self.onmessage = function onmessage(event) {
  let env, server;

  self.onmessage = function() {};

  env = JSON.parse(event.data);
  server = new Master();
  server.listen(env);
};

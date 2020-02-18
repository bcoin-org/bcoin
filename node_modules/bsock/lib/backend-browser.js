'use strict';

module.exports = {
  Client: global.WebSocket || global.MozWebSocket,
  EventSource: global.EventSource
};

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const UWS = require('uws');
const UWSClient = UWS;
const UWSServer = UWS.Server;
const noop = () => {};

let server = null;

// Make UWS look like Faye.
class API extends EventEmitter {
  constructor() {
    super();

    this.ws = null;
    this.readable = true;
    this.writable = true;

    this.url = '';
    this.binaryType = 'arraybuffer';
    this.version = 'hybi-13';
    this.protocol = '';
    this.extensions = '';
    this.bufferedAmount = 0;

    this.onopen = noop;
    this.onclose = noop;
    this.onerror = noop;
    this.onmessage = noop;

    this.on('error', noop);
  }

  _open(ws, outbound) {
    assert(ws);

    this.ws = ws;

    if (outbound) {
      ws.onopen = () => {
        this.onopen();
        this.emit('open');
      };
    }

    ws.onclose = ({code, reason}) => {
      const event = {
        code: code >>> 0,
        reason: String(reason)
      };
      this.onclose(event);
      this.emit('close', event);
    };

    ws.onerror = ({message}) => {
      if (message === 'uWs client connection error')
        message = `Network error: ${this.url}: connect ECONNREFUSED`;

      const event = {
        message: String(message)
      };

      this.onerror(event);
      this.emit('error', event);
    };

    ws.onmessage = ({data}) => {
      // UWS is zero copy.
      if (typeof data !== 'string') {
        assert(data instanceof ArrayBuffer);
        const ab = Buffer.from(data);
        const raw = Buffer.allocUnsafe(ab.length);
        ab.copy(raw, 0);
        data = raw;
      }

      const event = { data };

      this.onmessage(event);
      this.emit('message', event);
    };
  }

  write(data) {
    return this.send(data);
  }

  end(data) {
    if (data !== undefined)
      this.write(data);
    this.close();
  }

  pause() {
    ;
  }

  resume() {
    ;
  }

  send(data) {
    if (!this.ws)
      return true;

    this.ws.send(data);

    return true;
  }

  get readyState() {
    if (!this.ws)
      return API.CONNECTING;

    return this.ws.readyState;
  }

  ping(msg, callback) {
    if (!this.ws)
      return false;

    if (this.readyState > API.OPEN)
      return false;

    this.ws.ping(msg);

    if (callback)
      callback();

    return true;
  }

  close() {
    if (!this.ws)
      return;

    this.ws.close();
  }

  static isWebSocket(req, socket) {
    if (socket) {
      if (socket._isNative && (!server || server.serverGroup))
        return true;
    }

    if (req.method !== 'GET')
      return false;

    const connection = req.headers.connection;

    if (!connection)
      return false;

    const conn = connection.toLowerCase().split(/ *, */);

    if (conn.indexOf('upgrade') === -1)
      return false;

    const upgrade = req.headers.upgrade;

    if (!upgrade)
      return false;

    if (upgrade.toLowerCase() !== 'websocket')
      return false;

    const key = req.headers['sec-websocket-key'];

    if (!key)
      return false;

    if (key.length !== 24)
      return false;

    if (socket && (!socket.ssl || socket._parent)) {
      const {ssl, _handle, _parent} = socket;
      const handle = ssl ? _parent._handle : _handle;

      if (!handle)
        return false;
    }

    return true;
  }
}

API.CONNECTING = 0;
API.OPEN = 1;
API.CLOSING = 2;
API.CLOSED = 3;
API.CLOSE_TIMEOUT = 3000;

class Client extends API {
  constructor(url) {
    super();

    assert(typeof url === 'string');

    url = url.replace(/^http:/, 'ws:');
    url = url.replace(/^https:/, 'wss:');

    if (url.indexOf('://') === -1)
      url = `ws://${url}`;

    url = url.replace('://localhost', '://127.0.0.1');

    this.url = url;
    this._open(new UWSClient(url), true);
  }
}

class WebSocket extends API {
  constructor(req, socket, body) {
    super();

    assert(req);

    this.url = req.url;

    if (!server)
      server = new UWSServer({ noServer: true });

    server.handleUpgrade(req, socket, body, (ws) => {
      setImmediate(() => {
        this._open(ws, false);
        this.onopen();
        this.emit('open');
      });
    });
  }
}

WebSocket.Client = Client;

module.exports = WebSocket;

'use strict';

const WebSocket = require('./backend');
const Server = require('./server');
const Socket = require('./socket');

exports.WebSocket = WebSocket;
exports.Server = Server;
exports.server = () => new Server();
exports.createServer = Server.createServer.bind(Server);
exports.attach = Server.attach.bind(Server);
exports.Socket = Socket;
exports.socket = () => new Socket();
exports.connect = Socket.connect.bind(Socket);

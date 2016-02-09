function Ramdisk(fileData, size) {
  if (!(this instanceof Ramdisk))
    return new Ramdisk(fileData, size);

  if (size < fileData.length)
    size = fileData.length + (fileData.length / 2 | 0);

  this.size = fileData.length;
  this.heap = new Buffer(size);

  fileData.copy(this.heap, 0, 0, fileData.length);
}

Ramdisk.prototype.brk = function brk() {
  var heap = new Buffer(this.heap.length + (this.heap.length / 2 | 0));
  utils.debug('brk1(%d, %d)', this.heap.length, heap.length);
  this.heap.copy(heap, 0, 0, this.heap.length);
  utils.debug('brk2(%d, %d)', this.heap.length, heap.length);
  this.heap = heap;
};

Ramdisk.prototype.write = function write(data, offset) {
  var added = Math.max(0, (offset + data.length) - this.size);

  while (offset + data.length > this.heap.length)
    this.brk();

  data.copy(this.heap, offset, 0, data.length);

  this.size += added;

  return data.length;
};

Ramdisk.prototype.truncate = function truncate(size) {
  assert(size <= this.size);
  this.size = size;
};

Ramdisk.prototype.read = function read(size, offset) {
  var data, ret;

  if (offset + size > this.size)
    return;

  data = this.heap.slice(offset, offset + size);
  ret = new Buffer(size);

  data.copy(ret, 0, 0, data.length);

  return ret;
};

module.exports = Ramdisk;

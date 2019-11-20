'use strict';

describe('Special', function(ctx) {
  it('should skip test', () => this.skip());
  it('should skip test', () => ctx.skip());
  it('should not skip test', cb => cb());
});

all:
	@./node_modules/.bin/browserify lib/bcoin.js -o browser/bcoin.js

ugly:
	@uglifyjs --comments '/\*[^\0]+?Copyright[^\0]+?\*/' -o browser/bcoin.min.js browser/bcoin.js

clean:
	@rm browser/bcoin.js
	@rm browser/bcoin.min.js

test:
	@npm test

.PHONY: all ugly clean test

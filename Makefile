all:
	@browserify lib/bcoin.js -o bcoin.browser.js
	@uglifyjs --comments '/\*[^\0]+?Copyright[^\0]+?\*/' -o bcoin.min.js bcoin.browser.js

clean:
	@rm bcoin.browser.js
	@rm bcoin.min.js

test:
	@npm test

.PHONY: all clean test

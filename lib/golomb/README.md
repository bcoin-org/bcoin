# Golomb

Golomb `lib/golomb` is a bcoin module intended to be used as a Golomb Coded Set
for creating Compact Block Filters as specified in [BIP 158][0].  It is used to
create block filters which can be used to quickly scan blocks for a given set
of transaction outputs.

Block filters are stored as an index using the blockstore.  To enable indexing
filters, the config option `index-filter` should be enabled.  For mainnet, the
indexing requires several hours on average and occupies ~4GB of disk space as
of block #595225.

Block filters can be accessed using the RPC:

`getblockfilter <hash>`

or the HTTP API:

`GET /filter/<height|hash>`

`Golomb` implements the Golomb Code Set used to create the block filter. It
takes the parameters N - size of the items to add to the filter and the
parameters M and P.  The probability of a false positive is 1/M and M is
customarily set to 2^P. [BIP 158][0] defines the value of P as 19, based on
results from real world block data.

[0]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

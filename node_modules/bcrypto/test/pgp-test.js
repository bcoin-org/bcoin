/*!
 * pgp-test.js - PGP tests for javascript
 *
 * Parts of this software are based on golang/crypto:
 *   Copyright (c) 2009 The Go Authors. All rights reserved.
 *   https://github.com/golang/crypto
 *
 * Resources:
 *   https://github.com/golang/crypto/blob/master/openpgp/keys_test.go
 */

'use strict';

const assert = require('bsert');
const fs = require('fs');
const Path = require('path');
const pgp = require('../lib/pgp');
const rsa = require('../lib/rsa');
const SHA256 = require('../lib/sha256');

const keys = [
// JJs key
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.6
Comment: Hostname: pgp.mit.edu

mQENBFFPEEwBCACt4A3YR0QLEy5Mo40bqluqAbnQ4E3Gp/FG/xXrXra9/2BXxDjWZaDXUI86
jJXJ5ko5ZrMwb6u7qJZBXoogcgwgqvrhxorpmm7SLRw4VIRHn8E8D+yk5rJ+CexFREGeScWc
u7+zuJ336ag7kFzaWcc9BFUFXooIAzUUVWKLB28DnX+fbt02eBz2YxPpmdKnE33einvpiQul
YejAA2ZdTyXN7Z39jgwWbehv9pwxNclUYtGSvicEaiCTS/g0x9jZigK3cS7MqfU7SEDOVIM+
NHNUje7E1HokY3T0+s3uy9cJwft+QOvKMjlzzBlV4ncqxH2MVBeeefx4uUFubq3aopFDABEB
AAG0KkNocmlzdG9waGVyIEplZmZyZXkgPGNoamplZmZyZXlAZ21haWwuY29tPokBOAQTAQIA
IgUCUU8QTAIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQiWKrneZma73/Uwf/Qb4t
67yAvSHbZWzoQyFu4tYJLTNRV7kJW09kP+XULnEspgJn8u/Y7AMTt3KylmNizLQwrWxzqMQD
/kv1WkPopYfbztzfOgEPgxSM347ZYyouCLArwlqhJleOzjDkJYy4hwnY7tf3AxbjuAoaXnmJ
/IqIsluzbHtN9pjdioEGoWQkS+V39fzC0cGZpCoypbcgPM7HKrlR41OkMDfApGu2IdmRa9zj
09bfPwcYOR1wTxL0VzdbOTUAxHKfdlhYmdj/FZrPJGbhGelQgk/PrZkBsyMrtuJ2nmJDGsLe
4MP+ufijzowN4R25Dw01vYjWjfEPe/oRElmizuzALZcPKuTHErkBDQRRTxBMAQgA/KcvlYqR
ehiEMq3HyOmaZrVT0NK1uTg9bFVj6srQDpnR77uL4i2GLF+Nmu9Wg3L1zrOjwOBNAZ/OSCLn
FkrsG2QYjgdSvpHOrPVkoLqh8XtzFLVhnpz79Q6UChDNvTSs4hemfb2GCloDF+CulU8I98KK
1+En6KJ8ppwGdno5bhHhs09irdxrJUGblS63jKqirFkH0P9BEpjNnroVPUtqV1Dr57ik9XkS
D6wR82SWVlWgJvzO1bS/GnymakbtCx+VfdnB7Nx44bgnqgjtK1/vD7Dl2xacTiem7G/8+Zr+
/MBVANL+RlzhKtIZ5dGn+NkZff2otF6OBGVHgCuXzSOgTwARAQABiQEfBBgBAgAJBQJRTxBM
AhsMAAoJEIliq53mZmu9XmcIAKAEofa7v+b8nHH+lDMuPMi9jFtrLTwfJE4KkcTrDPdDdKOg
UCjB3nELgXY4ghPo1564ACAMiZrzBOdxFIcLI8NPwj2Ifn0LE6f82ea+sMcuRDRRz/jGq7oK
5x9br+Q6QMWnbjcBEOtkRtrz5dcxVOytY/CC/JJ3ZBjg9Fq6DsC6bk+8DknY9H1HG7O0OAmi
feklePCGXE2BifO0TGsK4/yVvUQ6GhXwsbHgKZvRKuGZc7i0yTIJnXjg3O63yy08dJYxDBNC
AiufFLgv/BxB6hRb1mvJAlBPr+qJzzEj5Q0gZlgwARbCztpFcOi9yNnriJ5FZ6BjXLBrj87c
wSq3wzM=
=EUHU
-----END PGP PUBLIC KEY BLOCK-----`,

// missing cross signature
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Charset: UTF-8
mQENBFMYynYBCACVOZ3/e8Bm2b9KH9QyIlHGo/i1bnkpqsgXj8tpJ2MIUOnXMMAY
ztW7kKFLCmgVdLIC0vSoLA4yhaLcMojznh/2CcUglZeb6Ao8Gtelr//Rd5DRfPpG
zqcfUo+m+eO1co2Orabw0tZDfGpg5p3AYl0hmxhUyYSc/xUq93xL1UJzBFgYXY54
QsM8dgeQgFseSk/YvdP5SMx1ev+eraUyiiUtWzWrWC1TdyRa5p4UZg6Rkoppf+WJ
QrW6BWrhAtqATHc8ozV7uJjeONjUEq24roRc/OFZdmQQGK6yrzKnnbA6MdHhqpdo
9kWDcXYb7pSE63Lc+OBa5X2GUVvXJLS/3nrtABEBAAG0F2ludmFsaWQtc2lnbmlu
Zy1zdWJrZXlziQEoBBMBAgASBQJTnKB5AhsBAgsHAhUIAh4BAAoJEO3UDQUIHpI/
dN4H/idX4FQ1LIZCnpHS/oxoWQWfpRgdKAEM0qCqjMgiipJeEwSQbqjTCynuh5/R
JlODDz85ABR06aoF4l5ebGLQWFCYifPnJZ/Yf5OYcMGtb7dIbqxWVFL9iLMO/oDL
ioI3dotjPui5e+2hI9pVH1UHB/bZ/GvMGo6Zg0XxLPolKQODMVjpjLAQ0YJ3spew
RAmOGre6tIvbDsMBnm8qREt7a07cBJ6XK7xjxYaZHQBiHVxyEWDa6gyANONx8duW
/fhQ/zDTnyVM/ik6VO0Ty9BhPpcEYLFwh5c1ilFari1ta3e6qKo6ZGa9YMk/REhu
yBHd9nTkI+0CiQUmbckUiVjDKKe5AQ0EUxjKdgEIAJcXQeP+NmuciE99YcJoffxv
2gVLU4ZXBNHEaP0mgaJ1+tmMD089vUQAcyGRvw8jfsNsVZQIOAuRxY94aHQhIRHR
bUzBN28ofo/AJJtfx62C15xt6fDKRV6HXYqAiygrHIpEoRLyiN69iScUsjIJeyFL
C8wa72e8pSL6dkHoaV1N9ZH/xmrJ+k0vsgkQaAh9CzYufncDxcwkoP+aOlGtX1gP
WwWoIbz0JwLEMPHBWvDDXQcQPQTYQyj+LGC9U6f9VZHN25E94subM1MjuT9OhN9Y
MLfWaaIc5WyhLFyQKW2Upofn9wSFi8ubyBnv640Dfd0rVmaWv7LNTZpoZ/GbJAMA
EQEAAYkBHwQYAQIACQUCU5ygeQIbAgAKCRDt1A0FCB6SP0zCB/sEzaVR38vpx+OQ
MMynCBJrakiqDmUZv9xtplY7zsHSQjpd6xGflbU2n+iX99Q+nav0ETQZifNUEd4N
1ljDGQejcTyKD6Pkg6wBL3x9/RJye7Zszazm4+toJXZ8xJ3800+BtaPoI39akYJm
+ijzbskvN0v/j5GOFJwQO0pPRAFtdHqRs9Kf4YanxhedB4dIUblzlIJuKsxFit6N
lgGRblagG3Vv2eBszbxzPbJjHCgVLR3RmrVezKOsZjr/2i7X+xLWIR0uD3IN1qOW
CXQxLBizEEmSNVNxsp7KPGTLnqO3bPtqFirxS9PJLIMPTPLNBY7ZYuPNTMqVIUWF
4artDmrG
=7FfJ
-----END PGP PUBLIC KEY BLOCK-----`,

// invalid cross signature
`-----BEGIN PGP PUBLIC KEY BLOCK-----
mQENBFMYynYBCACVOZ3/e8Bm2b9KH9QyIlHGo/i1bnkpqsgXj8tpJ2MIUOnXMMAY
ztW7kKFLCmgVdLIC0vSoLA4yhaLcMojznh/2CcUglZeb6Ao8Gtelr//Rd5DRfPpG
zqcfUo+m+eO1co2Orabw0tZDfGpg5p3AYl0hmxhUyYSc/xUq93xL1UJzBFgYXY54
QsM8dgeQgFseSk/YvdP5SMx1ev+eraUyiiUtWzWrWC1TdyRa5p4UZg6Rkoppf+WJ
QrW6BWrhAtqATHc8ozV7uJjeONjUEq24roRc/OFZdmQQGK6yrzKnnbA6MdHhqpdo
9kWDcXYb7pSE63Lc+OBa5X2GUVvXJLS/3nrtABEBAAG0F2ludmFsaWQtc2lnbmlu
Zy1zdWJrZXlziQEoBBMBAgASBQJTnKB5AhsBAgsHAhUIAh4BAAoJEO3UDQUIHpI/
dN4H/idX4FQ1LIZCnpHS/oxoWQWfpRgdKAEM0qCqjMgiipJeEwSQbqjTCynuh5/R
JlODDz85ABR06aoF4l5ebGLQWFCYifPnJZ/Yf5OYcMGtb7dIbqxWVFL9iLMO/oDL
ioI3dotjPui5e+2hI9pVH1UHB/bZ/GvMGo6Zg0XxLPolKQODMVjpjLAQ0YJ3spew
RAmOGre6tIvbDsMBnm8qREt7a07cBJ6XK7xjxYaZHQBiHVxyEWDa6gyANONx8duW
/fhQ/zDTnyVM/ik6VO0Ty9BhPpcEYLFwh5c1ilFari1ta3e6qKo6ZGa9YMk/REhu
yBHd9nTkI+0CiQUmbckUiVjDKKe5AQ0EUxjKdgEIAIINDqlj7X6jYKc6DjwrOkjQ
UIRWbQQar0LwmNilehmt70g5DCL1SYm9q4LcgJJ2Nhxj0/5qqsYib50OSWMcKeEe
iRXpXzv1ObpcQtI5ithp0gR53YPXBib80t3bUzomQ5UyZqAAHzMp3BKC54/vUrSK
FeRaxDzNLrCeyI00+LHNUtwghAqHvdNcsIf8VRumK8oTm3RmDh0TyjASWYbrt9c8
R1Um3zuoACOVy+mEIgIzsfHq0u7dwYwJB5+KeM7ZLx+HGIYdUYzHuUE1sLwVoELh
+SHIGHI1HDicOjzqgajShuIjj5hZTyQySVprrsLKiXS6NEwHAP20+XjayJ/R3tEA
EQEAAYkCPgQYAQIBKAUCU5ygeQIbAsBdIAQZAQIABgUCU5ygeQAKCRCpVlnFZmhO
52RJB/9uD1MSa0wjY6tHOIgquZcP3bHBvHmrHNMw9HR2wRCMO91ZkhrpdS3ZHtgb
u3/55etj0FdvDo1tb8P8FGSVtO5Vcwf5APM8sbbqoi8L951Q3i7qt847lfhu6sMl
w0LWFvPTOLHrliZHItPRjOltS1WAWfr2jUYhsU9ytaDAJmvf9DujxEOsN5G1YJep
54JCKVCkM/y585Zcnn+yxk/XwqoNQ0/iJUT9qRrZWvoeasxhl1PQcwihCwss44A+
YXaAt3hbk+6LEQuZoYS73yR3WHj+42tfm7YxRGeubXfgCEz/brETEWXMh4pe0vCL
bfWrmfSPq2rDegYcAybxRQz0lF8PAAoJEO3UDQUIHpI/exkH/0vQfdHA8g/N4T6E
i6b1CUVBAkvtdJpCATZjWPhXmShOw62gkDw306vHPilL4SCvEEi4KzG72zkp6VsB
DSRcpxCwT4mHue+duiy53/aRMtSJ+vDfiV1Vhq+3sWAck/yUtfDU9/u4eFaiNok1
8/Gd7reyuZt5CiJnpdPpjCwelK21l2w7sHAnJF55ITXdOxI8oG3BRKufz0z5lyDY
s2tXYmhhQIggdgelN8LbcMhWs/PBbtUr6uZlNJG2lW1yscD4aI529VjwJlCeo745
U7pO4eF05VViUJ2mmfoivL3tkhoTUWhx8xs8xCUcCg8DoEoSIhxtOmoTPR22Z9BL
6LCg2mg=
=Dhm4
-----END PGP PUBLIC KEY BLOCK-----`,

// good cross signature
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1
mI0EVUqeVwEEAMufHRrMPWK3gyvi0O0tABCs/oON9zV9KDZlr1a1M91ShCSFwCPo
7r80PxdWVWcj0V5h50/CJYtpN3eE/mUIgW2z1uDYQF1OzrQ8ubrksfsJvpAhENom
lTQEppv9mV8qhcM278teb7TX0pgrUHLYF5CfPdp1L957JLLXoQR/lwLVABEBAAG0
E2dvb2Qtc2lnbmluZy1zdWJrZXmIuAQTAQIAIgUCVUqeVwIbAwYLCQgHAwIGFQgC
CQoLBBYCAwECHgECF4AACgkQNRjL95IRWP69XQQAlH6+eyXJN4DZTLX78KGjHrsw
6FCvxxClEPtPUjcJy/1KCRQmtLAt9PbbA78dvgzjDeZMZqRAwdjyJhjyg/fkU2OH
7wq4ktjUu+dLcOBb+BFMEY+YjKZhf6EJuVfxoTVr5f82XNPbYHfTho9/OABKH6kv
X70PaKZhbwnwij8Nts65AaIEVUqftREEAJ3WxZfqAX0bTDbQPf2CMT2IVMGDfhK7
GyubOZgDFFjwUJQvHNvsrbeGLZ0xOBumLINyPO1amIfTgJNm1iiWFWfmnHReGcDl
y5mpYG60Mb79Whdcer7CMm3AqYh/dW4g6IB02NwZMKoUHo3PXmFLxMKXnWyJ0clw
R0LI/Qn509yXAKDh1SO20rqrBM+EAP2c5bfI98kyNwQAi3buu94qo3RR1ZbvfxgW
CKXDVm6N99jdZGNK7FbRifXqzJJDLcXZKLnstnC4Sd3uyfyf1uFhmDLIQRryn5m+
LBYHfDBPN3kdm7bsZDDq9GbTHiFZUfm/tChVKXWxkhpAmHhU/tH6GGzNSMXuIWSO
aOz3Rqq0ED4NXyNKjdF9MiwD/i83S0ZBc0LmJYt4Z10jtH2B6tYdqnAK29uQaadx
yZCX2scE09UIm32/w7pV77CKr1Cp/4OzAXS1tmFzQ+bX7DR+Gl8t4wxr57VeEMvl
BGw4Vjh3X8//m3xynxycQU18Q1zJ6PkiMyPw2owZ/nss3hpSRKFJsxMLhW3fKmKr
Ey2KiOcEGAECAAkFAlVKn7UCGwIAUgkQNRjL95IRWP5HIAQZEQIABgUCVUqftQAK
CRD98VjDN10SqkWrAKDTpEY8D8HC02E/KVC5YUI01B30wgCgurpILm20kXEDCeHp
C5pygfXw1DJrhAP+NyPJ4um/bU1I+rXaHHJYroYJs8YSweiNcwiHDQn0Engh/mVZ
SqLHvbKh2dL/RXymC3+rjPvQf5cup9bPxNMa6WagdYBNAfzWGtkVISeaQW+cTEp/
MtgVijRGXR/lGLGETPg2X3Afwn9N9bLMBkBprKgbBqU7lpaoPupxT61bL70=
=vtbN
-----END PGP PUBLIC KEY BLOCK-----`,

// revoked user id
`-----BEGIN PGP PUBLIC KEY BLOCK-----
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
7qTZOahrETw=
=IKnw
-----END PGP PUBLIC KEY BLOCK-----`,

// https://github.com/golang/crypto/blob/master/openpgp/read_test.go
// armored private key block
`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1.4.10 (GNU/Linux)
lQHYBE2rFNoBBADFwqWQIW/DSqcB4yCQqnAFTJ27qS5AnB46ccAdw3u4Greeu3Bp
idpoHdjULy7zSKlwR1EA873dO/k/e11Ml3dlAFUinWeejWaK2ugFP6JjiieSsrKn
vWNicdCS4HTWn0X4sjl0ZiAygw6GNhqEQ3cpLeL0g8E9hnYzJKQ0LWJa0QARAQAB
AAP/TB81EIo2VYNmTq0pK1ZXwUpxCrvAAIG3hwKjEzHcbQznsjNvPUihZ+NZQ6+X
0HCfPAdPkGDCLCb6NavcSW+iNnLTrdDnSI6+3BbIONqWWdRDYJhqZCkqmG6zqSfL
IdkJgCw94taUg5BWP/AAeQrhzjChvpMQTVKQL5mnuZbUCeMCAN5qrYMP2S9iKdnk
VANIFj7656ARKt/nf4CBzxcpHTyB8+d2CtPDKCmlJP6vL8t58Jmih+kHJMvC0dzn
gr5f5+sCAOOe5gt9e0am7AvQWhdbHVfJU0TQJx+m2OiCJAqGTB1nvtBLHdJnfdC9
TnXXQ6ZXibqLyBies/xeY2sCKL5qtTMCAKnX9+9d/5yQxRyrQUHt1NYhaXZnJbHx
q4ytu0eWz+5i68IYUSK69jJ1NWPM0T6SkqpB3KCAIv68VFm9PxqG1KmhSrQIVGVz
dCBLZXmIuAQTAQIAIgUCTasU2gIbAwYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AA
CgkQO9o98PRieSoLhgQAkLEZex02Qt7vGhZzMwuN0R22w3VwyYyjBx+fM3JFETy1
ut4xcLJoJfIaF5ZS38UplgakHG0FQ+b49i8dMij0aZmDqGxrew1m4kBfjXw9B/v+
eIqpODryb6cOSwyQFH0lQkXC040pjq9YqDsO5w0WYNXYKDnzRV0p4H1pweo2VDid
AdgETasU2gEEAN46UPeWRqKHvA99arOxee38fBt2CI08iiWyI8T3J6ivtFGixSqV
bRcPxYO/qLpVe5l84Nb3X71GfVXlc9hyv7CD6tcowL59hg1E/DC5ydI8K8iEpUmK
/UnHdIY5h8/kqgGxkY/T/hgp5fRQgW1ZoZxLajVlMRZ8W4tFtT0DeA+JABEBAAEA
A/0bE1jaaZKj6ndqcw86jd+QtD1SF+Cf21CWRNeLKnUds4FRRvclzTyUMuWPkUeX
TaNNsUOFqBsf6QQ2oHUBBK4VCHffHCW4ZEX2cd6umz7mpHW6XzN4DECEzOVksXtc
lUC1j4UB91DC/RNQqwX1IV2QLSwssVotPMPqhOi0ZLNY7wIA3n7DWKInxYZZ4K+6
rQ+POsz6brEoRHwr8x6XlHenq1Oki855pSa1yXIARoTrSJkBtn5oI+f8AzrnN0BN
oyeQAwIA/7E++3HDi5aweWrViiul9cd3rcsS0dEnksPhvS0ozCJiHsq/6GFmy7J8
QSHZPteedBnZyNp5jR+H7cIfVN3KgwH/Skq4PsuPhDq5TKK6i8Pc1WW8MA6DXTdU
nLkX7RGmMwjC0DBf7KWAlPjFaONAX3a8ndnz//fy1q7u2l9AZwrj1qa1iJ8EGAEC
AAkFAk2rFNoCGwwACgkQO9o98PRieSo2/QP/WTzr4ioINVsvN1akKuekmEMI3LAp
BfHwatufxxP1U+3Si/6YIk7kuPB9Hs+pRqCXzbvPRrI8NHZBmc8qIGthishdCYad
AHcVnXjtxrULkQFGbGvhKURLvS9WnzD/m1K2zzwxzkPTzT9/Yf06O6Mal5AdugPL
VrM0m72/jnpKo04=
=zNCn
-----END PGP PRIVATE KEY BLOCK-----`,

// e2e public key
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Charset: UTF-8
xv8AAABSBAAAAAATCCqGSM49AwEHAgME1LRoXSpOxtHXDUdmuvzchyg6005qIBJ4
sfaSxX7QgH9RV2ONUhC+WiayCNADq+UMzuR/vunSr4aQffXvuGnR383/AAAAFDxk
Z2lsQHlhaG9vLWluYy5jb20+wv8AAACGBBATCAA4/wAAAAWCVGvAG/8AAAACiwn/
AAAACZC2VkQCOjdvYf8AAAAFlQgJCgv/AAAAA5YBAv8AAAACngEAAE1BAP0X8veD
24IjmI5/C6ZAfVNXxgZZFhTAACFX75jUA3oD6AEAzoSwKf1aqH6oq62qhCN/pekX
+WAsVMBhNwzLpqtCRjLO/wAAAFYEAAAAABIIKoZIzj0DAQcCAwT50ain7vXiIRv8
B1DO3x3cE/aattZ5sHNixJzRCXi2vQIA5QmOxZ6b5jjUekNbdHG3SZi1a2Ak5mfX
fRxC/5VGAwEIB8L/AAAAZQQYEwgAGP8AAAAFglRrwBz/AAAACZC2VkQCOjdvYQAA
FJAA9isX3xtGyMLYwp2F3nXm7QEdY5bq5VUcD/RJlj792VwA/1wH0pCzVLl4Q9F9
ex7En5r7rHR5xwX82Msc+Rq9dSyO
=7MrZ
-----END PGP PUBLIC KEY BLOCK-----`,

// key v4 for verifying signed message v3
`-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: GPGTools - https://gpgtools.org
mI0EVfxoFQEEAMBIqmbDfYygcvP6Phr1wr1XI41IF7Qixqybs/foBF8qqblD9gIY
BKpXjnBOtbkcVOJ0nljd3/sQIfH4E0vQwK5/4YRQSI59eKOqd6Fx+fWQOLG+uu6z
tewpeCj9LLHvibx/Sc7VWRnrznia6ftrXxJ/wHMezSab3tnGC0YPVdGNABEBAAG0
JEdvY3J5cHRvIFRlc3QgS2V5IDx0aGVtYXhAZ21haWwuY29tPoi5BBMBCgAjBQJV
/GgVAhsDBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQeXnQmhdGW9PFVAP+
K7TU0qX5ArvIONIxh/WAweyOk884c5cE8f+3NOPOOCRGyVy0FId5A7MmD5GOQh4H
JseOZVEVCqlmngEvtHZb3U1VYtVGE5WZ+6rQhGsMcWP5qaT4soYwMBlSYxgYwQcx
YhN9qOr292f9j2Y//TTIJmZT4Oa+lMxhWdqTfX+qMgG4jQRV/GgVAQQArhFSiij1
b+hT3dnapbEU+23Z1yTu1DfF6zsxQ4XQWEV3eR8v+8mEDDNcz8oyyF56k6UQ3rXi
UMTIwRDg4V6SbZmaFbZYCOwp/EmXJ3rfhm7z7yzXj2OFN22luuqbyVhuL7LRdB0M
pxgmjXb4tTvfgKd26x34S+QqUJ7W6uprY4sAEQEAAYifBBgBCgAJBQJV/GgVAhsM
AAoJEHl50JoXRlvT7y8D/02ckx4OMkKBZo7viyrBw0MLG92i+DC2bs35PooHR6zz
786mitjOp5z2QWNLBvxC70S0qVfCIz8jKupO1J6rq6Z8CcbLF3qjm6h1omUBf8Nd
EfXKD2/2HV6zMKVknnKzIEzauh+eCKS2CeJUSSSryap/QLVAjRnckaES/OsEWhNB
=RZia
-----END PGP PUBLIC KEY BLOCK-----`,

// signed message v3
`-----BEGIN PGP MESSAGE-----
Comment: GPGTools - https://gpgtools.org
owGbwMvMwMVYWXlhlrhb9GXG03JJDKF/MtxDMjKLFYAoUaEktbhEITe1uDgxPVWP
q5NhKjMrWAVcC9evD8z/bF/uWNjqtk/X3y5/38XGRQHm/57rrDRYuGnTw597Xqka
uM3137/hH3Os+Jf2dc0fXOITKwJvXJvecPVs0ta+Vg7ZO1MLn8w58Xx+6L58mbka
DGHyU9yTueZE8D+QF/Tz28Y78dqtF56R1VPn9Xw4uJqrWYdd7b3vIZ1V6R4Nh05d
iT57d/OhWwA=
=hG7R
-----END PGP MESSAGE-----`
];

function read(name, enc) {
  return fs.readFileSync(Path.resolve(__dirname, 'data', name), enc);
}

const PASSPHRASE = '1234567890';

const pubring = read('pubring.gpg');
const pubringArmor = read('pubring.asc', 'utf8');
const secring = read('secring.gpg');
const secringArmor = read('secring.asc', 'utf8');

describe('PGP', function() {
  this.timeout(30000);

  for (const key of keys) {
    it('should deserialize and reserialize keyrings', () => {
      const msg1 = pgp.PGPMessage.fromString(key);

      const str1 = msg1.toString('PGP PUBLIC KEY BLOCK');
      const msg2 = pgp.PGPMessage.fromString(str1);
      const str2 = msg2.toString('PGP PUBLIC KEY BLOCK');

      assert.deepStrictEqual(msg1, msg2);
      assert.strictEqual(str1, str2);
    });
  }

  for (const data of [secring, secringArmor]) {
    it('should decode/decrypt and encode private keys', () => {
      const msg = typeof data === 'string'
        ? pgp.PGPMessage.fromString(data)
        : pgp.PGPMessage.decode(data);

      const keys = [];
      const master = [];
      const subkeys = [];

      for (const pkt of msg.packets) {
        switch (pkt.type) {
          case pgp.packetTypes.PRIVATE_KEY:
            keys.push(pkt.body);
            master.push(pkt.body);
            break;
          case pgp.packetTypes.PRIVATE_SUBKEY:
            keys.push(pkt.body);
            subkeys.push(pkt.body);
            break;
        }
      }

      assert.strictEqual(keys.length, 4);
      assert.strictEqual(master.length, 1);
      assert.strictEqual(subkeys.length, 3);

      {
        const priv = master[0];

        assert.strictEqual(priv.key.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(priv.key.timestamp, 1535394109);
        assert.strictEqual(priv.key.n.get().length, 256);
        assert.strictEqual(priv.key.e.get().length, 3);
        assert.strictEqual(priv.params.encrypted, true);
        assert.strictEqual(priv.params.checksum, true);
        assert.strictEqual(priv.params.cipher, pgp.cipherTypes.AES128);
        assert.strictEqual(priv.params.s2k.mode, 3);
        assert.strictEqual(priv.params.s2k.hash, pgp.hashTypes.SHA1);
        assert.strictEqual(priv.params.s2k.count, 35651584);
        assert.strictEqual(priv.params.s2k.salt.length, 8);
        assert.strictEqual(priv.params.iv.length, 16);
        assert.strictEqual(priv.data.length, 668);

        const secret = priv.secret(PASSPHRASE);

        assert.strictEqual(secret.d.get().length, 256);
        assert.strictEqual(secret.p.get().length, 128);
        assert.strictEqual(secret.q.get().length, 128);
        assert.strictEqual(secret.qi.get().length, 128);

        const pub = rsa.publicKeyImport({
          n: priv.key.n.get(),
          e: priv.key.e.get()
        });

        const pubj = rsa.publicKeyExport(pub);

        const key = rsa.privateKeyImport({
          e: priv.key.e.get(),
          p: secret.p.get(),
          q: secret.q.get(),
          d: secret.d.get()
        });

        const keyj = rsa.privateKeyExport(key);

        assert.bufferEqual(keyj.n, pubj.n);
        assert.bufferEqual(keyj.e, pubj.e);
        // assert.bufferEqual(keyj.d, secret.d.get());
        assert.bufferEqual(keyj.qi, secret.qi.get());

        const m = SHA256.digest(Buffer.from('foobar'));
        const s = rsa.sign(SHA256, m, key);
        assert(rsa.verify(SHA256, m, s, pub));
      }

      {
        const priv = subkeys[0];

        assert.strictEqual(priv.key.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(priv.key.timestamp, 1535394109);
        assert.strictEqual(priv.key.n.get().length, 256);
        assert.strictEqual(priv.key.e.get().length, 3);
        assert.strictEqual(priv.params.encrypted, true);
        assert.strictEqual(priv.params.checksum, true);
        assert.strictEqual(priv.params.cipher, pgp.cipherTypes.AES128);
        assert.strictEqual(priv.params.s2k.mode, 3);
        assert.strictEqual(priv.params.s2k.hash, pgp.hashTypes.SHA1);
        assert.strictEqual(priv.params.s2k.count, 35651584);
        assert.strictEqual(priv.params.s2k.salt.length, 8);
        assert.strictEqual(priv.params.iv.length, 16);
        assert.strictEqual(priv.data.length, 668);

        const secret = priv.secret(PASSPHRASE);

        assert.strictEqual(secret.d.get().length, 256);
        assert.strictEqual(secret.p.get().length, 128);
        assert.strictEqual(secret.q.get().length, 128);
        assert.strictEqual(secret.qi.get().length, 128);
      }

      {
        const priv = subkeys[1];

        assert.strictEqual(priv.key.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(priv.key.timestamp, 1535394388);
        assert.strictEqual(priv.key.n.get().length, 256);
        assert.strictEqual(priv.key.e.get().length, 3);
        assert.strictEqual(priv.params.encrypted, true);
        assert.strictEqual(priv.params.checksum, true);
        assert.strictEqual(priv.params.cipher, pgp.cipherTypes.AES128);
        assert.strictEqual(priv.params.s2k.mode, 3);
        assert.strictEqual(priv.params.s2k.hash, pgp.hashTypes.SHA1);
        assert.strictEqual(priv.params.s2k.count, 35651584);
        assert.strictEqual(priv.params.s2k.salt.length, 8);
        assert.strictEqual(priv.params.iv.length, 16);
        assert.strictEqual(priv.data.length, 668);

        const secret = priv.secret(PASSPHRASE);

        assert.strictEqual(secret.d.get().length, 256);
        assert.strictEqual(secret.p.get().length, 128);
        assert.strictEqual(secret.q.get().length, 128);
        assert.strictEqual(secret.qi.get().length, 128);
      }

      {
        const priv = subkeys[2];

        assert.strictEqual(priv.key.algorithm, pgp.keyTypes.ELGAMAL);
        assert.strictEqual(priv.key.timestamp, 1535394441);
        assert.strictEqual(priv.key.p.get().length, 256);
        assert.strictEqual(priv.key.g.get().length, 1);
        assert.strictEqual(priv.key.y.get().length, 256);
        assert.strictEqual(priv.params.encrypted, true);
        assert.strictEqual(priv.params.checksum, true);
        assert.strictEqual(priv.params.cipher, pgp.cipherTypes.AES128);
        assert.strictEqual(priv.params.s2k.mode, 3);
        assert.strictEqual(priv.params.s2k.hash, pgp.hashTypes.SHA1);
        assert.strictEqual(priv.params.s2k.count, 35651584);
        assert.strictEqual(priv.params.s2k.salt.length, 8);
        assert.strictEqual(priv.params.iv.length, 16);
        assert.strictEqual(priv.data.length, 65);

        const secret = priv.secret(PASSPHRASE);

        assert.strictEqual(secret.x.get().length, 43);
      }

      {
        const msg1 = msg;
        const str1 = msg1.toString('PGP PRIVATE KEY BLOCK');
        const msg2 = pgp.PGPMessage.fromString(str1);
        const str2 = msg2.toString('PGP PRIVATE KEY BLOCK');

        assert.deepStrictEqual(msg1, msg2);
        assert.strictEqual(str1, str2);
      }
    });
  }

  for (const data of [pubring, pubringArmor]) {
    it('should decode and encode public keys', () => {
      const msg = typeof data === 'string'
        ? pgp.PGPMessage.fromString(data)
        : pgp.PGPMessage.decode(data);

      const keys = [];
      const master = [];
      const subkeys = [];

      for (const pkt of msg.packets) {
        switch (pkt.type) {
          case pgp.packetTypes.PUBLIC_KEY:
            keys.push(pkt.body);
            master.push(pkt.body);
            break;
          case pgp.packetTypes.PUBLIC_SUBKEY:
            keys.push(pkt.body);
            subkeys.push(pkt.body);
            break;
        }
      }

      assert.strictEqual(keys.length, 4);
      assert.strictEqual(master.length, 1);
      assert.strictEqual(subkeys.length, 3);

      {
        const pub = master[0];

        assert.strictEqual(pub.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(pub.timestamp, 1535394109);
        assert.strictEqual(pub.n.get().length, 256);
        assert.strictEqual(pub.e.get().length, 3);
      }

      {
        const pub = subkeys[0];

        assert.strictEqual(pub.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(pub.timestamp, 1535394109);
        assert.strictEqual(pub.n.get().length, 256);
        assert.strictEqual(pub.e.get().length, 3);
      }

      {
        const pub = subkeys[1];

        assert.strictEqual(pub.algorithm, pgp.keyTypes.RSA);
        assert.strictEqual(pub.timestamp, 1535394388);
        assert.strictEqual(pub.n.get().length, 256);
        assert.strictEqual(pub.e.get().length, 3);
      }

      {
        const pub = subkeys[2];

        assert.strictEqual(pub.algorithm, pgp.keyTypes.ELGAMAL);
        assert.strictEqual(pub.timestamp, 1535394441);
        assert.strictEqual(pub.p.get().length, 256);
        assert.strictEqual(pub.g.get().length, 1);
        assert.strictEqual(pub.y.get().length, 256);
      }

      {
        const msg1 = msg;
        const str1 = msg1.toString('PGP PUBLIC KEY BLOCK');
        const msg2 = pgp.PGPMessage.fromString(str1);
        const str2 = msg2.toString('PGP PUBLIC KEY BLOCK');

        assert.deepStrictEqual(msg1, msg2);
        assert.strictEqual(str1, str2);
      }
    });
  }
});

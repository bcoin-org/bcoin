'use strict';

const assert = require('bsert');
const BN = require('../lib/bn.js');
const rng = require('../lib/random');

const dhGroups = {
  p16: {
    prime: ''
      + 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1'
      + '29024e088a67cc74020bbea63b139b22514a08798e3404dd'
      + 'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245'
      + 'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
      + 'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d'
      + 'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f'
      + '83655d23dca3ad961c62f356208552bb9ed529077096966d'
      + '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
      + 'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9'
      + 'de2bcbf6955817183995497cea956ae515d2261898fa0510'
      + '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64'
      + 'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
      + 'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b'
      + 'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c'
      + 'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31'
      + '43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7'
      + '88719a10bdba5b2699c327186af4e23c1a946834b6150bda'
      + '2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6'
      + '287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed'
      + '1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9'
      + '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199'
      + 'ffffffffffffffff',
    priv: ''
      + '6d5923e6449122cbbcc1b96093e0b7e4fd3e469f58daddae'
      + '53b49b20664f4132675df9ce98ae0cfdcac0f4181ccb643b'
      + '625f98104dcf6f7d8e81961e2cab4b5014895260cb977c7d'
      + '2f981f8532fb5da60b3676dfe57f293f05d525866053ac7e'
      + '65abfd19241146e92e64f309a97ef3b529af4d6189fa416c'
      + '9e1a816c3bdf88e5edf48fbd8233ef9038bb46faa95122c0'
      + '5a426be72039639cd2d53d37254b3d258960dcb33c255ede'
      + '20e9d7b4b123c8b4f4b986f53cdd510d042166f7dd7dca98'
      + '7c39ab36381ba30a5fdd027eb6128d2ef8e5802a2194d422'
      + 'b05fe6e1cb4817789b923d8636c1ec4b7601c90da3ddc178'
      + '52f59217ae070d87f2e75cbfb6ff92430ad26a71c8373452'
      + 'ae1cc5c93350e2d7b87e0acfeba401aaf518580937bf0b6c'
      + '341f8c49165a47e49ce50853989d07171c00f43dcddddf72'
      + '94fb9c3f4e1124e98ef656b797ef48974ddcd43a21fa06d0'
      + '565ae8ce494747ce9e0ea0166e76eb45279e5c6471db7df8'
      + 'cc88764be29666de9c545e72da36da2f7a352fb17bdeb982'
      + 'a6dc0193ec4bf00b2e533efd6cd4d46e6fb237b775615576'
      + 'dd6c7c7bbc087a25e6909d1ebc6e5b38e5c8472c0fc429c6'
      + 'f17da1838cbcd9bbef57c5b5522fd6053e62ba21fe97c826'
      + 'd3889d0cc17e5fa00b54d8d9f0f46fb523698af965950f4b'
      + '941369e180f0aece3870d9335f2301db251595d173902cad'
      + '394eaa6ffef8be6c',
    pub: ''
      + 'd53703b7340bc89bfc47176d351e5cf86d5a18d9662eca3c'
      + '9759c83b6ccda8859649a5866524d77f79e501db923416ca'
      + '2636243836d3e6df752defc0fb19cc386e3ae48ad647753f'
      + 'bf415e2612f8a9fd01efe7aca249589590c7e6a0332630bb'
      + '29c5b3501265d720213790556f0f1d114a9e2071be3620bd'
      + '4ee1e8bb96689ac9e226f0a4203025f0267adc273a43582b'
      + '00b70b490343529eaec4dcff140773cd6654658517f51193'
      + '13f21f0a8e04fe7d7b21ffeca85ff8f87c42bb8d9cb13a72'
      + 'c00e9c6e9dfcedda0777af951cc8ccab90d35e915e707d8e'
      + '4c2aca219547dd78e9a1a0730accdc9ad0b854e51edd1e91'
      + '4756760bab156ca6e3cb9c625cf0870def34e9ac2e552800'
      + 'd6ce506d43dbbc75acfa0c8d8fb12daa3c783fb726f187d5'
      + '58131779239c912d389d0511e0f3a81969d12aeee670e48f'
      + 'ba41f7ed9f10705543689c2506b976a8ffabed45e33795b0'
      + '1df4f6b993a33d1deab1316a67419afa31fbb6fdd252ee8c'
      + '7c7d1d016c44e3fcf6b41898d7f206aa33760b505e4eff2e'
      + 'c624bc7fe636b1d59e45d6f904fc391419f13d1f0cdb5b6c'
      + '2378b09434159917dde709f8a6b5dc30994d056e3f964371'
      + '11587ac7af0a442b8367a7bd940f752ddabf31cf01171e24'
      + 'd78df136e9681cd974ce4f858a5fb6efd3234a91857bb52d'
      + '9e7b414a8bc66db4b5a73bbeccfb6eb764b4f0cbf0375136'
      + 'b024b04e698d54a5'
  },
  p17: {
    prime: ''
      + 'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1'
      + '29024e088a67cc74020bbea63b139b22514a08798e3404dd'
      + 'ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245'
      + 'e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed'
      + 'ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d'
      + 'c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f'
      + '83655d23dca3ad961c62f356208552bb9ed529077096966d'
      + '670c354e4abc9804f1746c08ca18217c32905e462e36ce3b'
      + 'e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9'
      + 'de2bcbf6955817183995497cea956ae515d2261898fa0510'
      + '15728e5a8aaac42dad33170d04507a33a85521abdf1cba64'
      + 'ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7'
      + 'abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b'
      + 'f12ffa06d98a0864d87602733ec86a64521f2b18177b200c'
      + 'bbe117577a615d6c770988c0bad946e208e24fa074e5ab31'
      + '43db5bfce0fd108e4b82d120a92108011a723c12a787e6d7'
      + '88719a10bdba5b2699c327186af4e23c1a946834b6150bda'
      + '2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6'
      + '287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed'
      + '1f612970cee2d7afb81bdd762170481cd0069127d5b05aa9'
      + '93b4ea988d8fddc186ffb7dc90a6c08f4df435c934028492'
      + '36c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bd'
      + 'f8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831'
      + '179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1b'
      + 'db7f1447e6cc254b332051512bd7af426fb8f401378cd2bf'
      + '5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6'
      + 'd55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f3'
      + '23a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aa'
      + 'cc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be328'
      + '06a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55c'
      + 'da56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee'
      + '12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff',
    priv: ''
      + '6017f2bc23e1caff5b0a8b4e1fc72422b5204415787801dc'
      + '025762b8dbb98ab57603aaaa27c4e6bdf742b4a1726b9375'
      + 'a8ca3cf07771779589831d8bd18ddeb79c43e7e77d433950'
      + 'e652e49df35b11fa09644874d71d62fdaffb580816c2c88c'
      + '2c4a2eefd4a660360316741b05a15a2e37f236692ad3c463'
      + 'fff559938fc6b77176e84e1bb47fb41af691c5eb7bb81bd8'
      + 'c918f52625a1128f754b08f5a1403b84667231c4dfe07ed4'
      + '326234c113931ce606037e960f35a2dfdec38a5f057884d3'
      + '0af8fab3be39c1eeb390205fd65982191fc21d5aa30ddf51'
      + 'a8e1c58c0c19fc4b4a7380ea9e836aaf671c90c29bc4bcc7'
      + '813811aa436a7a9005de9b507957c56a9caa1351b6efc620'
      + '7225a18f6e97f830fb6a8c4f03b82f4611e67ab9497b9271'
      + 'd6ac252793cc3e5538990dbd894d2dbc2d152801937d9f74'
      + 'da4b741b50b4d40e4c75e2ac163f7b397fd555648b249f97'
      + 'ffe58ffb6d096aa84534c4c5729cff137759bd34e80db4ab'
      + '47e2b9c52064e7f0bf677f72ac9e5d0c6606943683f9d12f'
      + '180cf065a5cb8ec3179a874f358847a907f8471d15f1e728'
      + '7023249d6d13c82da52628654438f47b8b5cdf4761fbf6ad'
      + '9219eceac657dbd06cf2ab776ad4c968f81c3d039367f0a4'
      + 'd77c7ec4435c27b6c147071665100063b5666e06eb2fb2cc'
      + '3159ba34bc98ca346342195f6f1fb053ddc3bc1873564d40'
      + '1c6738cdf764d6e1ff25ca5926f80102ea6593c17170966b'
      + 'b5d7352dd7fb821230237ea3ebed1f920feaadbd21be295a'
      + '69f2083deae9c5cdf5f4830eb04b7c1f80cc61c17232d79f'
      + '7ecc2cc462a7965f804001c89982734e5abba2d31df1b012'
      + '152c6b226dff34510b54be8c2cd68d795def66c57a3abfb6'
      + '896f1d139e633417f8c694764974d268f46ece3a8d6616ea'
      + 'a592144be48ee1e0a1595d3e5edfede5b27cec6c48ceb2ff'
      + 'b42cb44275851b0ebf87dfc9aa2d0cb0805e9454b051dfe8'
      + 'a29fadd82491a4b4c23f2d06ba45483ab59976da1433c9ce'
      + '500164b957a04cf62dd67595319b512fc4b998424d1164dd'
      + 'bbe5d1a0f7257cbb04ec9b5ed92079a1502d98725023ecb2',
    pub: ''
      + '3bf836229c7dd874fe37c1790d201e82ed8e192ed61571ca'
      + '7285264974eb2a0171f3747b2fc23969a916cbd21e14f7e2'
      + 'f0d72dcd2247affba926f9e7bb99944cb5609aed85e71b89'
      + 'e89d2651550cb5bd8281bd3144066af78f194032aa777739'
      + 'cccb7862a1af401f99f7e5c693f25ddce2dedd9686633820'
      + 'd28d0f5ed0c6b5a094f5fe6170b8e2cbc9dff118398baee6'
      + 'e895a6301cb6e881b3cae749a5bdf5c56fc897ff68bc73f2'
      + '4811bb108b882872bade1f147d886a415cda2b93dd90190c'
      + 'be5c2dd53fe78add5960e97f58ff2506afe437f4cf4c912a'
      + '397c1a2139ac6207d3ab76e6b7ffd23bb6866dd7f87a9ae5'
      + '578789084ff2d06ea0d30156d7a10496e8ebe094f5703539'
      + '730f5fdbebc066de417be82c99c7da59953071f49da7878d'
      + 'a588775ff2a7f0084de390f009f372af75cdeba292b08ea8'
      + '4bd13a87e1ca678f9ad148145f7cef3620d69a891be46fbb'
      + 'cad858e2401ec0fd72abdea2f643e6d0197b7646fbb83220'
      + '0f4cf7a7f6a7559f9fb0d0f1680822af9dbd8dec4cd1b5e1'
      + '7bc799e902d9fe746ddf41da3b7020350d3600347398999a'
      + 'baf75d53e03ad2ee17de8a2032f1008c6c2e6618b62f225b'
      + 'a2f350179445debe68500fcbb6cae970a9920e321b468b74'
      + '5fb524fb88abbcacdca121d737c44d30724227a99745c209'
      + 'b970d1ff93bbc9f28b01b4e714d6c9cbd9ea032d4e964d8e'
      + '8fff01db095160c20b7646d9fcd314c4bc11bcc232aeccc0'
      + 'fbedccbc786951025597522eef283e3f56b44561a0765783'
      + '420128638c257e54b972a76e4261892d81222b3e2039c61a'
      + 'ab8408fcaac3d634f848ab3ee65ea1bd13c6cd75d2e78060'
      + 'e13cf67fbef8de66d2049e26c0541c679fff3e6afc290efe'
      + '875c213df9678e4a7ec484bc87dae5f0a1c26d7583e38941'
      + 'b7c68b004d4df8b004b666f9448aac1cc3ea21461f41ea5d'
      + 'd0f7a9e6161cfe0f58bcfd304bdc11d78c2e9d542e86c0b5'
      + '6985cc83f693f686eaac17411a8247bf62f5ccc7782349b5'
      + 'cc1f20e312fa2acc0197154d1bfee507e8db77e8f2732f2d'
      + '641440ccf248e8643b2bd1e1f9e8239356ab91098fcb431d',
    q: ''
      + 'a899c59999bf877d96442d284359783bdc64b5f878b688fe'
      + '51407f0526e616553ad0aaaac4d5bed3046f10a1faaf42bb'
      + '2342dc4b7908eea0c46e4c4576897675c2bfdc4467870d3d'
      + 'cd90adaed4359237a4bc6924bfb99aa6bf5f5ede15b574ea'
      + 'e977eac096f3c67d09bda574c6306c6123fa89d2f086b8dc'
      + 'ff92bc570c18d83fe6c810ccfd22ce4c749ef5e6ead3fffe'
      + 'c63d95e0e3fde1df9db6a35fa1d107058f37e41957769199'
      + 'd945dd7a373622c65f0af3fd9eb1ddc5c764bbfaf7a3dc37'
      + '2548e683b970dac4aa4b9869080d2376c9adecebb84e172c'
      + '09aeeb25fb8df23e60033260c4f8aac6b8b98ab894b1fb84'
      + 'ebb83c0fb2081c3f3eee07f44e24d8fabf76f19ed167b0d7'
      + 'ff971565aa4efa3625fce5a43ceeaa3eebb3ce88a00f597f'
      + '048c69292b38dba2103ecdd5ec4ccfe3b2d87fa6202f334b'
      + 'c1cab83b608dfc875b650b69f2c7e23c0b2b4adf149a6100'
      + 'db1b6dbad4679ecb1ea95eafaba3bd00db11c2134f5a8686'
      + '358b8b2ab49a1b2e85e1e45caeac5cd4dc0b3b5fffba8871'
      + '1c6baf399edd48dad5e5c313702737a6dbdcede80ca358e5'
      + '1d1c4fe42e8948a084403f61baed38aa9a1a5ce2918e9f33'
      + '100050a430b47bc592995606440272a4994677577a6aaa1b'
      + 'a101045dbec5a4e9566dab5445d1af3ed19519f07ac4e2a8'
      + 'bd0a84b01978f203a9125a0be020f71fab56c2c9e344d4f4'
      + '12d53d3cd8eb74ca5122002e931e3cb0bd4b7492436be17a'
      + 'd7ebe27148671f59432c36d8c56eb762655711cfc8471f70'
      + '83a8b7283bcb3b1b1d47d37c23d030288cfcef05fbdb4e16'
      + '652ee03ee7b77056a808cd700bc3d9ef826eca9a59be959c'
      + '947c865d6b372a1ca2d503d7df6d7611b12111665438475a'
      + '1c64145849b3da8c2d343410df892d958db232617f9896f1'
      + 'de95b8b5a47132be80dd65298c7f2047858409bf762dbc05'
      + 'a62ca392ac40cfb8201a0607a2cae07d99a307625f2b2d04'
      + 'fe83fbd3ab53602263410f143b73d5b46fc761882e78c782'
      + 'd2c36e716a770a7aefaf7f76cea872db7bffefdbc4c2f9e0'
      + '39c19adac915e7a63dcb8c8c78c113f29a3e0bc10e100ce0',
    qs: ''
      + '6f0a2fb763eaeb8eb324d564f03d4a55fdcd709e5f1b65e9'
      + '5702b0141182f9f945d71bc3e64a7dfdae7482a7dd5a4e58'
      + 'bc38f78de2013f2c468a621f08536969d2c8d011bb3bc259'
      + '2124692c91140a5472cad224acdacdeae5751dadfdf068b8'
      + '77bfa7374694c6a7be159fc3d24ff9eeeecaf62580427ad8'
      + '622d48c51a1c4b1701d768c79d8c819776e096d2694107a2'
      + 'f3ec0c32224795b59d32894834039dacb369280afb221bc0'
      + '90570a93cf409889b818bb30cccee98b2aa26dbba0f28499'
      + '08e1a3cd43fa1f1fb71049e5c77c3724d74dc351d9989057'
      + '37bbda3805bd6b1293da8774410fb66e3194e18cdb304dd9'
      + 'a0b59b583dcbc9fc045ac9d56aea5cfc9f8a0b95da1e11b7'
      + '574d1f976e45fe12294997fac66ca0b83fc056183549e850'
      + 'a11413cc4abbe39a211e8c8cbf82f2a23266b3c10ab9e286'
      + '07a1b6088909cddff856e1eb6b2cde8bdac53fa939827736'
      + 'ca1b892f6c95899613442bd02dbdb747f02487718e2d3f22'
      + 'f73734d29767ed8d0e346d0c4098b6fdcb4df7d0c4d29603'
      + '5bffe80d6c65ae0a1b814150d349096baaf950f2caf298d2'
      + 'b292a1d48cf82b10734fe8cedfa16914076dfe3e9b51337b'
      + 'ed28ea1e6824bb717b641ca0e526e175d3e5ed7892aebab0'
      + 'f207562cc938a821e2956107c09b6ce4049adddcd0b7505d'
      + '49ae6c69a20122461102d465d93dc03db026be54c303613a'
      + 'b8e5ce3fd4f65d0b6162ff740a0bf5469ffd442d8c509cd2'
      + '3b40dab90f6776ca17fc0678774bd6eee1fa85ababa52ec1'
      + 'a15031eb677c6c488661dddd8b83d6031fe294489ded5f08'
      + '8ad1689a14baeae7e688afa3033899c81f58de39b392ca94'
      + 'af6f15a46f19fa95c06f9493c8b96a9be25e78b9ea35013b'
      + 'caa76de6303939299d07426a88a334278fc3d0d9fa71373e'
      + 'be51d3c1076ab93a11d3d0d703366ff8cde4c11261d488e5'
      + '60a2bdf3bfe2476032294800d6a4a39d306e65c6d7d8d66e'
      + '5ec63eee94531e83a9bddc458a2b508285c0ee10b7bd94da'
      + '2815a0c5bd5b2e15cbe66355e42f5af8955cdfc0b3a4996d'
      + '288db1f4b32b15643b18193e378cb7491f3c3951cdd044b1'
      + 'a519571bffac2da986f5f1d506c66530a55f70751e24fa8e'
      + 'd83ac2347f4069fb561a5565e78c6f0207da24e889a93a96'
      + '65f717d9fe8a2938a09ab5f81be7ccecf466c0397fc15a57'
      + '469939793f302739765773c256a3ca55d0548afd117a7cae'
      + '98ca7e0d749a130c7b743d376848e255f8fdbe4cb4480b63'
      + 'cd2c015d1020cf095d175f3ca9dcdfbaf1b2a6e6468eee4c'
      + 'c750f2132a77f376bd9782b9d0ff4da98621b898e251a263'
      + '4301ba2214a8c430b2f7a79dbbfd6d7ff6e9b0c137b025ff'
      + '587c0bf912f0b19d4fff96b1ecd2ca990c89b386055c60f2'
      + '3b94214bd55096f17a7b2c0fa12b333235101cd6f28a128c'
      + '782e8a72671adadebbd073ded30bd7f09fb693565dcf0bf3'
      + '090c21d13e5b0989dd8956f18f17f4f69449a13549c9d80a'
      + '77e5e61b5aeeee9528634100e7bc390672f0ded1ca53555b'
      + 'abddbcf700b9da6192255bddf50a76b709fbed251dce4c7e'
      + '1ca36b85d1e97c1bc9d38c887a5adf140f9eeef674c31422'
      + 'e65f63cae719f8c1324e42fa5fd8500899ef5aa3f9856aa7'
      + 'ce10c85600a040343204f36bfeab8cfa6e9deb8a2edd2a8e'
      + '018d00c7c9fa3a251ad0f57183c37e6377797653f382ec7a'
      + '2b0145e16d3c856bc3634b46d90d7198aff12aff88a30e34'
      + 'e2bfaf62705f3382576a9d3eeb0829fca2387b5b654af46e'
      + '5cf6316fb57d59e5ea6c369061ac64d99671b0e516529dd5'
      + 'd9c48ea0503e55fee090d36c5ea8b5954f6fcc0060794e1c'
      + 'b7bc24aa1e5c0142fd4ce6e8fd5aa92a7bf84317ea9e1642'
      + 'b6995bac6705adf93cbce72433ed0871139970d640f67b78'
      + 'e63a7a6d849db2567df69ac7d79f8c62664ac221df228289'
      + 'd0a4f9ebd9acb4f87d49da64e51a619fd3f3baccbd9feb12'
      + '5abe0cc2c8d17ed1d8546da2b6c641f4d3020a5f9b9f26ac'
      + '16546c2d61385505612275ea344c2bbf1ce890023738f715'
      + '5e9eba6a071678c8ebd009c328c3eb643679de86e69a9fa5'
      + '67a9e146030ff03d546310a0a568c5ba0070e0da22f2cef8'
      + '54714b04d399bbc8fd261f9e8efcd0e83bdbc3f5cfb2d024'
      + '3e398478cc598e000124eb8858f9df8f52946c2a1ca5c400'
  }
};

const symbols = [
  [0, 1, 1],
  [0, -1, 1],
  [1, 1, 1],
  [1, -1, 1],
  [0, 5, 0],
  [1, 5, 1],
  [2, 5, -1],
  [-2, 5, -1],
  [2, -5, -1],
  [-2, -5, 1],
  [3, 5, -1],
  [5, 5, 0],
  [-5, 5, 0],
  [6, 5, 1],
  [6, -5, 1],
  [-6, 5, 1],
  [-6, -5, -1]
];

describe('BN.js', function() {
  describe('BN.js/Arithmetic', () => {
    describe('.add()', () => {
      it('should add numbers', () => {
        assert.equal(new BN(14).add(new BN(26)).toString(16), '28');

        const k = new BN(0x1234);

        let r = k;

        for (let i = 0; i < 257; i++)
          r = r.add(k);

        assert.equal(r.toString(16), '125868');
      });

      it('should handle carry properly (in-place)', () => {
        const k = new BN('abcdefabcdefabcdef', 16);
        const r = new BN('deadbeef', 16);

        for (let i = 0; i < 257; i++)
          r.iadd(k);

        assert.equal(r.toString(16), 'ac79bd9b79be7a277bde');
      });

      it('should properly do positive + negative', () => {
        let a = new BN('abcd', 16);
        let b = new BN('-abce', 16);

        assert.equal(a.iadd(b).toString(16), '-1');

        a = new BN('abcd', 16);
        b = new BN('-abce', 16);

        assert.equal(a.add(b).toString(16), '-1');
        assert.equal(b.add(a).toString(16), '-1');
      });
    });

    describe('.iaddn()', () => {
      it('should allow a sign change', () => {
        const a = new BN(-100);

        assert.equal(a.negative, 1);

        a.iaddn(200);

        assert.equal(a.negative, 0);
        assert.equal(a.toString(), '100');
      });

      it('should add negative number', () => {
        const a = new BN(-100);

        assert.equal(a.negative, 1);

        a.iaddn(-200);

        assert.equal(a.toString(), '-300');
      });

      it('should allow neg + pos with big number', () => {
        const a = new BN('-1000000000', 10);

        assert.equal(a.negative, 1);

        a.iaddn(200);

        assert.equal(a.toString(), '-999999800');
      });

      it('should carry limb', () => {
        const a = new BN('3ffffff', 16);

        assert.equal(a.iaddn(1).toString(16), '4000000');
      });

      it('should throw error with num eq 0x4000000', () => {
        assert.throws(() => {
          new BN(0).iaddn(0x4000000);
        });
      });

      it('should reset sign if value equal to value in instance', function () {
        const a = new BN(-1);
        assert.equal(a.addn(1).toString(), '0');
      });
    });

    describe('.sub()', () => {
      it('should subtract small numbers', () => {
        assert.equal(new BN(26).sub(new BN(14)).toString(16), 'c');
        assert.equal(new BN(14).sub(new BN(26)).toString(16), '-c');
        assert.equal(new BN(26).sub(new BN(26)).toString(16), '0');
        assert.equal(new BN(-26).sub(new BN(26)).toString(16), '-34');
      });

      const a = new BN(
        '31ff3c61db2db84b9823d320907a573f6ad37c437abe458b1802cda041d6384' +
        'a7d8daef41395491e2',
        16);

      const b = new BN(
        '6f0e4d9f1d6071c183677f601af9305721c91d31b0bbbae8fb790000',
        16);

      const r = new BN(
        '31ff3c61db2db84b9823d3208989726578fd75276287cd9516533a9acfb9a67' +
        '76281f34583ddb91e2',
        16);

      it('should subtract big numbers', () => {
        assert.equal(a.sub(b).cmp(r), 0);
      });

      it('should subtract numbers in place', () => {
        assert.equal(b.clone().isub(a).neg().cmp(r), 0);
      });

      it('should subtract with carry', () => {
        // Carry and copy
        let a = new BN('12345', 16);
        let b = new BN('1000000000000', 16);

        assert.equal(a.isub(b).toString(16), '-fffffffedcbb');

        a = new BN('12345', 16);
        b = new BN('1000000000000', 16);

        assert.equal(b.isub(a).toString(16), 'fffffffedcbb');
      });
    });

    describe('.isubn()', () => {
      it('should subtract negative number', () => {
        const r = new BN(
          '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b', 16);
        assert.equal(r.isubn(-1).toString(16),
          '7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681c');
      });

      it('should work for positive numbers', () => {
        const a = new BN(-100);

        assert.equal(a.negative, 1);

        a.isubn(200);

        assert.equal(a.negative, 1);
        assert.equal(a.toString(), '-300');
      });

      it('should not allow a sign change', () => {
        const a = new BN(-100);

        assert.equal(a.negative, 1);

        a.isubn(-200);

        assert.equal(a.negative, 0);
        assert.equal(a.toString(), '100');
      });

      it('should change sign on small numbers at 0', () => {
        const a = new BN(0).subn(2);
        assert.equal(a.toString(), '-2');
      });

      it('should change sign on small numbers at 1', () => {
        const a = new BN(1).subn(2);
        assert.equal(a.toString(), '-1');
      });

      it('should throw error with num eq 0x4000000', () => {
        assert.throws(() => {
          new BN(0).isubn(0x4000000);
        });
      });
    });

    function testMethod(name, mul) {
      describe(name, () => {
        it('should multiply numbers of different signs', () => {
          const offsets = [
            1, // smallMulTo
            250, // comb10MulTo
            1000, // bigMulTo
            15000 // jumboMulTo
          ];

          for (let i = 0; i < offsets.length; ++i) {
            const x = new BN(1).ishln(offsets[i]);

            assert.equal(mul(x, x).isNeg(), false);
            assert.equal(mul(x, x.neg()).isNeg(), true);
            assert.equal(mul(x.neg(), x).isNeg(), true);
            assert.equal(mul(x.neg(), x.neg()).isNeg(), false);
          }
        });

        it('should multiply with carry', () => {
          const n = new BN(0x1001);

          let r = n;

          for (let i = 0; i < 4; i++)
            r = mul(r, n);

          assert.equal(r.toString(16), '100500a00a005001');
        });

        it('should correctly multiply big numbers', () => {
          const n = new BN(
            '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
            16
          );

          assert.equal(
            mul(n, n).toString(16),
            '39e58a8055b6fb264b75ec8c646509784204ac15a8c24e05babc9729ab9' +
            'b055c3a9458e4ce3289560a38e08ba8175a9446ce14e608245ab3a9' +
            '978a8bd8acaa40');

          assert.equal(
            mul(mul(n, n), n).toString(16),
            '1b888e01a06e974017a28a5b4da436169761c9730b7aeedf75fc60f687b' +
            '46e0cf2cb11667f795d5569482640fe5f628939467a01a612b02350' +
            '0d0161e9730279a7561043af6197798e41b7432458463e64fa81158' +
            '907322dc330562697d0d600');
        });

        it('should multiply neg number on 0', () => {
          assert.equal(
            mul(new BN('-100000000000'), new BN('3').div(new BN('4')))
              .toString(16),
            '0'
          );
        });

        it('should regress mul big numbers', () => {
          let q = dhGroups.p17.q;

          const qs = dhGroups.p17.qs;

          q = new BN(q, 16);
          assert.equal(mul(q, q).toString(16), qs);
        });
      });
    }

    testMethod('.mul()', (x, y) => {
      return BN.prototype.mul.apply(x, [y]);
    });

    describe('.imul()', () => {
      it('should multiply numbers in-place', () => {
        let a = new BN('abcdef01234567890abcd', 16);
        let b = new BN('deadbeefa551edebabba8', 16);
        let c = a.mul(b);

        assert.equal(a.imul(b).toString(16), c.toString(16));

        a = new BN('abcdef01234567890abcd214a25123f512361e6d236', 16);
        b = new BN('deadbeefa551edebabba8121234fd21bac0341324dd', 16);
        c = a.mul(b);

        assert.equal(a.imul(b).toString(16), c.toString(16));
      });

      it('should multiply by 0', () => {
        const a = new BN('abcdef01234567890abcd', 16);
        const b = new BN('0', 16);
        const c = a.mul(b);

        assert.equal(a.imul(b).toString(16), c.toString(16));
      });

      it('should regress mul big numbers in-place', () => {
        let q = dhGroups.p17.q;

        const qs = dhGroups.p17.qs;

        q = new BN(q, 16);

        assert.equal(q.isqr().toString(16), qs);
      });
    });

    describe('.muln()', () => {
      it('should multiply number by small number', () => {
        const a = new BN('abcdef01234567890abcd', 16);
        const b = new BN('dead', 16);
        const c = a.mul(b);

        assert.equal(a.muln(0xdead).toString(16), c.toString(16));
      });

      it('should throw error with num eq 0x4000000', () => {
        assert.throws(() => {
          new BN(0).imuln(0x4000000);
        });
      });

      it('should negate number if number is negative', () => {
        const a = new BN('dead', 16);

        assert.equal(a.clone().imuln(-1).toString(16),
                     a.clone().neg().toString(16));
        assert.equal(a.clone().muln(-1).toString(16),
                     a.clone().neg().toString(16));

        const b = new BN('dead', 16);

        assert.equal(b.clone().imuln(-42).toString(16),
                     b.clone().neg().muln(42).toString(16));
        assert.equal(b.clone().muln(-42).toString(16),
                     b.clone().neg().muln(42).toString(16));
      });
    });

    describe('.pow()', () => {
      it('should raise number to the power', () => {
        const a = new BN('ab', 16);
        const b = new BN('13', 10);

        assert.equal(a.pow(b).toString(16), '15963da06977df51909c9ba5b');
        assert.equal(a.clone().ipow(b).toString(16), '15963da06977df51909c9ba5b');
        assert.equal(a.pown(13).toString(16), '15963da06977df51909c9ba5b');
        assert.equal(a.clone().ipown(13).toString(16), '15963da06977df51909c9ba5b');
      });
    });

    describe('.div()', () => {
      it('should divide small numbers (<=26 bits)', () => {
        assert.equal(new BN('256').div(new BN(10)).toString(10),
          '25');
        assert.equal(new BN('-256').div(new BN(10)).toString(10),
          '-25');
        assert.equal(new BN('256').div(new BN(-10)).toString(10),
          '-25');
        assert.equal(new BN('-256').div(new BN(-10)).toString(10),
          '25');

        assert.equal(new BN('10').div(new BN(256)).toString(10),
          '0');
        assert.equal(new BN('-10').div(new BN(256)).toString(10),
          '0');
        assert.equal(new BN('10').div(new BN(-256)).toString(10),
          '0');
        assert.equal(new BN('-10').div(new BN(-256)).toString(10),
          '0');
      });

      it('should divide large numbers (>53 bits)', () => {
        assert.equal(new BN('1222222225255589').div(new BN('611111124969028'))
          .toString(10), '1');
        assert.equal(new BN('-1222222225255589').div(new BN('611111124969028'))
          .toString(10), '-1');
        assert.equal(new BN('1222222225255589').div(new BN('-611111124969028'))
          .toString(10), '-1');
        assert.equal(new BN('-1222222225255589').div(new BN('-611111124969028'))
          .toString(10), '1');

        assert.equal(new BN('611111124969028').div(new BN('1222222225255589'))
          .toString(10), '0');
        assert.equal(new BN('-611111124969028').div(new BN('1222222225255589'))
          .toString(10), '0');
        assert.equal(new BN('611111124969028').div(new BN('-1222222225255589'))
          .toString(10), '0');
        assert.equal(new BN('-611111124969028').div(new BN('-1222222225255589'))
          .toString(10), '0');
      });

      it('should divide numbers', () => {
        assert.equal(new BN('69527932928').div(new BN('16974594')).toString(16),
          'fff');
        assert.equal(new BN('-69527932928').div(new BN('16974594')).toString(16),
          '-fff');

        const b = new BN(''
          + '39e58a8055b6fb264b75ec8c646509784204ac15a8c24e05babc9729ab9'
          + 'b055c3a9458e4ce3289560a38e08ba8175a9446ce14e608245ab3a9'
          + '978a8bd8acaa40',
          16);

        const n = new BN(
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          16
        );

        assert.equal(b.div(n).toString(16), n.toString(16));

        assert.equal(new BN('1').div(new BN('-5')).toString(10), '0');
      });

      it('should not fail on regression after moving to _wordDiv', () => {
        // Regression after moving to word div
        let p = new BN(
          'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f',
          16);

        let a = new BN(
          '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          16);

        const as = a.sqr();

        assert.equal(
          as.div(p).toString(16),
          '39e58a8055b6fb264b75ec8c646509784204ac15a8c24e05babc9729e58090b9');

        p = new BN(
          'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
          16);

        a = new BN(''
          + 'fffffffe00000003fffffffd0000000200000001fffffffe00000002ffffffff'
          + 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          16);

        assert.equal(
          a.div(p).toString(16),
          'ffffffff00000002000000000000000000000001000000000000000000000001');
      });
    });

    describe('.idivn()', () => {
      it('should divide numbers in-place', () => {
        assert.equal(new BN('10', 16).idivn(3).toString(16), '5');
        assert.equal(new BN('10', 16).idivn(-3).toString(16), '-5');
        assert.equal(new BN('12', 16).idivn(3).toString(16), '6');
        assert.equal(new BN('10000000000000000').idivn(3).toString(10),
          '3333333333333333');

        assert.equal(
          new BN('100000000000000000000000000000').idivn(3).toString(10),
          '33333333333333333333333333333');

        const t = new BN(3);

        assert.equal(
          new BN('12345678901234567890123456', 16).idivn(3).toString(16),
          new BN('12345678901234567890123456', 16).div(t).toString(16));
      });
    });

    describe('.divRound()', () => {
      it('should divide numbers with rounding', () => {
        assert.equal(new BN(9).divRound(new BN(20)).toString(10),
          '0');
        assert.equal(new BN(10).divRound(new BN(20)).toString(10),
          '1');
        assert.equal(new BN(150).divRound(new BN(20)).toString(10),
          '8');
        assert.equal(new BN(149).divRound(new BN(20)).toString(10),
          '7');
        assert.equal(new BN(149).divRound(new BN(17)).toString(10),
          '9');
        assert.equal(new BN(144).divRound(new BN(17)).toString(10),
          '8');
        assert.equal(new BN(-144).divRound(new BN(17)).toString(10),
          '-8');
      });

      it('should return 1 on exact division', () => {
        assert.equal(new BN(144).divRound(new BN(144)).toString(10), '1');
      });
    });

    describe('.mod()', () => {
      it('should modulo small numbers (<=26 bits)', () => {
        assert.equal(new BN('256').mod(new BN(10)).toString(10),
          '6');
        assert.equal(new BN('-256').mod(new BN(10)).toString(10),
          '-6');
        assert.equal(new BN('256').mod(new BN(-10)).toString(10),
          '6');
        assert.equal(new BN('-256').mod(new BN(-10)).toString(10),
          '-6');

        assert.equal(new BN('10').mod(new BN(256)).toString(10),
          '10');
        assert.equal(new BN('-10').mod(new BN(256)).toString(10),
          '-10');
        assert.equal(new BN('10').mod(new BN(-256)).toString(10),
          '10');
        assert.equal(new BN('-10').mod(new BN(-256)).toString(10),
          '-10');
      });

      it('should modulo large numbers (>53 bits)', () => {
        assert.equal(new BN('1222222225255589').mod(new BN('611111124969028'))
          .toString(10), '611111100286561');
        assert.equal(new BN('-1222222225255589').mod(new BN('611111124969028'))
          .toString(10), '-611111100286561');
        assert.equal(new BN('1222222225255589').mod(new BN('-611111124969028'))
          .toString(10), '611111100286561');
        assert.equal(new BN('-1222222225255589').mod(new BN('-611111124969028'))
          .toString(10), '-611111100286561');

        assert.equal(new BN('611111124969028').mod(new BN('1222222225255589'))
          .toString(10), '611111124969028');
        assert.equal(new BN('-611111124969028').mod(new BN('1222222225255589'))
          .toString(10), '-611111124969028');
        assert.equal(new BN('611111124969028').mod(new BN('-1222222225255589'))
          .toString(10), '611111124969028');
        assert.equal(new BN('-611111124969028').mod(new BN('-1222222225255589'))
          .toString(10), '-611111124969028');
      });

      it('should mod numbers', () => {
        assert.equal(new BN('10').mod(new BN(256)).toString(16),
          'a');
        assert.equal(new BN('69527932928').mod(new BN('16974594')).toString(16),
          '102f302');

        // 178 = 10 * 17 + 8
        assert.equal(new BN(178).div(new BN(10)).toNumber(), 17);
        assert.equal(new BN(178).mod(new BN(10)).toNumber(), 8);
        assert.equal(new BN(178).umod(new BN(10)).toNumber(), 8);

        // -178 = 10 * (-17) + (-8)
        assert.equal(new BN(-178).div(new BN(10)).toNumber(), -17);
        assert.equal(new BN(-178).mod(new BN(10)).toNumber(), -8);
        assert.equal(new BN(-178).umod(new BN(10)).toNumber(), 2);

        // 178 = -10 * (-17) + 8
        assert.equal(new BN(178).div(new BN(-10)).toNumber(), -17);
        assert.equal(new BN(178).mod(new BN(-10)).toNumber(), 8);
        assert.equal(new BN(178).umod(new BN(-10)).toNumber(), 8);

        // -178 = -10 * (17) + (-8)
        assert.equal(new BN(-178).div(new BN(-10)).toNumber(), 17);
        assert.equal(new BN(-178).mod(new BN(-10)).toNumber(), -8);
        assert.equal(new BN(-178).umod(new BN(-10)).toNumber(), 2);

        // -4 = 1 * (-3) + -1
        assert.equal(new BN(-4).div(new BN(-3)).toNumber(), 1);
        assert.equal(new BN(-4).mod(new BN(-3)).toNumber(), -1);

        // -4 = -1 * (3) + -1
        assert.equal(new BN(-4).mod(new BN(3)).toNumber(), -1);
        // -4 = 1 * (-3) + (-1 + 3)
        assert.equal(new BN(-4).umod(new BN(-3)).toNumber(), 2);

        const p = new BN(
          'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
          16);

        const a = new BN(
          'fffffffe00000003fffffffd0000000200000001fffffffe00000002ffffffff' +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          16);

        assert.equal(
          a.mod(p).toString(16),
          '0');
      });

      it('should properly carry the sign inside division', () => {
        const a = new BN('945304eb96065b2a98b57a48a06ae28d285a71b5', 'hex');
        const b = new BN(
          'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe',
          'hex');

        assert.equal(a.mul(b).mod(a).cmpn(0), 0);
      });
    });

    describe('.modrn()', () => {
      it('should act like .mod() on small numbers', () => {
        assert.equal(new BN('10', 16).modrn(256).toString(16), '10');
        assert.equal(new BN('10', 16).modrn(-256).toString(16), '10');
        assert.equal(new BN('100', 16).modrn(256).toString(16), '0');
        assert.equal(new BN('1001', 16).modrn(256).toString(16), '1');
        assert.equal(new BN('100000000001', 16).modrn(256).toString(16), '1');
        assert.equal(new BN('100000000001', 16).modrn(257).toString(16),
          new BN('100000000001', 16).mod(new BN(257)).toString(16));
        assert.equal(new BN('123456789012', 16).modrn(3).toString(16),
          new BN('123456789012', 16).mod(new BN(3)).toString(16));
      });
    });

    describe('.abs()', () => {
      it('should return absolute value', () => {
        assert.equal(new BN(0x1001).abs().toString(), '4097');
        assert.equal(new BN(-0x1001).abs().toString(), '4097');
        assert.equal(new BN('ffffffff', 16).abs().toString(), '4294967295');
      });
    });

    describe('.invm()', () => {
      it('should invert relatively-prime numbers', () => {
        const p = new BN(257);

        let a = new BN(3);
        let b = a.invm(p);

        assert.equal(a.mul(b).mod(p).toString(16), '1');

        const p192 = new BN(
          'fffffffffffffffffffffffffffffffeffffffffffffffff',
          16);

        a = new BN('deadbeef', 16);
        b = a.invm(p192);

        assert.equal(a.mul(b).mod(p192).toString(16), '1');

        // Even base
        const phi = new BN('872d9b030ba368706b68932cf07a0e0c', 16);
        const e = new BN(65537);
        const d = e.invm(phi);

        assert.equal(e.mul(d).mod(phi).toString(16), '1');

        // Even base (take #2)
        a = new BN('5');
        b = new BN('6');

        const r = a.invm(b);

        assert.equal(r.mul(a).mod(b).toString(16), '1');
      });
    });

    describe('.finvm()', () => {
      it('should invert relatively-prime numbers', () => {
        const p = new BN(257);

        let a = new BN(3);
        let b = a.finvm(p);

        assert.equal(a.mul(b).mod(p).toString(16), '1');

        const p192 = new BN(
          'fffffffffffffffffffffffffffffffeffffffffffffffff',
          16);

        a = new BN('deadbeef', 16);
        b = a.finvm(p192);

        assert.equal(a.mul(b).mod(p192).toString(16), '1');
      });
    });

    describe('.gcd()', () => {
      it('should return GCD', () => {
        assert.equal(new BN(3).gcd(new BN(2)).toString(10), '1');
        assert.equal(new BN(18).gcd(new BN(12)).toString(10), '6');
        assert.equal(new BN(-18).gcd(new BN(12)).toString(10), '6');
        assert.equal(new BN(-18).gcd(new BN(-12)).toString(10), '6');
        assert.equal(new BN(-18).gcd(new BN(0)).toString(10), '18');
        assert.equal(new BN(0).gcd(new BN(-18)).toString(10), '18');
        assert.equal(new BN(2).gcd(new BN(0)).toString(10), '2');
        assert.equal(new BN(0).gcd(new BN(3)).toString(10), '3');
        assert.equal(new BN(0).gcd(new BN(0)).toString(10), '0');
      });
    });

    describe('.egcd()', () => {
      it('should return EGCD', () => {
        assert.equal(new BN(3).egcd(new BN(2))[2].toString(10), '1');
        assert.equal(new BN(18).egcd(new BN(12))[2].toString(10), '6');
        assert.equal(new BN(-18).egcd(new BN(12))[2].toString(10), '6');
        assert.equal(new BN(0).egcd(new BN(12))[2].toString(10), '12');
      });
      it('should not allow 0 input', () => {
        assert.throws(() => {
          new BN(1).egcd(0);
        });
      });
      it('should not allow negative input', () => {
        assert.throws(() => {
          new BN(1).egcd(-1);
        });
      });
    });

    describe('BN.max(a, b)', () => {
      it('should return maximum', () => {
        assert.equal(BN.max(new BN(3), new BN(2)).toString(16), '3');
        assert.equal(BN.max(new BN(2), new BN(3)).toString(16), '3');
        assert.equal(BN.max(new BN(2), new BN(2)).toString(16), '2');
        assert.equal(BN.max(new BN(2), new BN(-2)).toString(16), '2');
      });
    });

    describe('BN.min(a, b)', () => {
      it('should return minimum', () => {
        assert.equal(BN.min(new BN(3), new BN(2)).toString(16), '2');
        assert.equal(BN.min(new BN(2), new BN(3)).toString(16), '2');
        assert.equal(BN.min(new BN(2), new BN(2)).toString(16), '2');
        assert.equal(BN.min(new BN(2), new BN(-2)).toString(16), '-2');
      });
    });

    describe('BN.ineg', () => {
      it('shouldn\'t change sign for zero', () => {
        assert.equal(new BN(0).ineg().toString(10), '0');
      });
    });
  });

  describe('BN.js/Binary', () => {
    describe('.shl()', () => {
      it('should shl numbers', () => {
        // TODO(indutny): add negative numbers when the time will come
        assert.equal(new BN('69527932928').shln(13).toString(16),
          '2060602000000');
        assert.equal(new BN('69527932928').shln(45).toString(16),
          '206060200000000000000');
      });

      it('should ushl numbers', () => {
        assert.equal(new BN('69527932928').ushln(13).toString(16),
          '2060602000000');
        assert.equal(new BN('69527932928').ushln(45).toString(16),
          '206060200000000000000');
      });
    });

    describe('.shr()', () => {
      it('should shr numbers', () => {
        // TODO(indutny): add negative numbers when the time will come
        assert.equal(new BN('69527932928').shrn(13).toString(16),
          '818180');
        assert.equal(new BN('69527932928').shrn(17).toString(16),
          '81818');
        assert.equal(new BN('69527932928').shrn(256).toString(16),
          '0');
      });

      it('should ushr numbers', () => {
        assert.equal(new BN('69527932928').ushrn(13).toString(16),
          '818180');
        assert.equal(new BN('69527932928').ushrn(17).toString(16),
          '81818');
        assert.equal(new BN('69527932928').ushrn(256).toString(16),
          '0');
      });
    });

    describe('.bincn()', () => {
      it('should increment bit', () => {
        assert.equal(new BN(0).bincn(1).toString(16), '2');
        assert.equal(new BN(2).bincn(1).toString(16), '4');
        assert.equal(new BN(2).bincn(1).bincn(1).toString(16),
          new BN(2).bincn(2).toString(16));
        assert.equal(new BN(0xffffff).bincn(1).toString(16), '1000001');
        assert.equal(new BN(2).bincn(63).toString(16),
          '8000000000000002');
      });
    });

    describe('.imaskn()', () => {
      it('should mask bits in-place', () => {
        assert.equal(new BN(0).imaskn(1).toString(16), '0');
        assert.equal(new BN(3).imaskn(1).toString(16), '1');
        assert.equal(new BN('123456789', 16).imaskn(4).toString(16), '9');
        assert.equal(new BN('123456789', 16).imaskn(16).toString(16), '6789');
        assert.equal(new BN('123456789', 16).imaskn(28).toString(16), '3456789');
      });

      it('should not mask when number is bigger than length', () => {
        assert.equal(new BN(0xe3).imaskn(56).toString(16), 'e3');
        assert.equal(new BN(0xe3).imaskn(26).toString(16), 'e3');
      });
    });

    describe('.testn()', () => {
      it('should support test specific bit', () => {
        [
          'ff',
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
        ].forEach((hex) => {
          const bn = new BN(hex, 16);
          const bl = bn.bitLength();

          for (let i = 0; i < bl; ++i) {
            assert.equal(bn.testn(i), true);
          }

          // test off the end
          assert.equal(bn.testn(bl), false);
        });

        const xbits = '01111001010111001001000100011101' +
          '11010011101100011000111001011101' +
          '10010100111000000001011000111101' +
          '01011111001111100100011110000010' +
          '01011010100111010001010011000100' +
          '01101001011110100001001111100110' +
          '001110010111';

        const x = new BN(
          '23478905234580795234378912401239784125643978256123048348957342'
        );
        for (let i = 0; i < x.bitLength(); ++i) {
          assert.equal(x.testn(i), (xbits.charAt(i) === '1'), 'Failed @ bit ' + i);
        }
      });

      it('should have short-cuts', () => {
        const x = new BN('abcd', 16);
        assert(!x.testn(128));
      });
    });

    describe('.and()', () => {
      it('should and numbers', () => {
        assert.equal(new BN('1010101010101010101010101010101010101010', 2)
          .and(new BN('101010101010101010101010101010101010101', 2))
          .toString(2), '0');
      });

      it('should and numbers of different limb-length', () => {
        assert.equal(
          new BN('abcd0000ffff', 16)
            .and(new BN('abcd', 16)).toString(16),
          'abcd');
      });
    });

    describe('.iand()', () => {
      it('should iand numbers', () => {
        assert.equal(new BN('1010101010101010101010101010101010101010', 2)
          .iand(new BN('101010101010101010101010101010101010101', 2))
          .toString(2), '0');
        assert.equal(new BN('1000000000000000000000000000000000000001', 2)
          .iand(new BN('1', 2))
          .toString(2), '1');
        assert.equal(new BN('1', 2)
          .iand(new BN('1000000000000000000000000000000000000001', 2))
          .toString(2), '1');
      });
    });

    describe('.or()', () => {
      it('should or numbers', () => {
        assert.equal(new BN('1010101010101010101010101010101010101010', 2)
          .or(new BN('101010101010101010101010101010101010101', 2))
          .toString(2), '1111111111111111111111111111111111111111');
      });

      it('should or numbers of different limb-length', () => {
        assert.equal(
          new BN('abcd00000000', 16)
            .or(new BN('abcd', 16)).toString(16),
          'abcd0000abcd');
      });
    });

    describe('.ior()', () => {
      it('should ior numbers', () => {
        assert.equal(new BN('1010101010101010101010101010101010101010', 2)
          .ior(new BN('101010101010101010101010101010101010101', 2))
          .toString(2), '1111111111111111111111111111111111111111');
        assert.equal(new BN('1000000000000000000000000000000000000000', 2)
          .ior(new BN('1', 2))
          .toString(2), '1000000000000000000000000000000000000001');
        assert.equal(new BN('1', 2)
          .ior(new BN('1000000000000000000000000000000000000000', 2))
          .toString(2), '1000000000000000000000000000000000000001');
      });
    });

    describe('.xor()', () => {
      it('should xor numbers', () => {
        assert.equal(new BN('11001100110011001100110011001100', 2)
          .xor(new BN('1100110011001100110011001100110', 2))
          .toString(2), '10101010101010101010101010101010');
      });
    });

    describe('.ixor()', () => {
      it('should ixor numbers', () => {
        assert.equal(new BN('11001100110011001100110011001100', 2)
          .ixor(new BN('1100110011001100110011001100110', 2))
          .toString(2), '10101010101010101010101010101010');
        assert.equal(new BN('11001100110011001100110011001100', 2)
          .ixor(new BN('1', 2))
          .toString(2), '11001100110011001100110011001101');
        assert.equal(new BN('1', 2)
          .ixor(new BN('11001100110011001100110011001100', 2))
          .toString(2), '11001100110011001100110011001101');
      });

      it('should and numbers of different limb-length', () => {
        assert.equal(
          new BN('abcd0000ffff', 16)
            .xor(new BN('abcd', 16)).toString(16),
          'abcd00005432');
      });
    });

    describe('.setn()', () => {
      it('should allow single bits to be set', () => {
        assert.equal(new BN(0).setn(2, true).toString(2), '100');
        assert.equal(new BN(0).setn(27, true).toString(2),
          '1000000000000000000000000000');
        assert.equal(new BN(0).setn(63, true).toString(16),
          new BN(1).iushln(63).toString(16));
        assert.equal(new BN('1000000000000000000000000001', 2).setn(27, false)
          .toString(2), '1');
        assert.equal(new BN('101', 2).setn(2, false).toString(2), '1');
      });
    });

    describe('.notn()', () => {
      it('should allow bitwise negation', () => {
        assert.equal(new BN('111000111', 2).notn(9).toString(2),
          '111000');
        assert.equal(new BN('000111000', 2).notn(9).toString(2),
          '111000111');
        assert.equal(new BN('111000111', 2).notn(9).toString(2),
          '111000');
        assert.equal(new BN('000111000', 2).notn(9).toString(2),
          '111000111');
        assert.equal(new BN('111000111', 2).notn(32).toString(2),
          '11111111111111111111111000111000');
        assert.equal(new BN('000111000', 2).notn(32).toString(2),
          '11111111111111111111111111000111');
        assert.equal(new BN('111000111', 2).notn(68).toString(2),
          '11111111111111111111111111111111' +
          '111111111111111111111111111000111000');
        assert.equal(new BN('000111000', 2).notn(68).toString(2),
          '11111111111111111111111111111111' +
          '111111111111111111111111111111000111');
      });
    });
  });

  describe('BN.js/Constructor', () => {
    describe('with Smi input', () => {
      it('should accept one limb number', () => {
        assert.equal(new BN(12345).toString(16), '3039');
      });

      it('should accept two-limb number', () => {
        assert.equal(new BN(0x4123456).toString(16), '4123456');
      });

      it('should accept 52 bits of precision', () => {
        const num = Math.pow(2, 52);
        assert.equal(new BN(num, 10).toString(10), num.toString(10));
      });

      it('should accept max safe integer', () => {
        const num = Math.pow(2, 53) - 1;
        assert.equal(new BN(num, 10).toString(10), num.toString(10));
      });

      it('should not accept an unsafe integer', () => {
        const num = Math.pow(2, 53);

        assert.throws(() => {
          return new BN(num, 10);
        });
      });

      it('should accept two-limb LE number', () => {
        assert.equal(new BN(0x4123456, null, 'le').toString(16), '56341204');
      });
    });

    describe('with String input', () => {
      it('should accept base-16', () => {
        assert.equal(new BN('1A6B765D8CDF', 16).toString(16), '1a6b765d8cdf');
        assert.equal(new BN('1A6B765D8CDF', 16).toString(), '29048849665247');
      });

      it('should accept base-hex', () => {
        assert.equal(new BN('FF', 'hex').toString(), '255');
      });

      it('should accept base-16 with spaces', () => {
        const num = 'a89c e5af8724 c0a23e0e 0ff77500';
        assert.equal(new BN(num, 16).toString(16), num.replace(/ /g, ''));
      });

      it('should accept long base-16', () => {
        const num = '123456789abcdef123456789abcdef123456789abcdef';
        assert.equal(new BN(num, 16).toString(16), num);
      });

      it('should accept positive base-10', () => {
        assert.equal(new BN('10654321').toString(), '10654321');
        assert.equal(new BN('29048849665247').toString(16), '1a6b765d8cdf');
      });

      it('should accept negative base-10', () => {
        assert.equal(new BN('-29048849665247').toString(16), '-1a6b765d8cdf');
      });

      it('should accept long base-10', () => {
        const num = '10000000000000000';
        assert.equal(new BN(num).toString(10), num);
      });

      it('should accept base-2', () => {
        const base2 = '11111111111111111111111111111111111111111111111111111';
        assert.equal(new BN(base2, 2).toString(2), base2);
      });

      it('should accept base-36', () => {
        const base36 = 'zzZzzzZzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz';
        assert.equal(new BN(base36, 36).toString(36), base36.toLowerCase());
      });

      it('should not overflow limbs during base-10', () => {
        const num = '65820182292848241686198767302293' +
          '20890292528855852623664389292032';
        const n = new BN(num);
        assert(!n.words || n.words[0] < 0x4000000);
      });

      it('should accept base-16 LE integer', () => {
        assert.equal(new BN('1A6B765D8CDF', 16, 'le').toString(16),
          'df8c5d766b1a');
      });

      it('should not accept wrong characters for base', () => {
        assert.throws(() => {
          return new BN('01FF');
        });
      });

      it('should not accept decimal', () => {
        assert.throws(() => {
          const res = new BN('10.00', 10);
          res;
        });

        assert.throws(() => {
          const res = new BN('16.00', 16);
          res;
        });
      });

      it('should not accept non-hex characters', () => {
        [
          '0000000z',
          '000000gg',
          '0000gg00',
          'fffggfff',
          '/0000000',
          '0-000000', // if -, is first, that is OK
          'ff.fffff',
          'hexadecimal'
        ].forEach((str) => {
          assert.throws(() => {
            const res = new BN(str, 16);
            res;
          });
        });
      });

      it.skip('should not ignore zeroes on LE string', () => {
        assert.strictEqual(new BN('0010', 'hex', 'le').toNumber(), 256);
      });
    });

    describe('with Array input', () => {
      it('should not fail on empty array', () => {
        assert.equal(new BN([]).toString(16), '0');
      });

      it('should import/export big endian', () => {
        assert.equal(new BN([1, 2, 3]).toString(16), '10203');
        assert.equal(new BN([1, 2, 3, 4]).toString(16), '1020304');
        assert.equal(new BN([1, 2, 3, 4, 5]).toString(16), '102030405');
        assert.equal(new BN([1, 2, 3, 4, 5, 6, 7, 8]).toString(16),
          '102030405060708');
        assert.equal(new BN([1, 2, 3, 4]).toArray().join(','), '1,2,3,4');
        assert.equal(new BN([1, 2, 3, 4, 5, 6, 7, 8]).toArray().join(','),
          '1,2,3,4,5,6,7,8');
      });

      it('should import little endian', () => {
        assert.equal(new BN([1, 2, 3], 10, 'le').toString(16), '30201');
        assert.equal(new BN([1, 2, 3, 4], 10, 'le').toString(16), '4030201');
        assert.equal(new BN([1, 2, 3, 4, 5], 10, 'le').toString(16),
          '504030201');
        assert.equal(new BN([1, 2, 3, 4, 5, 6, 7, 8], 'le').toString(16),
          '807060504030201');
        assert.equal(new BN([1, 2, 3, 4]).toArray('le').join(','), '4,3,2,1');
        assert.equal(new BN([1, 2, 3, 4, 5, 6, 7, 8]).toArray('le').join(','),
          '8,7,6,5,4,3,2,1');
      });

      it('should import big endian with implicit base', () => {
        assert.equal(new BN([1, 2, 3, 4, 5], 'le').toString(16), '504030201');
      });
    });

    // the Array code is able to handle Buffer
    describe('with Buffer input', () => {
      it('should not fail on empty Buffer', () => {
        assert.equal(new BN(Buffer.alloc(0)).toString(16), '0');
      });

      it('should import/export big endian', () => {
        assert.equal(new BN(Buffer.from('010203', 'hex')).toString(16), '10203');
      });

      it('should import little endian', () => {
        assert.equal(new BN(Buffer.from('010203', 'hex'), 'le').toString(16), '30201');
      });
    });

    describe('with BN input', () => {
      it('should clone BN', () => {
        const num = new BN(12345);
        assert.equal(new BN(num).toString(10), '12345');
      });
    });
  });

  describe('BN.js/Reduction context', () => {
    function testMethod(name, fn) {
      describe(name + ' method', () => {
        it('should support add, iadd, sub, isub operations', () => {
          const p = new BN(257);
          const m = fn(p);
          const a = new BN(123).toRed(m);
          const b = new BN(231).toRed(m);

          assert.equal(a.redAdd(b).fromRed().toString(10), '97');
          assert.equal(a.redSub(b).fromRed().toString(10), '149');
          assert.equal(b.redSub(a).fromRed().toString(10), '108');

          assert.equal(a.clone().redIAdd(b).fromRed().toString(10), '97');
          assert.equal(a.clone().redISub(b).fromRed().toString(10), '149');
          assert.equal(b.clone().redISub(a).fromRed().toString(10), '108');
        });

        it('should support pow and mul operations', () => {
          const p192 = new BN(
            'fffffffffffffffffffffffffffffffeffffffffffffffff',
            16);

          const m = fn(p192);
          const a = new BN(123);
          const b = new BN(231);
          const c = a.toRed(m).redMul(b.toRed(m)).fromRed();

          assert(c.cmp(a.mul(b).mod(p192)) === 0);

          assert.equal(a.toRed(m).redPow(new BN(0)).fromRed()
            .cmp(new BN(1)), 0);
          assert.equal(a.toRed(m).redPow(new BN(3)).fromRed()
            .cmp(a.sqr().mul(a)), 0);
          assert.equal(a.toRed(m).redPow(new BN(4)).fromRed()
            .cmp(a.sqr().sqr()), 0);
          assert.equal(a.toRed(m).redPow(new BN(8)).fromRed()
            .cmp(a.sqr().sqr().sqr()), 0);
          assert.equal(a.toRed(m).redPow(new BN(9)).fromRed()
            .cmp(a.sqr().sqr().sqr().mul(a)), 0);
          assert.equal(a.toRed(m).redPow(new BN(17)).fromRed()
            .cmp(a.sqr().sqr().sqr().sqr().mul(a)), 0);
          assert.equal(
            a.toRed(m).redPow(new BN('deadbeefabbadead', 16)).fromRed()
              .toString(16),
            '3aa0e7e304e320b68ef61592bcb00341866d6fa66e11a4d6');
        });

        it('should sqrtm numbers', () => {
          let p = new BN(263);
          let m = fn(p);
          let q = new BN(11).toRed(m);
          let qr = q.redSqrt();

          assert.equal(qr.redSqr().cmp(q), 0);

          qr = q.redSqrt();
          assert.equal(qr.redSqr().cmp(q), 0);

          p = new BN(
            'fffffffffffffffffffffffffffffffeffffffffffffffff',
            16);
          m = fn(p);

          q = new BN(13).toRed(m);
          qr = q.redSqrt(true, p);
          assert.equal(qr.redSqr().cmp(q), 0);

          qr = q.redSqrt(false, p);
          assert.equal(qr.redSqr().cmp(q), 0);

          // Tonelli-shanks
          p = new BN(13);
          m = fn(p);
          q = new BN(10).toRed(m);
          assert.equal(q.redSqrt().fromRed().toString(10), '7');
        });

        it('should invm numbers', () => {
          const p = new BN(257);
          const m = fn(p);
          const a = new BN(3).toRed(m);
          const b = a.redInvm();

          assert.equal(a.redMul(b).fromRed().toString(16), '1');
        });

        it('should invm numbers (regression)', () => {
          const p = new BN(
            'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
            16);
          let a = new BN(
            'e1d969b8192fbac73ea5b7921896d6a2263d4d4077bb8e5055361d1f7f8163f3',
            16);

          const m = fn(p);
          a = a.toRed(m);

          assert.equal(a.redInvm().fromRed().negative, 0);
        });

        it('should imul numbers', () => {
          const p = new BN(
            'fffffffffffffffffffffffffffffffeffffffffffffffff',
            16);

          const m = fn(p);

          const a = new BN('deadbeefabbadead', 16);
          const b = new BN('abbadeadbeefdead', 16);
          const c = a.mul(b).mod(p);

          assert.equal(a.toRed(m).redIMul(b.toRed(m)).fromRed().toString(16),
            c.toString(16));
        });

        it('should pow(base, 0) == 1', () => {
          const base = new BN(256).toRed(BN.red('k256'));
          const exponent = new BN(0);
          const result = base.redPow(exponent);
          assert.equal(result.toString(), '1');
        });

        it('should shl numbers', () => {
          const base = new BN(256).toRed(BN.red('k256'));
          const result = base.redShln(1);
          assert.equal(result.toString(), '512');
        });

        it('should reduce when converting to red', () => {
          const p = new BN(257);
          const m = fn(p);
          const a = new BN(5).toRed(m);

          assert.doesNotThrow(() => {
            const b = a.redISub(new BN(512).toRed(m));
            b.redISub(new BN(512).toRed(m));
          });
        });

        it('redNeg and zero value', () => {
          const a = new BN(0).toRed(BN.red('k256')).redNeg();
          assert.equal(a.isZero(), true);
        });

        it('should not allow modulus <= 1', () => {
          assert.throws(() => {
            BN.red(new BN(0));
          });

          assert.throws(() => {
            BN.red(new BN(1));
          });

          assert.doesNotThrow(() => {
            BN.red(new BN(2));
          });
        });
      });
    }

    testMethod('Plain', BN.red);
    testMethod('Montgomery', BN.mont);

    describe('Pseudo-Mersenne Primes', () => {
      it('should reduce numbers mod k256', () => {
        const p = BN._prime('k256');

        if (!p.ireduce)
          this.skip();

        assert.equal(p.ireduce(new BN(0xdead)).toString(16), 'dead');
        assert.equal(p.ireduce(new BN('deadbeef', 16)).toString(16), 'deadbeef');

        const num = new BN('fedcba9876543210fedcba9876543210dead' +
        'fedcba9876543210fedcba9876543210dead',
          16);

        let exp = num.mod(p.p).toString(16);

        assert.equal(p.ireduce(num).toString(16), exp);

        const regr = new BN('f7e46df64c1815962bf7bc9c56128798' +
        '3f4fcef9cb1979573163b477eab93959' +
        '335dfb29ef07a4d835d22aa3b6797760' +
        '70a8b8f59ba73d56d01a79af9',
          16);

        exp = regr.mod(p.p).toString(16);

        assert.equal(p.ireduce(regr).toString(16), exp);
      });

      it('should not fail to invm number mod k256', () => {
        let regr2 = new BN(
          '6c150c4aa9a8cf1934485d40674d4a7cd494675537bda36d49405c5d2c6f496f', 16);
        regr2 = regr2.toRed(BN.red('k256'));
        assert.equal(regr2.redInvm().redMul(regr2).fromRed().cmpn(1), 0);
      });

      it('should correctly square the number', () => {
        const p = BN._prime('k256').p;
        const red = BN.red('k256');

        const n = new BN('9cd8cb48c3281596139f147c1364a3ed' +
        'e88d3f310fdb0eb98c924e599ca1b3c9',
          16);
        const expected = n.sqr().mod(p);
        const actual = n.toRed(red).redSqr().fromRed();

        assert.equal(actual.toString(16), expected.toString(16));
      });

      it('redISqr should return right result', () => {
        const n = new BN('30f28939', 16);
        const actual = n.toRed(BN.red('k256')).redISqr().fromRed();
        assert.equal(actual.toString(16), '95bd93d19520eb1');
      });
    });

    it('should avoid 4.1.0 regresion', () => {
      function bits2int(obits, q) {
        const bits = new BN(obits);
        const shift = (obits.length << 3) - q.bitLength();
        if (shift > 0) {
          bits.ishrn(shift);
        }
        return bits;
      }

      const t = Buffer.from(''
        + 'aff1651e4cd6036d57aa8b2a05ccf1a9d5a40166340ecbbdc55'
        + 'be10b568aa0aa3d05ce9a2fcec9df8ed018e29683c6051cb83e'
        + '46ce31ba4edb045356a8d0d80b',
        'hex');

      const g = new BN(''
        + '5c7ff6b06f8f143fe8288433493e4769c4d988ace5be25a0e24809670'
        + '716c613d7b0cee6932f8faa7c44d2cb24523da53fbe4f6ec3595892d1'
        + 'aa58c4328a06c46a15662e7eaa703a1decf8bbb2d05dbe2eb956c142a'
        + '338661d10461c0d135472085057f3494309ffa73c611f78b32adbb574'
        + '0c361c9f35be90997db2014e2ef5aa61782f52abeb8bd6432c4dd097b'
        + 'c5423b285dafb60dc364e8161f4a2a35aca3a10b1c4d203cc76a470a3'
        + '3afdcbdd92959859abd8b56e1725252d78eac66e71ba9ae3f1dd24871'
        + '99874393cd4d832186800654760e1e34c09e4d155179f9ec0dc4473f9'
        + '96bdce6eed1cabed8b6f116f7ad9cf505df0f998e34ab27514b0ffe7',
        16);

      const p = new BN(''
        + '9db6fb5951b66bb6fe1e140f1d2ce5502374161fd6538df1648218642'
        + 'f0b5c48c8f7a41aadfa187324b87674fa1822b00f1ecf8136943d7c55'
        + '757264e5a1a44ffe012e9936e00c1d3e9310b01c7d179805d3058b2a9'
        + 'f4bb6f9716bfe6117c6b5b3cc4d9be341104ad4a80ad6c94e005f4b99'
        + '3e14f091eb51743bf33050c38de235567e1b34c3d6a5c0ceaa1a0f368'
        + '213c3d19843d0b4b09dcb9fc72d39c8de41f1bf14d4bb4563ca283716'
        + '21cad3324b6a2d392145bebfac748805236f5ca2fe92b871cd8f9c36d'
        + '3292b5509ca8caa77a2adfc7bfd77dda6f71125a7456fea153e433256'
        + 'a2261c6a06ed3693797e7995fad5aabbcfbe3eda2741e375404ae25b',
        16);

      const q = new BN(''
        + 'f2c3119374ce76c9356990b465374a17f23f9ed35089bd969f61c6dde'
        + '9998c1f', 16);

      const k = bits2int(t, q);
      const expectedR = ''
        + '89ec4bb1400eccff8e7d9aa515cd1de7803f2daff09693ee7fd1353e'
        + '90a68307';

      const r = g.toRed(BN.mont(p)).redPow(k).fromRed().mod(q);

      assert.equal(r.toString(16), expectedR);
    });

    it('K256.split for 512 bits number should return equal numbers', () => {
      const prime = BN._prime('k256');

      if (!prime.split)
        this.skip();

      const input = new BN(1).iushln(512).subn(1);
      assert.equal(input.bitLength(), 512);

      const output = new BN(0);
      prime.split(input, output);

      assert.equal(input.cmp(output), 0);
    });

    it('imod should change host object', () => {
      const red = BN.red(new BN(13));
      const a = new BN(2).toRed(red);
      const b = new BN(7).toRed(red);
      const c = a.redIMul(b);
      assert.equal(a.toNumber(), 1);
      assert.equal(c.toNumber(), 1);
    });
  });

  describe('BN.js/Utils', () => {
    describe('.toString()', () => {
      describe('binary padding', () => {
        it('should have a length of 256', () => {
          const a = new BN(0);

          assert.equal(a.toString(2, 256).length, 256);
        });
      });

      describe('hex padding', () => {
        it('should have length of 8 from leading 15', () => {
          const a = new BN('ffb9602', 16);

          assert.equal(a.toString('hex', 2).length, 8);
        });

        it('should have length of 8 from leading zero', () => {
          const a = new BN('fb9604', 16);

          assert.equal(a.toString('hex', 8).length, 8);
        });

        it('should have length of 8 from leading zeros', () => {
          const a = new BN(0);

          assert.equal(a.toString('hex', 8).length, 8);
        });

        it('should have length of 64 from leading 15', () => {
          const a = new BN(
            'ffb96ff654e61130ba8422f0debca77a0ea74ae5ea8bca9b54ab64aabf01003',
            16);

          assert.equal(a.toString('hex', 2).length, 64);
        });

        it('should have length of 64 from leading zero', () => {
          const a = new BN(
            'fb96ff654e61130ba8422f0debca77a0ea74ae5ea8bca9b54ab64aabf01003',
            16);

          assert.equal(a.toString('hex', 64).length, 64);
        });
      });
    });

    describe('.isNeg()', () => {
      it('should return true for negative numbers', () => {
        assert.equal(new BN(-1).isNeg(), true);
        assert.equal(new BN(1).isNeg(), false);
        assert.equal(new BN(0).isNeg(), false);
        assert.equal(new BN('-0', 10).isNeg(), false);
      });
    });

    describe('.isOdd()', () => {
      it('should return true for odd numbers', () => {
        assert.equal(new BN(0).isOdd(), false);
        assert.equal(new BN(1).isOdd(), true);
        assert.equal(new BN(2).isOdd(), false);
        assert.equal(new BN('-0', 10).isOdd(), false);
        assert.equal(new BN('-1', 10).isOdd(), true);
        assert.equal(new BN('-2', 10).isOdd(), false);
      });
    });

    describe('.isEven()', () => {
      it('should return true for even numbers', () => {
        assert.equal(new BN(0).isEven(), true);
        assert.equal(new BN(1).isEven(), false);
        assert.equal(new BN(2).isEven(), true);
        assert.equal(new BN('-0', 10).isEven(), true);
        assert.equal(new BN('-1', 10).isEven(), false);
        assert.equal(new BN('-2', 10).isEven(), true);
      });
    });

    describe('.isZero()', () => {
      it('should return true for zero', () => {
        assert.equal(new BN(0).isZero(), true);
        assert.equal(new BN(1).isZero(), false);
        assert.equal(new BN(0xffffffff).isZero(), false);
      });
    });

    describe('.bitLength()', () => {
      it('should return proper bitLength', () => {
        assert.equal(new BN(0).bitLength(), 0);
        assert.equal(new BN(0x1).bitLength(), 1);
        assert.equal(new BN(0x2).bitLength(), 2);
        assert.equal(new BN(0x3).bitLength(), 2);
        assert.equal(new BN(0x4).bitLength(), 3);
        assert.equal(new BN(0x8).bitLength(), 4);
        assert.equal(new BN(0x10).bitLength(), 5);
        assert.equal(new BN(0x100).bitLength(), 9);
        assert.equal(new BN(0x123456).bitLength(), 21);
        assert.equal(new BN('123456789', 16).bitLength(), 33);
        assert.equal(new BN('8023456789', 16).bitLength(), 40);
      });
    });

    describe('.byteLength()', () => {
      it('should return proper byteLength', () => {
        assert.equal(new BN(0).byteLength(), 0);
        assert.equal(new BN(0x1).byteLength(), 1);
        assert.equal(new BN(0x2).byteLength(), 1);
        assert.equal(new BN(0x3).byteLength(), 1);
        assert.equal(new BN(0x4).byteLength(), 1);
        assert.equal(new BN(0x8).byteLength(), 1);
        assert.equal(new BN(0x10).byteLength(), 1);
        assert.equal(new BN(0x100).byteLength(), 2);
        assert.equal(new BN(0x123456).byteLength(), 3);
        assert.equal(new BN('123456789', 16).byteLength(), 5);
        assert.equal(new BN('8023456789', 16).byteLength(), 5);
      });
    });

    describe('.toArray()', () => {
      it('should return [0] for `0`', () => {
        const n = new BN(0);
        assert.deepEqual(n.toArray('be'), [0]);
        assert.deepEqual(n.toArray('le'), [0]);
      });

      it('should zero pad to desired lengths', () => {
        const n = new BN(0x123456);
        assert.deepEqual(n.toArray('be', 5), [0x00, 0x00, 0x12, 0x34, 0x56]);
        assert.deepEqual(n.toArray('le', 5), [0x56, 0x34, 0x12, 0x00, 0x00]);
      });

      it('should throw when naturally larger than desired length', () => {
        const n = new BN(0x123456);
        assert.throws(() => {
          n.toArray('be', 2);
        });
      });
    });

    describe('.toBuffer', () => {
      it('should return proper Buffer', () => {
        const n = new BN(0x123456);
        assert.deepEqual(n.toBuffer('be', 5).toString('hex'), '0000123456');
        assert.deepEqual(n.toBuffer('le', 5).toString('hex'), '5634120000');
      });
    });

    describe('.toNumber()', () => {
      it('should return proper Number if below the limit', () => {
        assert.deepEqual(new BN(0x123456).toNumber(), 0x123456);
        assert.deepEqual(new BN(0x3ffffff).toNumber(), 0x3ffffff);
        assert.deepEqual(new BN(0x4000000).toNumber(), 0x4000000);
        assert.deepEqual(new BN(0x10000000000000).toNumber(), 0x10000000000000);
        assert.deepEqual(new BN(0x10040004004000).toNumber(), 0x10040004004000);
        assert.deepEqual(new BN(-0x123456).toNumber(), -0x123456);
        assert.deepEqual(new BN(-0x3ffffff).toNumber(), -0x3ffffff);
        assert.deepEqual(new BN(-0x4000000).toNumber(), -0x4000000);
        assert.deepEqual(new BN(-0x10000000000000).toNumber(), -0x10000000000000);
        assert.deepEqual(new BN(-0x10040004004000).toNumber(), -0x10040004004000);
      });

      it('should throw when number exceeds 53 bits', () => {
        const n = new BN(1).iushln(54);
        assert.throws(() => {
          n.toNumber();
        });
      });
    });

    describe('.zeroBits()', () => {
      it('should return proper zeroBits', () => {
        assert.equal(new BN(0).zeroBits(), 0);
        assert.equal(new BN(0x1).zeroBits(), 0);
        assert.equal(new BN(0x2).zeroBits(), 1);
        assert.equal(new BN(0x3).zeroBits(), 0);
        assert.equal(new BN(0x4).zeroBits(), 2);
        assert.equal(new BN(0x8).zeroBits(), 3);
        assert.equal(new BN(0x10).zeroBits(), 4);
        assert.equal(new BN(0x100).zeroBits(), 8);
        assert.equal(new BN(0x1000000).zeroBits(), 24);
        assert.equal(new BN(0x123456).zeroBits(), 1);
      });
    });

    describe('.toJSON', () => {
      it('should return hex string', () => {
        assert.equal(new BN(0x123).toJSON(), '0123');
      });

      it('should be padded to multiple of 2 bytes for interop', () => {
        assert.equal(new BN(0x1).toJSON(), '01');
      });
    });

    describe('.cmpn', () => {
      it('should return -1, 0, 1 correctly', () => {
        assert.equal(new BN(42).cmpn(42), 0);
        assert.equal(new BN(42).cmpn(43), -1);
        assert.equal(new BN(42).cmpn(41), 1);
        assert.equal(new BN(0x3fffffe).cmpn(0x3fffffe), 0);
        assert.equal(new BN(0x3fffffe).cmpn(0x3ffffff), -1);
        assert.equal(new BN(0x3fffffe).cmpn(0x3fffffd), 1);
        assert.throws(() => {
          new BN(0x3fffffe).cmpn(0x4000000);
        });
        assert.equal(new BN(42).cmpn(-42), 1);
        assert.equal(new BN(-42).cmpn(42), -1);
        assert.equal(new BN(-42).cmpn(-42), 0);
        assert.equal(1 / new BN(-42).cmpn(-42), Infinity);
      });
    });

    describe('.cmp', () => {
      it('should return -1, 0, 1 correctly', () => {
        assert.equal(new BN(42).cmp(new BN(42)), 0);
        assert.equal(new BN(42).cmp(new BN(43)), -1);
        assert.equal(new BN(42).cmp(new BN(41)), 1);
        assert.equal(new BN(0x3fffffe).cmp(new BN(0x3fffffe)), 0);
        assert.equal(new BN(0x3fffffe).cmp(new BN(0x3ffffff)), -1);
        assert.equal(new BN(0x3fffffe).cmp(new BN(0x3fffffd)), 1);
        assert.equal(new BN(0x3fffffe).cmp(new BN(0x4000000)), -1);
        assert.equal(new BN(42).cmp(new BN(-42)), 1);
        assert.equal(new BN(-42).cmp(new BN(42)), -1);
        assert.equal(new BN(-42).cmp(new BN(-42)), 0);
        assert.equal(1 / new BN(-42).cmp(new BN(-42)), Infinity);
      });
    });

    describe('comparison shorthands', () => {
      it('.gtn greater than', () => {
        assert.equal(new BN(3).gtn(2), true);
        assert.equal(new BN(3).gtn(3), false);
        assert.equal(new BN(3).gtn(4), false);
      });

      it('.gt greater than', () => {
        assert.equal(new BN(3).gt(new BN(2)), true);
        assert.equal(new BN(3).gt(new BN(3)), false);
        assert.equal(new BN(3).gt(new BN(4)), false);
      });

      it('.gten greater than or equal', () => {
        assert.equal(new BN(3).gten(3), true);
        assert.equal(new BN(3).gten(2), true);
        assert.equal(new BN(3).gten(4), false);
      });

      it('.gte greater than or equal', () => {
        assert.equal(new BN(3).gte(new BN(3)), true);
        assert.equal(new BN(3).gte(new BN(2)), true);
        assert.equal(new BN(3).gte(new BN(4)), false);
      });

      it('.ltn less than', () => {
        assert.equal(new BN(2).ltn(3), true);
        assert.equal(new BN(2).ltn(2), false);
        assert.equal(new BN(2).ltn(1), false);
      });

      it('.lt less than', () => {
        assert.equal(new BN(2).lt(new BN(3)), true);
        assert.equal(new BN(2).lt(new BN(2)), false);
        assert.equal(new BN(2).lt(new BN(1)), false);
      });

      it('.lten less than or equal', () => {
        assert.equal(new BN(3).lten(3), true);
        assert.equal(new BN(3).lten(2), false);
        assert.equal(new BN(3).lten(4), true);
      });

      it('.lte less than or equal', () => {
        assert.equal(new BN(3).lte(new BN(3)), true);
        assert.equal(new BN(3).lte(new BN(2)), false);
        assert.equal(new BN(3).lte(new BN(4)), true);
      });

      it('.eqn equal', () => {
        assert.equal(new BN(3).eqn(3), true);
        assert.equal(new BN(3).eqn(2), false);
        assert.equal(new BN(3).eqn(4), false);
      });

      it('.eq equal', () => {
        assert.equal(new BN(3).eq(new BN(3)), true);
        assert.equal(new BN(3).eq(new BN(2)), false);
        assert.equal(new BN(3).eq(new BN(4)), false);
      });
    });

    describe('.fromTwos', () => {
      it('should convert from two\'s complement to negative number', () => {
        assert.equal(new BN('00000000', 16).fromTwos(32).toNumber(), 0);
        assert.equal(new BN('00000001', 16).fromTwos(32).toNumber(), 1);
        assert.equal(new BN('7fffffff', 16).fromTwos(32).toNumber(), 2147483647);
        assert.equal(new BN('80000000', 16).fromTwos(32).toNumber(), -2147483648);
        assert.equal(new BN('f0000000', 16).fromTwos(32).toNumber(), -268435456);
        assert.equal(new BN('f1234567', 16).fromTwos(32).toNumber(), -249346713);
        assert.equal(new BN('ffffffff', 16).fromTwos(32).toNumber(), -1);
        assert.equal(new BN('fffffffe', 16).fromTwos(32).toNumber(), -2);
        assert.equal(new BN('fffffffffffffffffffffffffffffffe', 16)
          .fromTwos(128).toNumber(), -2);
        assert.equal(new BN('ffffffffffffffffffffffffffffffff' +
          'fffffffffffffffffffffffffffffffe', 16).fromTwos(256).toNumber(), -2);
        assert.equal(new BN('ffffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffff', 16).fromTwos(256).toNumber(), -1);
        assert.equal(new BN('7fffffffffffffffffffffffffffffff' +
          'ffffffffffffffffffffffffffffffff', 16).fromTwos(256).toString(10),
          new BN('5789604461865809771178549250434395392663499' +
            '2332820282019728792003956564819967', 10).toString(10));
        assert.equal(new BN('80000000000000000000000000000000' +
          '00000000000000000000000000000000', 16).fromTwos(256).toString(10),
          new BN('-578960446186580977117854925043439539266349' +
            '92332820282019728792003956564819968', 10).toString(10));
      });
    });

    describe('.toTwos', () => {
      it('should convert from negative number to two\'s complement', () => {
        assert.equal(new BN(0).toTwos(32).toString(16), '0');
        assert.equal(new BN(1).toTwos(32).toString(16), '1');
        assert.equal(new BN(2147483647).toTwos(32).toString(16), '7fffffff');
        assert.equal(new BN('-2147483648', 10).toTwos(32).toString(16), '80000000');
        assert.equal(new BN('-268435456', 10).toTwos(32).toString(16), 'f0000000');
        assert.equal(new BN('-249346713', 10).toTwos(32).toString(16), 'f1234567');
        assert.equal(new BN('-1', 10).toTwos(32).toString(16), 'ffffffff');
        assert.equal(new BN('-2', 10).toTwos(32).toString(16), 'fffffffe');
        assert.equal(new BN('-2', 10).toTwos(128).toString(16),
          'fffffffffffffffffffffffffffffffe');
        assert.equal(new BN('-2', 10).toTwos(256).toString(16),
          'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe');
        assert.equal(new BN('-1', 10).toTwos(256).toString(16),
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
        assert.equal(new BN('5789604461865809771178549250434395392663' +
          '4992332820282019728792003956564819967', 10).toTwos(256).toString(16),
          '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
        assert.equal(new BN('-578960446186580977117854925043439539266' +
          '34992332820282019728792003956564819968', 10).toTwos(256).toString(16),
          '8000000000000000000000000000000000000000000000000000000000000000');
      });
    });

    describe('.isBN', () => {
      it('should return true for BN', () => {
        assert.equal(BN.isBN(new BN()), true);
      });

      it('should return false for everything else', () => {
        assert.equal(BN.isBN(1), false);
        assert.equal(BN.isBN([]), false);
        assert.equal(BN.isBN({}), false);
      });
    });
  });

  describe('BN-NG', () => {
    const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

    for (const [x, y, z] of symbols) {
      it(`should compute jacobi symbol for: ${x}, ${y}`, () => {
        const xx = new BN(x);
        const yy = new BN(y);

        assert.strictEqual(xx.jacobi(yy), z);

        if (!xx.isNeg() && yy.abs().gtn(1)) {
          const xxx = xx.toRed(BN.red(yy.abs()));
          assert.strictEqual(xxx.redJacobi(), z);
        }
      });
    }

    it('should get random int', () => {
      const p = BN._prime('p192').p;

      let saw = false;

      for (let i = 0; i < 100; i++) {
        const r = BN.random(rng, 0, p);

        assert(!r.isNeg());
        assert(r.cmp(p) < 0);

        if (r.bitLength() > (p.bitLength() >>> 1))
          saw = true;
      }

      assert(saw);
    });

    it('should get random bits', () => {
      let saw = false;

      for (let i = 0; i < 100; i++) {
        const r = BN.randomBits(rng, 256);

        assert(!r.isNeg());
        assert(r.bitLength() <= 256);

        if (r.bitLength() > (256 >>> 1))
          saw = true;
      }

      assert(saw);
    });

    it('should toNumber and fromNumber', () => {
      assert.strictEqual(BN.fromNumber(1234567890).toNumber(), 1234567890);
      assert.strictEqual(BN.fromNumber(-1234567890).toNumber(), -1234567890);
      assert.strictEqual(BN.fromNumber(0x1234567890).toNumber(), 0x1234567890);
      assert.strictEqual(BN.fromNumber(-0x1234567890).toNumber(), -0x1234567890);

      assert.throws(() => BN.fromNumber(-MAX_SAFE_INTEGER - 1).toNumber());
      assert.throws(() => BN.fromNumber(MAX_SAFE_INTEGER + 1).toNumber());
      assert.doesNotThrow(() => BN.fromNumber(-MAX_SAFE_INTEGER).toNumber());
      assert.doesNotThrow(() => BN.fromNumber(MAX_SAFE_INTEGER).toNumber());
    });

    it('should toDouble and toDouble', () => {
      assert.strictEqual(BN.fromDouble(1234567890).toDouble(), 1234567890);
      assert.strictEqual(BN.fromDouble(-1234567890).toDouble(), -1234567890);
      assert.strictEqual(BN.fromDouble(0x1234567890).toDouble(), 0x1234567890);
      assert.strictEqual(BN.fromDouble(-0x1234567890).toDouble(), -0x1234567890);

      assert.doesNotThrow(() => BN.fromDouble(-MAX_SAFE_INTEGER - 1).toDouble());
      assert.doesNotThrow(() => BN.fromDouble(MAX_SAFE_INTEGER + 1).toDouble());
    });

    it('should toString and fromString', () => {
      assert.strictEqual(BN.fromString('1234567890', 10).toString(), '1234567890');
      assert.strictEqual(BN.fromString('-1234567890', 10).toString(), '-1234567890');
      assert.strictEqual(BN.fromString('1234567890', 16).toString(16), '1234567890');
      assert.strictEqual(BN.fromString('-1234567890', 16).toString(16), '-1234567890');

      assert.strictEqual(BN.fromString('abcdef1234', 16).toString(16), 'abcdef1234');
      assert.strictEqual(BN.fromString('-abcdef1234', 16).toString(16), '-abcdef1234');

      assert.strictEqual(BN.fromString('123456789', 10).toString(10, 2), '0123456789');
      assert.strictEqual(BN.fromString('-123456789', 10).toString(10, 2), '-0123456789');
      assert.strictEqual(BN.fromString('123456789', 16).toString(16, 2), '0123456789');
      assert.strictEqual(BN.fromString('-123456789', 16).toString(16, 2), '-0123456789');
    });

    it('should toJSON and fromJSON', () => {
      assert.strictEqual(BN.fromJSON('1234567890').toJSON(), '1234567890');
      assert.strictEqual(BN.fromJSON('-1234567890').toJSON(), '-1234567890');
      assert.strictEqual(BN.fromJSON('0123456789').toJSON(), '0123456789');
      assert.strictEqual(BN.fromJSON('-0123456789').toJSON(), '-0123456789');
    });

    it('should toBuffer and fromBuffer', () => {
      assert.strictEqual(BN.fromBuffer(new BN(0x1234567890).toBuffer()).toNumber(), 0x1234567890);
    });

    if (typeof BigInt === 'function') {
      it('should toBigInt and fromBigInt', () => {
        assert.strictEqual(new BN(0x1234567890).toBigInt(), BigInt(0x1234567890));
        assert.strictEqual(new BN(-0x1234567890).toBigInt(), BigInt(-0x1234567890));
        assert(BN.fromBigInt(BigInt(0x1234567890)).eq(new BN(0x1234567890)));
        assert(BN.fromBigInt(-BigInt(0x1234567890)).eq(new BN(-0x1234567890)));
      });
    }

    it('should count bits and zero bits', () => {
      assert.strictEqual(new BN(0x010001).zeroBits(), 0);
      assert.strictEqual(new BN(0x010001).bitLength(), 17);
      assert.strictEqual(new BN(-0x010001).zeroBits(), 0);
      assert.strictEqual(new BN(-0x010001).bitLength(), 17);
      assert.strictEqual(new BN(0x20000).zeroBits(), 17);
      assert.strictEqual(new BN(0x20000).bitLength(), 18);
      assert.strictEqual(new BN(-0x20000).zeroBits(), 17);
      assert.strictEqual(new BN(-0x20000).bitLength(), 18);
    });

    it('should compute sqrt', () => {
      assert.strictEqual(new BN(1024).sqrt().toNumber(), 32);
      assert.strictEqual(new BN(1025).sqrt().toNumber(), 32);
    });

    it('should compute division', () => {
      // Note: rounds towards zero, not negative infinity.
      assert.strictEqual(new BN(3).div(new BN(-2)).toNumber(), -1);
      assert.strictEqual(new BN(-3).div(new BN(2)).toNumber(), -1);
      assert.strictEqual(new BN(-3).div(new BN(-2)).toNumber(), 1);
      assert.strictEqual(new BN(4).div(new BN(-2)).toNumber(), -2);
      assert.strictEqual(new BN(-4).div(new BN(2)).toNumber(), -2);
      assert.strictEqual(new BN(-4).div(new BN(-2)).toNumber(), 2);
    });

    it('should compute division n', () => {
      // Note: rounds towards zero, not negative infinity.
      assert.strictEqual(new BN(3).divn(-2).toNumber(), -1);
      assert.strictEqual(new BN(-3).divn(2).toNumber(), -1);
      assert.strictEqual(new BN(-3).divn(-2).toNumber(), 1);
      assert.strictEqual(new BN(4).divn(-2).toNumber(), -2);
      assert.strictEqual(new BN(-4).divn(2).toNumber(), -2);
      assert.strictEqual(new BN(-4).divn(-2).toNumber(), 2);
    });

    it('should compute modulo', () => {
      assert.strictEqual(new BN(3).mod(new BN(-2)).toNumber(), 1);
      assert.strictEqual(new BN(-3).mod(new BN(2)).toNumber(), -1);
      assert.strictEqual(new BN(-3).mod(new BN(-2)).toNumber(), -1);
      assert.strictEqual(new BN(4).mod(new BN(-2)).toNumber(), 0);
      assert.strictEqual(new BN(-4).mod(new BN(2)).toNumber(), 0);
      assert.strictEqual(new BN(-4).mod(new BN(-2)).toNumber(), 0);
    });

    it('should compute modulo n', () => {
      assert.strictEqual(new BN(3).modrn(-2), 1);
      assert.strictEqual(new BN(-3).modrn(2), -1);
      assert.strictEqual(new BN(-3).modrn(-2), -1);
      assert.strictEqual(new BN(4).modrn(-2), 0);
      assert.strictEqual(new BN(-4).modrn(2), 0);
      assert.strictEqual(new BN(-4).modrn(-2), 0);
    });

    it('should compute unsigned modulo', () => {
      assert.strictEqual(new BN(3).umod(new BN(-2)).toNumber(), 1);
      assert.strictEqual(new BN(-3).umod(new BN(2)).toNumber(), 1);
      assert.strictEqual(new BN(-3).umod(new BN(-2)).toNumber(), 1);
      assert.strictEqual(new BN(4).umod(new BN(-2)).toNumber(), 0);
      assert.strictEqual(new BN(-4).umod(new BN(2)).toNumber(), 0);
      assert.strictEqual(new BN(-4).umod(new BN(-2)).toNumber(), 0);
    });

    it('should compute unsigned modulo n', () => {
      assert.strictEqual(new BN(3).umodrn(-2), 1);
      assert.strictEqual(new BN(-3).umodrn(2), 1);
      assert.strictEqual(new BN(-3).umodrn(-2), 1);
      assert.strictEqual(new BN(4).umodrn(-2), 0);
      assert.strictEqual(new BN(-4).umodrn(2), 0);
      assert.strictEqual(new BN(-4).umodrn(-2), 0);
    });

    it('should compute powm', () => {
      const x = new BN('49d695e8e09850acf3ced130d55cf4cc', 16);
      const y = new BN('1abc952', 16);
      const m = new BN('b06577896432d8cf7af1c491cad11be9b584316d0045187f40c8ae8d57724725', 16);
      const r = new BN('3f4cbb5b31c94b98dc5234de233af07319e93088192a9c87e3f0da9b213c779b', 16);

      assert.strictEqual(x.powm(y, m).toString(), r.toString());
      assert.strictEqual(
        x.toRed(BN.red(m)).redPow(y).fromRed().toString(),
        r.toString());
    });

    it('should compute inverse', () => {
      const p = BN._prime('p192').p;
      const r = BN.random(rng, 0, p);
      const rInv = r.invm(p);

      assert.strictEqual(r.mul(rInv).subn(1).umod(p).toString(), '0');
      assert.strictEqual(rInv.toString(), r.invm(p).toString());
    });

    it('should compute invmp', () => {
      if (!BN.prototype._invmp)
        this.skip();

      const p = BN._prime('p192').p;
      const r = BN.random(rng, 0, p);
      const rInv = r._invmp(p);

      assert.strictEqual(r.mul(rInv).subn(1).umod(p).toString(), '0');
      assert.strictEqual(rInv.toString(), r._invmp(p).toString());
    });

    it('should compute gcd and egcd', () => {
      const r1 = BN.randomBits(rng, 256);
      const r2 = BN.randomBits(rng, 256);
      const gcd_ = r1.gcd(r2);
      const [,, gcd] = r1.egcd(r2);

      assert.strictEqual(gcd_.toString(), gcd.toString());
    });

    it('should compute egcd', () => {
      const r1 = BN.randomBits(rng, 256);
      const r2 = BN.randomBits(rng, 256);
      const g = r1.gcd(r2);
      const [a1, b1, g1] = r1.egcd(r2);

      const r1d = r1.div(g1);
      const r2d = r2.div(g1);
      const [a2, b2, g2] = r1d.egcd(r2d);

      assert.strictEqual(g.toString(), g1.toString());
      assert.strictEqual(g1.toString(), r1.mul(a1).add(r2.mul(b1)).toString());
      assert.strictEqual(g2.toString(), '1');
      assert.strictEqual(r1d.mul(a2).add(r2d.mul(b2)).subn(1).toString(), '0');
    });

    it('should compute sqrt', () => {
      const r = BN.randomBits(rng, 256);
      const R = r.sqrt();

      assert(R.sqr().lte(r));
      assert(r.lt(R.addn(1).sqr()));

      const r2 = r.sqr();
      const R2 = r2.sqrt();

      assert(R2.eq(r));
    });

    it('should compute sqrtp', () => {
      const p = BN._prime('p192').p;
      const r = BN.random(rng, 0, p);
      const R = r.sqr().umod(p);
      const s = R.sqrtp(p);

      assert.strictEqual(s.sqr().umod(p).toString(), R.toString());
    });

    it('should compute sqrtpq', () => {
      const p = BN._prime('p192').p;
      const q = BN._prime('p224').p;
      const n = p.mul(q);
      const r = BN.random(rng, 0, n);
      const R = r.sqr().umod(n);
      const s = R.sqrtpq(p, q);

      assert.strictEqual(s.sqr().umod(n).toString(), R.toString());
    });

    it('should test perfect squares', () => {
      assert(new BN(0).isSquare());
      assert(new BN(1).isSquare());
      assert(!new BN(2).isSquare());
      assert(!new BN(3).isSquare());
      assert(new BN(4).isSquare());
      assert(!new BN(5).isSquare());
      assert(!new BN(6).isSquare());
      assert(!new BN(7).isSquare());
      assert(new BN(1024).isSquare());
      assert(!new BN(1025).isSquare());
    });

    it('should read and serialize aligned data', () => {
      const p = BN._prime('p192').p;
      const p1 = p.ushrn(8);
      const p7 = p.maskn(7 * 8);
      const be = Buffer.alloc(p.byteLength(), 0x00);
      const le = Buffer.alloc(p.byteLength(), 0x00);

      assert((be.byteOffset & 7) === 0);
      assert((be.byteLength & 7) === 0);
      assert((le.byteOffset & 7) === 0);
      assert((le.byteLength & 7) === 0);

      p.toBuffer('be').copy(be);
      p.toBuffer('le').copy(le);

      assert(BN.fromBuffer(be, 'be').eq(p));
      assert(BN.fromBuffer(le, 'le').eq(p));
      assert(BN.fromArrayLike(be, 'be').eq(p));
      assert(BN.fromArrayLike(le, 'le').eq(p));
      assert(new BN(be, 'be').eq(p));
      assert(new BN(le, 'le').eq(p));

      assert(BN.fromBuffer(be.slice(0, -1), 'be').eq(p1));
      assert(BN.fromBuffer(le.slice(1), 'le').eq(p1));
      assert(BN.fromArrayLike(be.slice(0, -1), 'be').eq(p1));
      assert(BN.fromArrayLike(le.slice(1), 'le').eq(p1));
      assert(new BN(be.slice(0, -1), 'be').eq(p1));
      assert(new BN(le.slice(1), 'le').eq(p1));

      assert(BN.fromBuffer(be.slice(-7), 'be').eq(p7));
      assert(BN.fromBuffer(le.slice(0, 7), 'le').eq(p7));
      assert(BN.fromArrayLike(be.slice(-7), 'be').eq(p7));
      assert(BN.fromArrayLike(le.slice(0, 7), 'le').eq(p7));
      assert(new BN(be.slice(-7), 'be').eq(p7));
      assert(new BN(le.slice(0, 7), 'le').eq(p7));

      const beu = new Uint8Array(be.buffer, be.byteOffset, be.length);
      const leu = new Uint8Array(le.buffer, le.byteOffset, le.length);
      const l = be.length;

      assert(BN.fromArrayLike(beu, 'be').eq(p));
      assert(BN.fromArrayLike(leu, 'le').eq(p));
      assert(new BN(beu, 'be').eq(p));
      assert(new BN(leu, 'le').eq(p));

      assert(BN.fromArrayLike(beu.subarray(0, l - 1), 'be').eq(p1));
      assert(BN.fromArrayLike(leu.subarray(1), 'le').eq(p1));
      assert(new BN(beu.subarray(0, l - 1), 'be').eq(p1));
      assert(new BN(leu.subarray(1), 'le').eq(p1));

      assert(BN.fromArrayLike(beu.subarray(l - 7), 'be').eq(p7));
      assert(BN.fromArrayLike(leu.subarray(0, 7), 'le').eq(p7));
      assert(new BN(beu.subarray(l - 7), 'be').eq(p7));
      assert(new BN(leu.subarray(0, 7), 'le').eq(p7));

      const bea = Array.from(be);
      const lea = Array.from(le);

      assert(BN.fromArrayLike(bea, 'be').eq(p));
      assert(BN.fromArrayLike(lea, 'le').eq(p));
      assert(new BN(bea, 'be').eq(p));
      assert(new BN(lea, 'le').eq(p));

      assert(BN.fromArrayLike(bea.slice(0, -1), 'be').eq(p1));
      assert(BN.fromArrayLike(lea.slice(1), 'le').eq(p1));
      assert(new BN(bea.slice(0, -1), 'be').eq(p1));
      assert(new BN(lea.slice(1), 'le').eq(p1));

      assert(BN.fromArrayLike(bea.slice(-7), 'be').eq(p7));
      assert(BN.fromArrayLike(lea.slice(0, 7), 'le').eq(p7));
      assert(new BN(bea.slice(-7), 'be').eq(p7));
      assert(new BN(lea.slice(0, 7), 'le').eq(p7));
    });

    it('should read and serialize unaligned data', () => {
      const p = BN._prime('p192').p;
      const p1 = p.ushrn(8);
      const p7 = p.maskn(7 * 8);
      const be = Buffer.alloc(1 + p.byteLength(), 0x00).slice(1);
      const le = Buffer.alloc(1 + p.byteLength(), 0x00).slice(1);

      assert((be.byteOffset & 7) !== 0);
      assert((be.byteLength & 7) === 0);
      assert((le.byteOffset & 7) !== 0);
      assert((le.byteLength & 7) === 0);

      p.toBuffer('be').copy(be);
      p.toBuffer('le').copy(le);

      assert(BN.fromBuffer(be, 'be').eq(p));
      assert(BN.fromBuffer(le, 'le').eq(p));
      assert(BN.fromArrayLike(be, 'be').eq(p));
      assert(BN.fromArrayLike(le, 'le').eq(p));
      assert(new BN(be, 'be').eq(p));
      assert(new BN(le, 'le').eq(p));

      assert(BN.fromBuffer(be.slice(0, -1), 'be').eq(p1));
      assert(BN.fromBuffer(le.slice(1), 'le').eq(p1));
      assert(BN.fromArrayLike(be.slice(0, -1), 'be').eq(p1));
      assert(BN.fromArrayLike(le.slice(1), 'le').eq(p1));
      assert(new BN(be.slice(0, -1), 'be').eq(p1));
      assert(new BN(le.slice(1), 'le').eq(p1));

      assert(BN.fromBuffer(be.slice(-7), 'be').eq(p7));
      assert(BN.fromBuffer(le.slice(0, 7), 'le').eq(p7));
      assert(BN.fromArrayLike(be.slice(-7), 'be').eq(p7));
      assert(BN.fromArrayLike(le.slice(0, 7), 'le').eq(p7));
      assert(new BN(be.slice(-7), 'be').eq(p7));
      assert(new BN(le.slice(0, 7), 'le').eq(p7));

      const beu = new Uint8Array(be.buffer, be.byteOffset, be.length);
      const leu = new Uint8Array(le.buffer, le.byteOffset, le.length);
      const l = be.length;

      assert(BN.fromArrayLike(beu, 'be').eq(p));
      assert(BN.fromArrayLike(leu, 'le').eq(p));
      assert(new BN(beu, 'be').eq(p));
      assert(new BN(leu, 'le').eq(p));

      assert(BN.fromArrayLike(beu.subarray(0, l - 1), 'be').eq(p1));
      assert(BN.fromArrayLike(leu.subarray(1), 'le').eq(p1));
      assert(new BN(beu.subarray(0, l - 1), 'be').eq(p1));
      assert(new BN(leu.subarray(1), 'le').eq(p1));

      assert(BN.fromArrayLike(beu.subarray(l - 7), 'be').eq(p7));
      assert(BN.fromArrayLike(leu.subarray(0, 7), 'le').eq(p7));
      assert(new BN(beu.subarray(l - 7), 'be').eq(p7));
      assert(new BN(leu.subarray(0, 7), 'le').eq(p7));

      const bea = Array.from(be);
      const lea = Array.from(le);

      assert(BN.fromArrayLike(bea, 'be').eq(p));
      assert(BN.fromArrayLike(lea, 'le').eq(p));
      assert(new BN(bea, 'be').eq(p));
      assert(new BN(lea, 'le').eq(p));

      assert(BN.fromArrayLike(bea.slice(0, -1), 'be').eq(p1));
      assert(BN.fromArrayLike(lea.slice(1), 'le').eq(p1));
      assert(new BN(bea.slice(0, -1), 'be').eq(p1));
      assert(new BN(lea.slice(1), 'le').eq(p1));

      assert(BN.fromArrayLike(bea.slice(-7), 'be').eq(p7));
      assert(BN.fromArrayLike(lea.slice(0, 7), 'le').eq(p7));
      assert(new BN(bea.slice(-7), 'be').eq(p7));
      assert(new BN(lea.slice(0, 7), 'le').eq(p7));
    });
  });

  describe('BN.js/Slow DH test', () => {
    for (const name of Object.keys(dhGroups)) {
      it('should match public key for ' + name + ' group', () => {
        const group = dhGroups[name];

        this.timeout(3600 * 1000);

        const base = new BN(2);
        const mont = BN.red(new BN(group.prime, 16));
        const priv = new BN(group.priv, 16);
        const multed = base.toRed(mont).redPow(priv).fromRed();
        const actual = multed.toBuffer();

        assert.equal(actual.toString('hex'), group.pub);
      });
    }
  });
});

import hashlib
import json
import os
import struct

import kawpow

from electrum import kawpow_full

from . import ElectrumTestCase


# Real Neurai mainnet headers (neurai-cli getblockheader <hash> false): height -> (block hash, raw header)
REAL_HEADERS = {
    # epoch 0, periods 0 and 2499
    1: ("b439bb2c2a24432bf236ea6bfd5dc0dba211ef0f45bea4268f5afc5913a568d9",
        "0000002006484804618cf622331522c2b49ca624047349025cbe19a00b0c3cd3440000009fe38b39de8d89902a1b074dd36c399028bab9a5d5eb4bb4ad04746f733b3f7ee9813d64ffff0021010000000000000000000000f15eaf262faab59587a9ffba657092f5947e4e11dabb64194e1753399e316b2c"),
    2: ("5090926760a583f3d336faac3e24d50331e06652963f0abe89a4b5c5b4d63fdb",
        "00000020d968a51359fc5a8f26a4be450fef11a2dbc05dfd6bea36f22b43242a2cbb39b40bddba2adf12e7dcd2d3322a44bec06d9434aff5c0ce1c5bc84d69dc42919a76ea813d64ffff002102000000000000000000000080cf261526b6a15fa7b8f97e283043f99c35a3a1d1c8bc66557aecb38e0a166e"),
    7499: ("000000009d2dacfd3bed48d8f942fdde0d17c299c2642bbc2885862b5fc7f0f2",
           "000000205f34dbe3f684f4dc392b12bde9fa2787dd49ea45b329e72acc75ebaa03000000ca1ed65a9600e6dcf70937e1829276133e7d03a7aa05f9445f86ae18f64bbd2adcc644641495061d4b1d00007970b222e7d49712af530bd4b734245a39705e177c0bb07f5ddb924b40cb36040687de7ebd4e1f47"),
    # epoch 1
    7500: ("000000053e4ed42eb9311deaac7617813b4bdb4d1865d48a8e9b4721fa6834a8",
           "00000020f2f0c75f2b868528bc2b64c299c2170ddefd42f9d848ed3bfdac2d9d000000005b524b02891eac223b94b82670f25fbfa61a8b91147dd4da0429a56ede60c6f4de664564fc7e061d4c1d00008cc0f70b00f8fcff9d8c9bfab6e716829812241178d250642a8a4d37e99c4b99e445f28701ddec62"),
    7501: ("000000106b2b3273dab8709e96431abb9ccc2b51f27dbb02a48fc5ec28b2bd67",
           "00000020a83468fa21479b8e8ad465184ddb4b3b811776acea1d31b92ed44e3e050000000a9283e5eddf8bb31208d00fb228050fc5d50bd68f9a5182ec80a897f3e91a71ed6645642de4131d4d1d00005fd4e60600f8fcff5e34badfc777687e120302d0b0f645d692ccbf6e1857201b44797473664e6205"),
    # epoch 249, above the last checkpoint (1870847) but for the first one
    1867500: ("00000000008716447dd7e73752c4bb5d74ea7b3c916beed17ed7d0912767829c",
              "000000307263661c8ba4bfef8ac518790bcd725d3bd599ff8d6c1adaa3d00a0000000000d170e4fc700379e98bc9c8af5dbcbabdc8d77d9bf310d12a9793a9bf6fcebefd1733f86a1098001cec7e1c00ebd58f6791b151888bd406c16bef4d7524770b9c65be85a6279d21f0273109b5024f5f6df7931ef1"),
    1871907: ("00000000001d23b08845d670331a5a5293b1715664886403b6091380256d32b3",
              "000000301a3a25a74dee492a44b518fa0b39dfd7eb4dab8be90acda7eb570300000000000765e1768e374392f909cad4af3275d96ecb5a272473230e207f90e535b281e3c74afc6ae887001c23901c002ccdd12900000016fe68e863e09e1ea9214d5f1b52775936154f96fa2b52cd80a616ecdd47a56998"),
}


def pow_inputs(raw_hex: str):
    """(nheight, header_hash, nonce, mix_hash) of a raw KAWPOW header, in the
    byte order of kawpow.light_verify(), as electrum.blockchain passes them."""
    raw = bytes.fromhex(raw_hex)
    header_hash = hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1]
    nheight, nonce = struct.unpack('<IQ', raw[76:88])
    return nheight, header_hash, nonce, raw[88:120][::-1]


class TestKawpowFull(ElectrumTestCase):

    def test_epoch_sizes(self):
        # Ethash sizes, as cpp-kawpow and the node compute them
        self.assertEqual(16776896 // 64, kawpow_full.light_cache_num_items(0))
        self.assertEqual(1073739904 // 128, kawpow_full.full_dataset_num_items(0))
        self.assertEqual(772091, kawpow_full.light_cache_num_items(249))
        self.assertEqual(bytes(32), kawpow_full.epoch_seed(0))
        self.assertEqual(kawpow.keccak_256(bytes(32)), kawpow_full.epoch_seed(1))

    def test_light_hash(self):
        # the Python Keccak-f[800] gives the final hash of the C light_verify
        for height, (block_hash, raw) in REAL_HEADERS.items():
            nheight, header_hash, nonce, mix_hash = pow_inputs(raw)
            self.assertEqual(height, nheight)
            final = kawpow.light_verify(header_hash, mix_hash, nonce)
            self.assertEqual(block_hash, final.hex())
            self.assertEqual(final, kawpow_full.light_hash(header_hash, nonce, mix_hash))

    def test_real_headers(self):
        with open(os.path.join(os.path.dirname(__file__), 'blockchain_mainnet_headers.json')) as f:
            data = json.load(f)
        headers = dict(REAL_HEADERS)
        for i in (181, 190):  # 1870848 and 1870857
            headers[data['first_height'] + i] = (None, data['headers'][i])
        # epochs 249 and 0 first, which other tests may have built already
        for height in sorted(headers, key=lambda h: (h // kawpow_full.EPOCH_LENGTH == 1, -h)):
            block_hash, raw = headers[height]
            with self.subTest(height=height):
                nheight, header_hash, nonce, mix_hash = pow_inputs(raw)
                final, mix = kawpow_full.progpow_hash(nheight, header_hash, nonce)
                self.assertEqual(mix_hash, mix)
                self.assertEqual(kawpow.light_verify(header_hash, mix_hash, nonce), final)
                if block_hash:
                    self.assertEqual(block_hash, final.hex())
                self.assertEqual((True, final), kawpow_full.verify(nheight, header_hash, nonce, mix_hash))
        self.assertLessEqual(len(kawpow_full._contexts), kawpow_full.MAX_EPOCHS_IN_MEMORY)

    def test_tampered_headers(self):
        nheight, header_hash, nonce, mix_hash = pow_inputs(REAL_HEADERS[7499][1])
        self.assertTrue(kawpow_full.verify(nheight, header_hash, nonce, mix_hash)[0])
        other_mix = bytes([mix_hash[0] ^ 1]) + mix_hash[1:]
        self.assertFalse(kawpow_full.verify(nheight, header_hash, nonce, other_mix)[0])
        self.assertFalse(kawpow_full.verify(nheight, header_hash, nonce + 1, mix_hash)[0])
        other_header_hash = header_hash[:31] + bytes([header_hash[31] ^ 0x80])
        self.assertFalse(kawpow_full.verify(nheight, other_header_hash, nonce, mix_hash)[0])
        # the program changes every 3 blocks, the DAG every 7500 blocks
        self.assertFalse(kawpow_full.verify(nheight - 3, header_hash, nonce, mix_hash)[0])
        self.assertFalse(kawpow_full.verify(nheight + 1, header_hash, nonce, mix_hash)[0])
        with self.assertRaises(ValueError):
            kawpow_full.verify((kawpow_full.MAX_EPOCH_NUMBER + 1) * kawpow_full.EPOCH_LENGTH,
                               header_hash, nonce, mix_hash)

    def test_ground_mix_hash_passes_light_check_only(self):
        # a server can grind mix_hash until the light check meets the target,
        # without any DAG work; here a target of 2**248 (~256 tries)
        nheight, header_hash, nonce, mix_hash = pow_inputs(REAL_HEADERS[2][1])
        target = 1 << 248
        for i in range(100000):
            forged_mix = hashlib.sha256(i.to_bytes(4, 'little')).digest()
            final = kawpow.light_verify(header_hash, forged_mix, nonce)
            if int.from_bytes(final, 'big') <= target:
                break
        else:
            self.fail('no mix_hash found')
        ok, recomputed_final = kawpow_full.verify(nheight, header_hash, nonce, forged_mix)
        self.assertFalse(ok)
        self.assertEqual(kawpow.light_verify(header_hash, mix_hash, nonce), recomputed_final)


class TestLightCacheFiles(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        kawpow_full.set_cache_dir(self.electrum_path)
        self.addCleanup(kawpow_full.set_cache_dir, None)

    def test_light_cache_is_kept_on_disk(self):
        num_items = 7  # tiny caches: same code path as a real epoch
        built = kawpow_full.build_light_cache(num_items, kawpow_full.epoch_seed(5))
        self.assertEqual(built, kawpow_full.get_light_cache(5, num_items))
        path = os.path.join(self.electrum_path, 'kawpow_light_cache_5')
        self.assertTrue(os.path.exists(path))
        self.assertEqual(built, kawpow_full._read_light_cache(5, num_items))
        # a damaged file is ignored, and replaced by a good one
        with open(path, 'r+b') as f:
            f.seek(40)
            f.write(b'\xff')
        self.assertIsNone(kawpow_full._read_light_cache(5, num_items))
        self.assertEqual(built, kawpow_full.get_light_cache(5, num_items))
        self.assertEqual(built, kawpow_full._read_light_cache(5, num_items))
        # a file of the wrong size too
        self.assertIsNone(kawpow_full._read_light_cache(5, num_items + 1))

    def test_only_the_last_two_epochs_are_kept(self):
        for epoch in (3, 4, 5, 6):
            kawpow_full.get_light_cache(epoch, 3)
        files = sorted(f for f in os.listdir(self.electrum_path) if f.startswith('kawpow_light_cache_'))
        self.assertEqual(['kawpow_light_cache_5', 'kawpow_light_cache_6'], files)

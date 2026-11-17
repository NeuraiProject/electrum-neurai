from electrum import bitcoin
from electrum.bitcoin import COIN
from electrum.coinchooser import CoinChooserBase, CoinChooserPrivacy
from electrum.transaction import PartialTxInput, PartialTxOutput, TxOutpoint
from electrum.util import NotEnoughFunds

from . import ElectrumTestCase


class TestCoinChooser(ElectrumTestCase):

    def test_bucket_candidates_with_empty_buckets(self):
        def sufficient_funds(buckets, *, bucket_value_sum):
            return True
        coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=False)
        self.assertEqual([[]], coin_chooser.bucket_candidates_any([], sufficient_funds))
        self.assertEqual([[]], coin_chooser.bucket_candidates_prefer_confirmed([], sufficient_funds))
        def sufficient_funds(buckets, *, bucket_value_sum):
            return False
        with self.assertRaises(NotEnoughFunds):
            coin_chooser.bucket_candidates_any([], sufficient_funds)
        with self.assertRaises(NotEnoughFunds):
            coin_chooser.bucket_candidates_prefer_confirmed([], sufficient_funds)

    def test_choose_buckets_is_abstract(self):
        coin_chooser = CoinChooserBase(enable_output_value_rounding=False)
        with self.assertRaises(NotImplementedError):
            coin_chooser.choose_buckets([], lambda *args, **kwargs: True, lambda buckets: None)


def _coin(n: int, value: int, *, asset: str = None) -> PartialTxInput:
    coin = PartialTxInput(prevout=TxOutpoint(txid=bytes([n]) * 32, out_idx=0))
    coin._trusted_address = bitcoin.hash160_to_p2pkh(bytes([n]) * 20)
    coin._trusted_value_sats = value  # for an asset coin: the asset amount
    coin._trusted_asset = asset
    coin.block_height = 100
    return coin


class TestCoinChooserAssets(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.base_coin = _coin(1, 10 * COIN)
        self.asset_coin = _coin(2, 50 * COIN, asset='CATS')
        self.dest = bitcoin.hash160_to_p2pkh(bytes([3]) * 20)
        self.change = bitcoin.hash160_to_p2pkh(bytes([4]) * 20)

    def test_bucket_value_is_the_coins_value(self):
        coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=False)
        buckets = coin_chooser.bucketize_coins(
            [self.base_coin, self.asset_coin], fee_estimator_vb=lambda size: 1000 * size)
        base_bucket, asset_bucket = sorted(buckets, key=lambda b: b.coins[0].prevout)
        # the fee of an input is accounted for by its effective value only
        self.assertEqual({None: 10 * COIN}, dict(base_bucket.value_))
        self.assertLess(base_bucket.effective_value[None], 10 * COIN)
        self.assertEqual({'CATS': 50 * COIN}, dict(asset_bucket.value_))
        self.assertLess(asset_bucket.effective_value[None], 0)

    def test_asset_transfer_with_constant_fee(self):
        # an absolute fee typed in the Qt confirmation dialog, or the zero fee it retries
        # with, is a constant fee: asset buckets must not be filtered out then
        outputs = [PartialTxOutput.from_address_and_value(self.dest, 20 * COIN, asset='CATS')]
        for fee in (100_000, 0):
            coin_chooser = CoinChooserPrivacy(enable_output_value_rounding=False)
            tx = coin_chooser.make_tx(
                coins=[self.base_coin, self.asset_coin], inputs=[], outputs=outputs,
                change_addrs=[self.change], restricted_change_address={},
                fee_estimator_vb=lambda size: fee, dust_threshold=546_000)
            self.assertIn(self.asset_coin.prevout, {txin.prevout for txin in tx.inputs()})
            # 20 CATS sent, 30 CATS of change
            self.assertEqual(50 * COIN, tx.output_value(asset_aware=True)['CATS'])
            self.assertEqual(fee, tx.get_fee())

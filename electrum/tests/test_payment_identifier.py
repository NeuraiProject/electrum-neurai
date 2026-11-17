from unittest import mock

from electrum import payment_identifier
from electrum.invoices import Invoice
from electrum.payment_identifier import PaymentIdentifier, PaymentIdentifierState
from electrum.util import InvoiceError

from . import ElectrumTestCase


BOLT11 = ('lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjyp'
          'eh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x8'
          '6fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w')
LNURL = ('LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZE'
         'PEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS')


class TestNoLightning(ElectrumTestCase):

    def test_invoice_from_bech32_raises_invoice_error(self):
        # used to raise NotImplementedError, which callers do not catch
        for text in (BOLT11, 'lnfoo', ''):
            with self.assertRaises(InvoiceError):
                Invoice.from_bech32(text)

    def test_typed_lightning_text_is_refused(self):
        # e.g. typing anything starting with "ln" in the 'Pay to' field used to crash
        for text in (BOLT11, 'ln', 'lnbc', 'LNBC1', 'not_implemented_lightning:' + BOLT11):
            with self.subTest(text=text[:20]):
                pi = PaymentIdentifier(None, text)
                self.assertFalse(pi.is_valid())
                self.assertEqual(PaymentIdentifierState.INVALID, pi._state)
                self.assertIn('Lightning', pi.get_error())
        # 'lightning:' is not a URI scheme this fork knows about
        pi = PaymentIdentifier(None, 'lightning:' + BOLT11)
        self.assertEqual(PaymentIdentifierState.INVALID, pi._state)

    def test_lnurl_is_refused_without_resolving(self):
        with mock.patch.object(payment_identifier, 'decode_lnurl', side_effect=AssertionError('decoded')):
            pi = PaymentIdentifier(None, LNURL)
        self.assertFalse(pi.need_resolve())  # would make an HTTP request
        self.assertEqual(PaymentIdentifierState.INVALID, pi._state)
        self.assertIn('Lightning', pi.get_error())

    async def test_email_like_is_not_looked_up_as_lightning_address(self):
        pi = PaymentIdentifier(None, 'satoshi@example.com')
        self.assertTrue(pi.need_resolve())  # openalias lookup
        async def no_openalias(self):
            return None
        with mock.patch.object(PaymentIdentifier, 'resolve_openalias', no_openalias), \
                mock.patch.object(payment_identifier, 'request_lnurl', side_effect=AssertionError('HTTP request')):
            await pi._do_resolve()
        self.assertEqual(PaymentIdentifierState.NOT_FOUND, pi._state)

    def test_neurai_uri_with_lightning_param_still_works(self):
        addr = 'NTiZdUy7x61yrovNK6aFx8SvPV1R4D7ReW'
        pi = PaymentIdentifier(None, f'neurai:{addr}?amount=1&lightning={BOLT11}')
        self.assertTrue(pi.is_valid())
        self.assertIsNone(pi.bolt11)
        self.assertEqual(addr, pi.bip21['address'])

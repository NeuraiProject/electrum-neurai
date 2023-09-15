import attr

from typing import Optional, List

from electrum.i18n import _
from electrum.json_db import StoredObject, stored_in

RESERVED_MESSAGE = _('Reserved For Atomic Swap')

@stored_in('atomic_swap')
@attr.s
class AtomicSwap(StoredObject):
    timestamp = attr.ib(type=int, validator=attr.validators.instance_of(int))
    is_mine = attr.ib(type=bool, validator=attr.validators.instance_of(bool))
    redeemed = attr.ib(type=bool, validator=attr.validators.instance_of(bool))
    in_assets = attr.ib(type=List[Optional[str]])
    in_amounts = attr.ib(type=List[int])
    out_assets = attr.ib(type=List[Optional[str]])
    out_amounts = attr.ib(type=List[int])
    swap_hex = attr.ib(type=str, validator=attr.validators.instance_of(str))

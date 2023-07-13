# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import json

from typing import NamedTuple, Union

from .util import inv_dict, all_subclasses
from . import neurai


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


GIT_REPO_URL = "https://github.com/NeuraiProject/electrum-neurai"
GIT_REPO_ISSUES_URL = "https://github.com/NeuraiProject/electrum-neurai/issues"
BIP39_WALLET_FORMATS = read_json('bip39_wallet_formats.json', [])


class BurnAmounts(NamedTuple):
    IssueAssetBurnAmount: Union[int, float]
    ReissueAssetBurnAmount: Union[int, float]
    IssueSubAssetBurnAmount: Union[int, float]
    IssueUniqueAssetBurnAmount: Union[int, float]
    IssueMsgChannelAssetBurnAmount: Union[int, float]
    IssueQualifierAssetBurnAmount: Union[int, float]
    IssueSubQualifierAssetBurnAmount: Union[int, float]
    IssueRestrictedAssetBurnAmount: Union[int, float]
    AddNullQualifierTagBurnAmount: Union[int, float]


class BurnAddresses(NamedTuple):
    IssueAssetBurnAddress: str
    ReissueAssetBurnAddress: str
    IssueSubAssetBurnAddress: str
    IssueUniqueAssetBurnAddress: str
    IssueMsgChannelAssetBurnAddress: str
    IssueQualifierAssetBurnAddress: str
    IssueSubQualifierAssetBurnAddress: str
    IssueRestrictedAssetBurnAddress: str
    AddNullQualifierTagBurnAddress: str
    GlobalBurnAddress: str

class AbstractNet:
    GENESIS = None
    CHECKPOINTS = None
    DGW_CHECKPOINTS = None
    DGW_CHECKPOINTS_SPACING = 0
    DGW_CHECKPOINTS_START = 0
    MATURE = 0

    NET_NAME: str
    TESTNET: bool
    WIF_PREFIX: int
    ADDRTYPE_P2PKH: int
    ADDRTYPE_P2SH: int
    SEGWIT_HRP: str
    BOLT11_HRP: str
    GENESIS: str
    BLOCK_HEIGHT_FIRST_LIGHTNING_CHANNELS: int = 0
    BIP44_COIN_TYPE: int
    LN_REALM_BYTE: int

    @classmethod
    def max_checkpoint(cls) -> int:
        return max(0, len(cls.DGW_CHECKPOINTS) * 2016 - 1)

    @classmethod
    def rev_genesis_bytes(cls) -> bytes:
        return bytes.fromhex(neurai.rev_hex(cls.GENESIS))


class NeuraiMainnet(AbstractNet):
    NET_NAME = "mainnet"
    TESTNET = False
    WIF_PREFIX = 128
    ADDRTYPE_P2PKH = 53
    ADDRTYPE_P2SH = 117
    ADDRTYPE_P2SH_ALT = 117
    MATURE = 60
    SEGWIT_HRP = ""
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806"
    DEFAULT_PORTS = {'t': '19011', 's': '19012'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = []
    DGW_CHECKPOINTS = read_json('checkpoints_dgw.json', [])
    DGW_CHECKPOINTS_SPACING = 2016
    DGW_CHECKPOINTS_START = 0

    XPRV_HEADERS = {
        'standard': 0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh': 0x0295b005,  # Yprv
        'p2wpkh': 0x04b2430c,  # zprv
        'p2wsh': 0x02aa7a99,  # Zprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard': 0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh': 0x0295b43f,  # Ypub
        'p2wpkh': 0x04b24746,  # zpub
        'p2wsh': 0x02aa7ed3,  # Zpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)
    BIP44_COIN_TYPE = 0

    BURN_AMOUNTS = BurnAmounts(
        IssueAssetBurnAmount=1000,
        ReissueAssetBurnAmount=200,
        IssueSubAssetBurnAmount=200,
        IssueUniqueAssetBurnAmount=10,
        IssueMsgChannelAssetBurnAmount=200,
        IssueQualifierAssetBurnAmount=2000,
        IssueSubQualifierAssetBurnAmount=200,
        IssueRestrictedAssetBurnAmount=3000,
        AddNullQualifierTagBurnAmount=0.2
    )

    BURN_ADDRESSES = BurnAddresses(
        IssueAssetBurnAddress='NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr',
        ReissueAssetBurnAddress='NXReissueAssetXXXXXXXXXXXXXXWLe4Ao',
        IssueSubAssetBurnAddress='NXissueSubAssetXXXXXXXXXXXXXX6B2JF',
        IssueUniqueAssetBurnAddress='NXissueUniqueAssetXXXXXXXXXXUBzP4Z',
        IssueMsgChannelAssetBurnAddress='NXissueMsgChanneLAssetXXXXXXTUzrtJ',
        IssueQualifierAssetBurnAddress='NXissueQuaLifierXXXXXXXXXXXXWurNcU',
        IssueSubQualifierAssetBurnAddress='NXissueSubQuaLifierXXXXXXXXXV71vM3',
        IssueRestrictedAssetBurnAddress='NXissueRestrictedXXXXXXXXXXXWpXx4H',
        AddNullQualifierTagBurnAddress='NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr',
        GlobalBurnAddress='NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr'
    )

class NeuraiTestnet(AbstractNet):
    NET_NAME = "testnet"
    BIP44_COIN_TYPE = 0
    LN_REALM_BYTE = 0
    LN_DNS_SEEDS = [
    ]
    TESTNET = True
    WIF_PREFIX = 239
    ADDRTYPE_P2PKH = 127
    ADDRTYPE_P2SH = 196
    ADDRTYPE_P2SH_ALT = 196
    MATURE = 60
    SEGWIT_HRP = ""
    BOLT11_HRP = SEGWIT_HRP
    GENESIS = "0000006af8b8297448605b0283473ec712f9768f81cc7eae6269b875dee3b0cf"
    DEFAULT_PORTS = {'t': '19111', 's': '19112'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = []
    DGW_CHECKPOINTS = read_json('checkpoints_dgw_testnet.json', [])
    DGW_CHECKPOINTS_SPACING = 2016
    DGW_CHECKPOINTS_START = 0

    XPRV_HEADERS = {
        'standard': 0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh': 0x024285b5,  # Uprv
        'p2wpkh': 0x045f18bc,  # vprv
        'p2wsh': 0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard': 0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh': 0x024289ef,  # Upub
        'p2wpkh': 0x045f1cf6,  # vpub
        'p2wsh': 0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = inv_dict(XPUB_HEADERS)

    BURN_AMOUNTS = BurnAmounts(
        IssueAssetBurnAmount=500,
        ReissueAssetBurnAmount=100,
        IssueSubAssetBurnAmount=100,
        IssueUniqueAssetBurnAmount=5,
        IssueMsgChannelAssetBurnAmount=100,
        IssueQualifierAssetBurnAmount=1000,
        IssueSubQualifierAssetBurnAmount=100,
        IssueRestrictedAssetBurnAmount=1500,
        AddNullQualifierTagBurnAmount=0.1
    )

    BURN_ADDRESSES = BurnAddresses(
        IssueAssetBurnAddress='tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy',
        ReissueAssetBurnAddress='tXReissueAssetXXXXXXXXXXXXXXYmsjpM',
        IssueSubAssetBurnAddress='tXissueSubAssetXXXXXXXXXXXXXW53F8Q',
        IssueUniqueAssetBurnAddress='tXissueUniqueAssetXXXXXXXXXXSChvqQ',
        IssueMsgChannelAssetBurnAddress='tXissueMsgChanneLAssetXXXXXXVFmW2d',
        IssueQualifierAssetBurnAddress='tXissueQuaLifierXXXXXXXXXXXXTfjTyH',
        IssueSubQualifierAssetBurnAddress='tXissueSubQuaLifierXXXXXXXXXYmbjCh',
        IssueRestrictedAssetBurnAddress='tXissueRestrictedXXXXXXXXXXXbvd3Ug',
        AddNullQualifierTagBurnAddress='tXaddTagBurnXXXXXXXXXXXXXXXXYXaTg1',
        GlobalBurnAddress='tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy'
    )


NETS_LIST = tuple(all_subclasses(AbstractNet))

# don't import net directly, import the module instead (so that net is singleton)
net = NeuraiMainnet


def set_mainnet():
    global net
    net = NeuraiMainnet


def set_testnet():
    global net
    net = NeuraiTestnet

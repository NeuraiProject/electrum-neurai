# Full KAWPOW verification in pure Python.
#
# kawpow.light_verify() only hashes the mix_hash a header carries, so it does
# not prove that the mix_hash comes from the DAG of the epoch. This module
# recomputes the ProgPoW 0.9.4 mix (Ravencoin/Neurai variant) from the epoch's
# light cache, like progpow::verify() of the node does. It is a port of
# lib/kawpow/progpow.cpp and lib/kawpow/kawpow.cpp of cpp-kawpow 0.9.4.4,
# using the keccak-512 of the kawpow package (C) for the light cache and the
# dataset items. The light cache of an epoch takes tens of MB (49 MB at epoch
# 249) and seconds to build, so only the last epochs used are kept.

import hashlib
import os
import struct
import threading
from collections import OrderedDict
from typing import Optional, Tuple

import kawpow


EPOCH_LENGTH = 7500
MAX_EPOCH_NUMBER = 896  # ETHASH_MAX_EPOCH_NUMBER of the node
PERIOD_LENGTH = 3
NUM_REGS = 32
NUM_LANES = 16
NUM_CACHE_ACCESSES = 11
NUM_MATH_OPERATIONS = 18
L1_CACHE_NUM_ITEMS = 16 * 1024 // 4
LIGHT_CACHE_INIT_SIZE = 1 << 24
LIGHT_CACHE_GROWTH = 1 << 17
LIGHT_CACHE_ROUNDS = 3
FULL_DATASET_INIT_SIZE = 1 << 30
FULL_DATASET_GROWTH = 1 << 23
FULL_DATASET_ITEM_PARENTS = 512
NUM_ROUNDS = 64

MAX_EPOCHS_IN_MEMORY = 2

_M32 = 0xffffffff
_M32_IN_64 = int.from_bytes(b'\xff\xff\xff\xff\x00\x00\x00\x00' * 8, 'little')
_FNV_PRIME = 0x01000193
_FNV_OFFSET_BASIS = 0x811c9dc5

_RAVENCOIN_KAWPOW = (0x72, 0x41, 0x56, 0x45, 0x4E, 0x43, 0x4F, 0x49,
                     0x4E, 0x4B, 0x41, 0x57, 0x50, 0x4F, 0x57)


def _make_keccak512():
    # call the C function directly when cffi accepts bytes, saving ~25% per call
    try:
        f, unpack = kawpow.lib.kawpow_keccak512, kawpow.ffi.unpack
        def keccak512(data: bytes) -> bytes:
            # keep the returned union alive while reading it: `.str` only
            # points into its memory, which another thread could reuse
            result = f(data, len(data))
            return unpack(result.str, 64)
        if keccak512(bytes(64)) == kawpow.keccak_512(bytes(64)):
            return keccak512
    except Exception:
        pass
    return kawpow.keccak_512


_keccak512 = _make_keccak512()


# Keccak-f[800], used by ProgPoW on its own 25 x 32-bit words state
_KECCAKF800_RC = (
    0x00000001, 0x00008082, 0x0000808A, 0x80008000, 0x0000808B, 0x80000001,
    0x80008081, 0x00008009, 0x0000008A, 0x00000088, 0x80008009, 0x8000000A,
    0x8000808B, 0x0000008B, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
    0x0000800A, 0x8000000A, 0x80008081, 0x00008080,
)
# rho offsets r[x][y] of Keccak-f[1600]; Keccak-f[800] takes them mod 32
_KECCAK_RHO = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
               (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
# rho and pi: B[y][2x+3y] = rot(A[x][y], r[x][y]); for each lane of B,
# (index of the lane of A, rotation), lane (x, y) being at index x + 5y
_KECCAKF800_RHO_PI = [None] * 25
for _x in range(5):
    for _y in range(5):
        _KECCAKF800_RHO_PI[_y + 5 * ((2 * _x + 3 * _y) % 5)] = (_x + 5 * _y, _KECCAK_RHO[_x][_y] % 32)
_KECCAKF800_RHO_PI = tuple(_KECCAKF800_RHO_PI)
del _x, _y


def keccak_f800(state: list) -> list:
    """Keccak-f[800] permutation (22 rounds) of 25 little-endian 32-bit words."""
    a = list(state)
    m = _M32
    rho_pi = _KECCAKF800_RHO_PI
    for rc in _KECCAKF800_RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 31)) & m) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        # rho and pi
        b = []
        for src, r in rho_pi:
            v = a[src]
            b.append(((v << r) | (v >> (32 - r))) & m if r else v)
        # chi
        a = [b[i] ^ (~b[5 * (i // 5) + (i + 1) % 5] & b[5 * (i // 5) + (i + 2) % 5]) for i in range(25)]
        # iota
        a[0] ^= rc
    return a


def _kiss99(z: int, w: int, jsr: int, jcong: int):
    """KISS99 generator; yields uint32 values forever."""
    m = _M32
    while True:
        z = 36969 * (z & 0xffff) + (z >> 16)
        w = 18000 * (w & 0xffff) + (w >> 16)
        jcong = (69069 * jcong + 1234567) & m
        jsr ^= (jsr << 17) & m
        jsr ^= jsr >> 13
        jsr ^= (jsr << 5) & m
        yield (((((z << 16) + w) & m) ^ jcong) + jsr) & m


def _fnv1a(u: int, v: int) -> int:
    return ((u ^ v) * _FNV_PRIME) & _M32


def _is_odd_prime(number: int) -> bool:
    d = 3
    while d * d <= number:
        if number % d == 0:
            return False
        d += 2
    return True


def _find_largest_prime(upper_bound: int) -> int:
    n = upper_bound
    if n < 2:
        return 0
    if n == 2:
        return 2
    if n % 2 == 0:
        n -= 1
    while not _is_odd_prime(n):
        n -= 2
    return n


def light_cache_num_items(epoch: int) -> int:
    return _find_largest_prime((LIGHT_CACHE_INIT_SIZE + epoch * LIGHT_CACHE_GROWTH) // 64)


def full_dataset_num_items(epoch: int) -> int:
    """Number of 1024-bit items of the full dataset (DAG)."""
    return _find_largest_prime((FULL_DATASET_INIT_SIZE + epoch * FULL_DATASET_GROWTH) // 128)


def epoch_seed(epoch: int) -> bytes:
    seed = bytes(32)
    for _ in range(epoch):
        seed = kawpow.keccak_256(seed)
    return seed


def build_light_cache(num_items: int, seed: bytes) -> bytearray:
    """The light cache: num_items 64-byte items of 16 little-endian words."""
    # built in place: a list of ints would be ~15% faster but take twice the memory
    keccak512 = _keccak512
    from_bytes = int.from_bytes
    unpack_from = struct.Struct('<I').unpack_from
    n = num_items
    cache = bytearray(n * 64)
    item = keccak512(seed)
    cache[0:64] = item
    for i in range(1, n):
        item = keccak512(item)
        cache[i << 6:(i + 1) << 6] = item
    for _ in range(LIGHT_CACHE_ROUNDS):
        prev = from_bytes(cache[(n - 1) << 6:], 'little')
        for o in range(0, n << 6, 64):
            # parents: the item indexed by the first word of this item, and the previous item
            v = (unpack_from(cache, o)[0] % n) << 6
            item = keccak512((from_bytes(cache[v:v + 64], 'little') ^ prev).to_bytes(64, 'little'))
            cache[o:o + 64] = item
            prev = from_bytes(item, 'little')
    return cache


def _dataset_item_512(cache: bytearray, n: int, index: int) -> bytes:
    """Item `index` of the full dataset as 512 bits, from the light cache
    `cache` of `n` items. The 16 words of the mix are kept as even words E and
    odd words O, each word in the low half of a 64-bit slot, so a whole fnv1()
    of the mix is a few operations on two Python ints."""
    from_bytes = int.from_bytes
    keccak512 = _keccak512
    P = _FNV_PRIME
    MK = _M32_IN_64
    M = _M32
    seed = index & M
    o = (index % n) << 6
    mix = from_bytes(keccak512((from_bytes(cache[o:o + 64], 'little') ^ seed).to_bytes(64, 'little')), 'little')
    E = mix & MK
    O = (mix >> 32) & MK
    for j in range(0, FULL_DATASET_ITEM_PARENTS, 2):
        # words j % 16 (even, in E) and j % 16 + 1 (odd, in O) are at the same shift
        sh = (j & 15) << 5
        o = (((((seed ^ j) * P) ^ (E >> sh)) & M) % n) << 6
        c = from_bytes(cache[o:o + 64], 'little')
        E = ((E * P) ^ c) & MK
        O = ((O * P) ^ (c >> 32)) & MK
        o = (((((seed ^ (j + 1)) * P) ^ (O >> sh)) & M) % n) << 6
        c = from_bytes(cache[o:o + 64], 'little')
        E = ((E * P) ^ c) & MK
        O = ((O * P) ^ (c >> 32)) & MK
    return keccak512((E | (O << 32)).to_bytes(64, 'little'))


def dataset_item_2048(cache: bytearray, n: int, index: int) -> bytes:
    """Item `index` of the full dataset as 2048 bits (256 bytes)."""
    i = index * 4
    return b''.join([_dataset_item_512(cache, n, i + k) for k in range(4)])


_cache_dir = None  # type: Optional[str]


def set_cache_dir(path: Optional[str]) -> None:
    """Keep the light caches built in `path`: an epoch lasts ~5 days of
    blocks, so restarts read it (~0.1 s) instead of building it (seconds)."""
    global _cache_dir
    _cache_dir = path


def _light_cache_file(epoch: int) -> str:
    return os.path.join(_cache_dir, f'kawpow_light_cache_{epoch}')


def _read_light_cache(epoch: int, num_items: int) -> Optional[bytearray]:
    """The cache file holds the sha256 of the cache, then the cache."""
    try:
        with open(_light_cache_file(epoch), 'rb') as f:
            digest = f.read(32)
            cache = bytearray(num_items * 64)
            if f.readinto(cache) != len(cache) or f.read(1):
                return None
    except OSError:
        return None
    return cache if hashlib.sha256(cache).digest() == digest else None


def _write_light_cache(epoch: int, cache: bytearray) -> None:
    path = _light_cache_file(epoch)
    try:
        with open(path + '.tmp', 'wb') as f:
            f.write(hashlib.sha256(cache).digest())
            f.write(cache)
        os.replace(path + '.tmp', path)
        # keep this epoch's file and the previous one's
        for name in os.listdir(_cache_dir):
            prefix = 'kawpow_light_cache_'
            if name.startswith(prefix) and name[len(prefix):].isdigit() and int(name[len(prefix):]) < epoch - 1:
                os.remove(os.path.join(_cache_dir, name))
    except OSError:
        pass  # only a speed-up


def get_light_cache(epoch: int, num_items: int) -> bytearray:
    if _cache_dir:
        cache = _read_light_cache(epoch, num_items)
        if cache is not None:
            return cache
    cache = build_light_cache(num_items, epoch_seed(epoch))
    if _cache_dir:
        _write_light_cache(epoch, cache)
    return cache


class EpochContext:

    def __init__(self, epoch: int):
        if not 0 <= epoch <= MAX_EPOCH_NUMBER:
            raise ValueError(f'invalid epoch {epoch}')
        self.epoch = epoch
        self.light_num_items = light_cache_num_items(epoch)
        self.full_num_items = full_dataset_num_items(epoch)
        self.light_cache = get_light_cache(epoch, self.light_num_items)
        # the first 16 KiB of the full dataset
        l1 = b''.join([self.dataset_item_2048(i) for i in range(L1_CACHE_NUM_ITEMS * 4 // 256)])
        self.l1_cache = struct.unpack(f'<{L1_CACHE_NUM_ITEMS}I', l1)

    def dataset_item_2048(self, index: int) -> bytes:
        return dataset_item_2048(self.light_cache, self.light_num_items, index)


_contexts = OrderedDict()  # type: OrderedDict[int, EpochContext]
_contexts_lock = threading.Lock()


def get_epoch_context(epoch: int) -> EpochContext:
    """The context of `epoch`, built on first use (seconds) and kept with
    those of the last MAX_EPOCHS_IN_MEMORY - 1 other epochs used."""
    with _contexts_lock:
        ctx = _contexts.get(epoch)
        if ctx is None:
            ctx = EpochContext(epoch)
            _contexts[epoch] = ctx
            while len(_contexts) > MAX_EPOCHS_IN_MEMORY:
                _contexts.popitem(last=False)
        else:
            _contexts.move_to_end(epoch)
        return ctx


# random_math(a, b, selector % 11), with a and b uint32
def _rotl32(n: int, c: int) -> int:
    c &= 31
    return ((n << c) | (n >> (32 - c))) & _M32


def _rotr32(n: int, c: int) -> int:
    c &= 31
    return ((n >> c) | (n << (32 - c))) & _M32


def _clz32(x: int) -> int:
    return 32 - x.bit_length()


def _popcount32(x: int) -> int:
    return bin(x).count('1')


_RANDOM_MATH = (
    lambda a, b: (a + b) & _M32,
    lambda a, b: (a * b) & _M32,
    lambda a, b: (a * b) >> 32,
    lambda a, b: a if a < b else b,
    _rotl32,
    _rotr32,
    lambda a, b: a & b,
    lambda a, b: a | b,
    lambda a, b: a ^ b,
    lambda a, b: _clz32(a) + _clz32(b),
    lambda a, b: _popcount32(a) + _popcount32(b),
)


def _random_merge(a: int, b: int, selector: int) -> int:
    x = (selector >> 16) % 31 + 1
    s = selector % 4
    if s == 0:
        return (a * 33 + b) & _M32
    if s == 1:
        return ((a ^ b) * 33) & _M32
    if s == 2:
        return (((a << x) | (a >> (32 - x))) & _M32) ^ b
    return (((a >> x) | (a << (32 - x))) & _M32) ^ b


class _Program:
    """The random program of a ProgPoW period, the same for its 64 rounds
    (round() of progpow.cpp takes mix_rng_state by value)."""

    def __init__(self, period: int):
        rng = _kiss99(*self._rng_init(period & _M32, (period >> 32) & _M32))
        dst_seq = list(range(NUM_REGS))
        src_seq = list(range(NUM_REGS))
        for i in range(NUM_REGS, 1, -1):
            j = next(rng) % i
            dst_seq[i - 1], dst_seq[j] = dst_seq[j], dst_seq[i - 1]
            j = next(rng) % i
            src_seq[i - 1], src_seq[j] = src_seq[j], src_seq[i - 1]
        dst_counter = 0
        src_counter = 0

        def next_dst():
            nonlocal dst_counter
            dst_counter += 1
            return dst_seq[(dst_counter - 1) % NUM_REGS]

        def next_src():
            nonlocal src_counter
            src_counter += 1
            return src_seq[(src_counter - 1) % NUM_REGS]

        # (False, src, dst, merge selector): merge l1_cache[mix[src] % size] into mix[dst]
        # (True, src1, src2, math fn, dst, merge selector): merge math(mix[src1], mix[src2]) into mix[dst]
        ops = []
        for i in range(max(NUM_CACHE_ACCESSES, NUM_MATH_OPERATIONS)):
            if i < NUM_CACHE_ACCESSES:
                src = next_src()
                dst = next_dst()
                sel = next(rng)
                ops.append((False, src, dst, sel))
            if i < NUM_MATH_OPERATIONS:
                src_rnd = next(rng) % (NUM_REGS * (NUM_REGS - 1))
                src1 = src_rnd % NUM_REGS
                src2 = src_rnd // NUM_REGS
                if src2 >= src1:
                    src2 += 1
                sel1 = next(rng)
                dst = next_dst()
                sel2 = next(rng)
                ops.append((True, src1, src2, _RANDOM_MATH[sel1 % 11], dst, sel2))
        self.ops = tuple(ops)
        dag = []
        for i in range(4):  # words of the DAG item per lane
            dst = 0 if i == 0 else next_dst()
            dag.append((dst, next(rng)))
        self.dag = tuple(dag)

    @staticmethod
    def _rng_init(seed_lo: int, seed_hi: int):
        z = _fnv1a(_FNV_OFFSET_BASIS, seed_lo)
        w = _fnv1a(z, seed_hi)
        jsr = _fnv1a(w, seed_lo)
        jcong = _fnv1a(jsr, seed_hi)
        return z, w, jsr, jcong


_programs = OrderedDict()  # type: OrderedDict[int, _Program]
_programs_lock = threading.Lock()


def _get_program(period: int) -> _Program:
    with _programs_lock:
        prog = _programs.get(period)
        if prog is None:
            prog = _programs[period] = _Program(period)
            while len(_programs) > 16:
                _programs.popitem(last=False)
        return prog


def _init_mix(seed_lo: int, seed_hi: int) -> list:
    z = _fnv1a(_FNV_OFFSET_BASIS, seed_lo)
    w = _fnv1a(z, seed_hi)
    mix = []
    for lane in range(NUM_LANES):
        jsr = _fnv1a(w, lane)
        jcong = _fnv1a(jsr, lane)
        rng = _kiss99(z, w, jsr, jcong)
        mix.append([next(rng) for _ in range(NUM_REGS)])
    return mix


def _hash_mix(ctx: EpochContext, block_number: int, seed_lo: int, seed_hi: int) -> bytes:
    mix = _init_mix(seed_lo, seed_hi)
    prog = _get_program(block_number // PERIOD_LENGTH)
    num_items = ctx.full_num_items // 2
    l1 = ctx.l1_cache
    merge = _random_merge
    for r in range(NUM_ROUNDS):
        item = struct.unpack('<64I', ctx.dataset_item_2048(mix[r % NUM_LANES][0] % num_items))
        for op in prog.ops:
            if op[0]:
                _, src1, src2, math, dst, sel = op
                for lane in mix:
                    lane[dst] = merge(lane[dst], math(lane[src1], lane[src2]), sel)
            else:
                _, src, dst, sel = op
                for lane in mix:
                    lane[dst] = merge(lane[dst], l1[lane[src] % L1_CACHE_NUM_ITEMS], sel)
        for l, lane in enumerate(mix):
            offset = ((l ^ r) % NUM_LANES) * 4
            for i, (dst, sel) in enumerate(prog.dag):
                lane[dst] = merge(lane[dst], item[offset + i], sel)
    # reduce the mix to 256 bits
    lane_hashes = []
    for lane in mix:
        h = _FNV_OFFSET_BASIS
        for v in lane:
            h = _fnv1a(h, v)
        lane_hashes.append(h)
    words = [_FNV_OFFSET_BASIS] * 8
    for l, h in enumerate(lane_hashes):
        words[l % 8] = _fnv1a(words[l % 8], h)
    return struct.pack('<8I', *words)


def _seed_state(header_hash: bytes, nonce: int) -> list:
    """First Keccak-f[800] of ProgPoW; its first 8 words."""
    state = list(struct.unpack('<8I', header_hash)) + [nonce & _M32, nonce >> 32] + list(_RAVENCOIN_KAWPOW)
    return keccak_f800(state)[:8]


def _final_hash(state2: list, mix_hash: bytes) -> bytes:
    state = state2 + list(struct.unpack('<8I', mix_hash)) + list(_RAVENCOIN_KAWPOW[:9])
    return struct.pack('<8I', *keccak_f800(state)[:8])


def light_hash(header_hash: bytes, nonce: int, mix_hash: bytes) -> bytes:
    """Final hash from the mix_hash of the header, as kawpow.light_verify()."""
    return _final_hash(_seed_state(header_hash, nonce), mix_hash)


def progpow_hash(block_number: int, header_hash: bytes, nonce: int) -> Tuple[bytes, bytes]:
    """progpow::hash(): returns (final_hash, mix_hash) of a header. Hashes are
    the bytes of cpp-kawpow hash256, as kawpow.light_verify() takes and returns
    them: header_hash is the sha256d of the 80-byte header reversed, mix_hash
    the one of the header reversed, and final_hash the block hash (hex order)."""
    if len(header_hash) != 32:
        raise ValueError('header_hash must have length of 32')
    if not 0 <= nonce < 1 << 64:
        raise ValueError('nonce must be uint64')
    ctx = get_epoch_context(block_number // EPOCH_LENGTH)
    state2 = _seed_state(header_hash, nonce)
    mix_hash = _hash_mix(ctx, block_number, state2[0], state2[1])
    return _final_hash(state2, mix_hash), mix_hash


def verify(block_number: int, header_hash: bytes, nonce: int, mix_hash: bytes) -> Tuple[bool, bytes]:
    """Whether mix_hash is the ProgPoW mix of the header, and the final hash
    computed from the recomputed mix."""
    final_hash, expected_mix_hash = progpow_hash(block_number, header_hash, nonce)
    return expected_mix_hash == mix_hash, final_hash

import os

from electrum import util
from electrum.ipfs_db import IPFSDB

from . import ElectrumTestCase


def registered_handlers(db: IPFSDB) -> int:
    """How many of db's event handlers are registered with the callback manager."""
    n = 0
    with util.callback_mgr.callback_lock:
        for callbacks in util.callback_mgr.callbacks.values():
            n += sum(1 for cb in callbacks if getattr(cb, '__self__', None) is db)
    return n


class TestIPFSDBSingleton(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self._prev_instance = IPFSDB._instance
        self.addCleanup(self._restore_instance)

    def _restore_instance(self):
        inst = IPFSDB._instance
        if inst is not None and inst is not self._prev_instance:
            inst.unregister_callbacks()
        IPFSDB._instance = self._prev_instance
        if self._prev_instance is not None:
            self._prev_instance.register_callbacks()

    def paths(self, name):
        return os.path.join(self.electrum_path, name + '.json'), os.path.join(self.electrum_path, name + '_raw')

    def test_initialize_reuses_the_instance(self):
        # used to check hasattr(cls, 'instance') instead of '_instance': every call built
        # (and __init__-ed twice) a new instance, registering its event callbacks twice
        IPFSDB.initialize(*self.paths('a'))
        db = IPFSDB.get_instance()
        n_handlers = len(list(db._list_callbacks()))
        self.assertTrue(n_handlers)
        self.assertEqual(n_handlers, registered_handlers(db))
        IPFSDB.initialize(*self.paths('a'))
        self.assertIs(db, IPFSDB.get_instance())
        self.assertIs(db, IPFSDB(*self.paths('a')))
        self.assertEqual(n_handlers, registered_handlers(db))

    def test_initialize_with_other_files_replaces_the_instance(self):
        IPFSDB.initialize(*self.paths('a'))
        db_a = IPFSDB.get_instance()
        IPFSDB.initialize(*self.paths('b'))
        db_b = IPFSDB.get_instance()
        self.assertIsNot(db_a, db_b)
        self.assertEqual(os.path.realpath(self.paths('b')[0]), os.path.realpath(db_b.path))
        self.assertEqual(0, registered_handlers(db_a))
        self.assertEqual(len(list(db_b._list_callbacks())), registered_handlers(db_b))

    def test_failed_init_keeps_previous_instance(self):
        IPFSDB.initialize(*self.paths('a'))
        db_a = IPFSDB.get_instance()
        not_a_dir = os.path.join(self.electrum_path, 'file')
        with open(not_a_dir, 'w') as f:
            f.write('x')
        with self.assertRaises(Exception):
            IPFSDB.initialize(os.path.join(not_a_dir, 'db.json'), os.path.join(not_a_dir, 'raw'))
        self.assertIs(db_a, IPFSDB.get_instance())

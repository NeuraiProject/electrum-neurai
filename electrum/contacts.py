# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2015 Thomas Voegtlin
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
import re
from typing import Optional, Tuple

import dns
import threading
from dns.exception import DNSException

from . import neurai
from . import dnssec
from .util import read_json_file, write_json_file, to_string
from .logging import Logger
from .util import trigger_callback

class Contacts(dict, Logger):

    def __init__(self, db):
        Logger.__init__(self)
        self.db = db
        d = self.db.get('contacts', {})
        try:
            self.update(d)
        except:
            return
        # backward compatibility
        for k, v in self.items():
            _type, n = v
            if _type == 'address' and neurai.is_address(n):
                self.pop(k)
                self[n] = ('address', k)

    def save(self):
        self.db.put('contacts', dict(self))

    def import_file(self, path):
        data = read_json_file(path)
        data = self._validate(data)
        self.update(data)
        self.save()

    def export_file(self, path):
        write_json_file(path, self)

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.save()

    def pop(self, key):
        if key in self.keys():
            res = dict.pop(self, key)
            self.save()
            return res

    def resolve(self, k):
        if neurai.is_address(k):
            return {
                'address': k,
                'type': 'address'
            }
        if k in self.keys():
            _type, addr = self[k]
            if _type == 'address':
                return {
                    'address': addr,
                    'type': 'contact'
                }
        out = self.resolve_openalias(k)
        if out:
            address, name, validated = out
            return {
                'address': address,
                'name': name,
                'type': 'openalias',
                'validated': validated
            }
        raise Exception("Invalid neurai address or alias", k)

    def fetch_openalias(self, config):
        self.alias_info = None
        alias = config.get('alias')
        if alias:
            alias = str(alias)
            def f():
                self.alias_info = self.resolve_openalias(alias)
                trigger_callback('alias_received')
            t = threading.Thread(target=f)
            t.daemon = True
            t.start()

    def resolve_openalias(self, url: str) -> Optional[Tuple[str, str, bool]]:
        # support email-style addresses, per the OA standard
        url = url.replace('@', '.')
        try:
            records, validated = dnssec.query(url, dns.rdatatype.TXT)
        except DNSException as e:
            self.logger.info(f'Error resolving openalias: {repr(e)}')
            return None
        prefix = 'xna'
        for record in records:
            string = to_string(record.strings[0], 'utf8')
            if string.startswith('oa1:' + prefix):
                address = self.find_regex(string, r'recipient_address=([A-Za-z0-9]+)')
                name = self.find_regex(string, r'recipient_name=([^;]+)')
                if not name:
                    name = address
                if not address:
                    continue
                return address, name, validated

    def find_regex(self, haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None
            
    def _validate(self, data):
        for k, v in list(data.items()):
            if k == 'contacts':
                return self._validate(v)
            if not neurai.is_address(k):
                data.pop(k)
            else:
                _type, _ = v
                if _type != 'address':
                    data.pop(k)
        return data


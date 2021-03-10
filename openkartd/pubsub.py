# Copyright 2021, Sam Edwards <CFSworks@gmail.com>
# SPDX-License-Identifier: BSD-3-Clause

# Sentinel value
MISSING = object()

class DeltaScanner:
    """Utility class for monitoring some mutable object and periodically
    generating JSON-delta "diff stanzas" for changes to the object.
    """

    def __init__(self, root):
        self.root = root

        self.__obj2refs = {}
        self.__obj2stanzas = None

        for _ in self.scan(): pass # Get synced up

    def __scan_object(self, obj):
        if id(obj) in self.__obj2stanzas:
            yield from self.__obj2stanzas[id(obj)]
            return

        stanzas = self.__obj2stanzas.setdefault(id(obj), [])

        refs = self.__obj2refs.get(id(obj), MISSING)
        if refs is MISSING:
            # Have to describe this fresh
            stanza = (), obj
            yield stanza
            stanzas.append(stanza)

            # Scan everything already in it
            if isinstance(obj, list):
                subobjs = obj
            elif isinstance(obj, dict):
                subobjs = obj.values()
            else:
                subobjs = ()

            for x in subobjs:
                for _ in self.__scan_object(x):
                    pass

        elif refs is None:
            # Opaque, non-delta type; don't scan
            pass

        elif isinstance(refs, dict):
            assert isinstance(obj, dict)

            # First the delete stanzas
            for k in refs.keys():
                if k not in obj:
                    stanza = (k,),
                    yield stanza
                    stanzas.append(stanza)

            # Now scan everything not deleted
            for k in obj.keys():
                for stanza in self.__scan_object(obj[k]):
                    stanza = ((k,) + stanza[0],) + stanza[1:]
                    yield stanza
                    stanzas.append(stanza)

        elif isinstance(refs, list):
            assert isinstance(obj, list)

            ids = [id(x) for x in obj]

            # Determine common subsequence of (refs, ids)
            def is_subseq(x, y):
                it = iter(y)
                return all(c in it for c in x)
            if ids == refs:
                subseq = ids
            elif is_subseq(ids, refs):
                subseq = ids
            elif is_subseq(refs, ids):
                subseq = list(refs)
            else:
                subseq = [] # FIXME: A more advanced algorithm is needed here
                for x,y in zip(refs, ids):
                    if x == y:
                        subseq.append(x)
                    else:
                        break
                i = len(subseq)
                for x,y in reversed(list(zip(refs, ids))):
                    if x == y:
                        subseq.insert(i, x)
                    else:
                        break
            assert is_subseq(subseq, ids) and is_subseq(subseq, refs)

            # Delete the objects not in the subsequence
            deleted_indexes = []
            for i,x in enumerate(subseq + [None]):
                assert refs[:i] == subseq[:i]

                while len(refs) > i and refs[i] != x:
                    del refs[i]
                    deleted_indexes.append(i + len(deleted_indexes))

            assert refs == subseq

            # Now add/visit everything else
            change_stanzas = []
            for i,x in enumerate(obj):
                if refs and refs[0] == id(x):
                    # This appears in 'refs'; visit
                    refs.pop(0)

                    for stanza in self.__scan_object(x):
                        assert stanza[0]

                        stanza = ((i,) + stanza[0],) + stanza[1:]
                        change_stanzas.append(stanza)

                else:
                    # This is not refs[0], so add a new object
                    for _ in self.__scan_object(x): pass # Make sure we know about it

                    is_insert = bool(refs)

                    if i in deleted_indexes:
                        # No need to delete-and-reinsert; just replace
                        deleted_indexes.remove(i)
                        is_insert = False

                    stanza = (i,), x
                    if is_insert: stanza += ('i',)
                    change_stanzas.append(stanza)

            # We should have handled all pending visits
            assert not refs

            for i in reversed(deleted_indexes):
                stanza = (i,),
                yield stanza
                stanzas.append(stanza)

            yield from change_stanzas
            stanzas.extend(change_stanzas)

        else:
            assert False # This is supposed to be unreachable

        # Now update obj2refs

        if isinstance(obj, dict):
            refs = {k:id(v) for k,v in obj.items()}
        elif isinstance(obj, list):
            refs = [id(x) for x in obj]
        else:
            refs = None

        self.__obj2refs[id(obj)] = refs

    def scan(self):
        """Generator that yields a sequence of diff stanzas.

        This is not thread-safe; only one thread may call this at a time,
        and the root object shall not be modified until the generator finishes.

        This also updates the internal representation of the root object's
        state, so that the next call to scan() will not have the same changes
        included.
        """

        assert self.__obj2stanzas is None
        self.__obj2stanzas = {}

        try:
            yield from self.__scan_object(self.root)

            # Clean up self.__obj2refs
            discard = set(self.__obj2refs.keys()) - set(self.__obj2stanzas.keys())
            for x in discard:
                del self.__obj2refs[x]

        finally:
            self.__obj2stanzas = None


def test_delta():
    import copy

    d = {}
    scanner = DeltaScanner(d)
    assert list(scanner.scan()) == []

    def patch(root, stanzas):
        for stanza in stanzas:
            x = root
            path = list(stanza[0])
            k = path.pop(0)
            for node in path:
                x = x[k]
                k = node

            if len(stanza) == 1:
                del x[k]
                continue

            v = copy.deepcopy(stanza[1])

            if len(stanza)==3:
                assert stanza[2] == 'i'
                x.insert(k, v)
            elif isinstance(x, list) and k == len(x):
                x.append(v)
            else:
                x[k] = v

    def sequence():
        d['x'] = 2
        yield 1

        del d['x']
        yield 1

        d['x'] = d['y'] = []
        yield 2

        d['x'].append(4)
        yield 2

        d['x'].insert(0, 'test')
        yield 2

        d['x'][1] = 3
        del d['y']
        yield 2

        d['x'].append(d['x'].pop(0))
        yield 2

        d['x'].insert(0, 0)
        d['x'].insert(0, 1)
        d['x'].insert(0, 2)
        d['x'].append(3)
        d['x'].append(4)
        d['x'].append(5)
        yield 6

        d['x'][4] = 'test2'
        yield 1

        d['a'] = {'x': '1', 'y': '2'}
        yield 1

    d2 = {}
    for expected_stanzas in sequence():
        stanzas = list(scanner.scan())
        if expected_stanzas is not None:
            assert len(stanzas) == expected_stanzas
        patch(d2, stanzas)
        assert d == d2
        assert list(scanner.scan()) == []


class PubSub:
    class Topic:
        def __init__(self, root: object):
            self.root = root
            self.scanner = DeltaScanner(root)

            self.__entered = False

            self._subscribers = []

        def __enter__(self):
            assert not self.__entered
            self.__entered = True

            return self.root

        def __exit__(self, type, value, traceback):
            assert self.__entered
            self.__entered = False

            self.__update()

        def __update(self):
            stanzas = list(self.scanner.scan())
            if not stanzas: return

            self.publish('update', {'diff': stanzas})

        def publish(self, msg: str, data: dict = {}):
            for sub, s in self._subscribers:
                d = {'s': s, 'msg': msg}
                d.update(data)
                sub.receive(d)

        def publish_bytes(self, data: bytes):
            for sub, s in self._subscribers:
                sub.receive(chr(s).encode() + data)

        def _close(self):
            self.publish('close')
            del self._subscribers[:]

    def __init__(self):
        self._topics = {}

    def create_topic(self, key: str, root_obj = MISSING):
        if key in self._topics:
            raise KeyError(f'topic {key!r} already exists')

        if root_obj is MISSING:
            root_obj = {}

        topic = self._topics[key] = self.Topic(root_obj)
        return topic

    def topic(self, key: str):
        try:
            return self._topics[key]
        except KeyError as e:
            raise KeyError(f'invalid topic {key!r}') from e

    def close_topic(self, key: str):
        self.topic(key)._close()
        del self._topics[key]


class Subscriber:
    def __init__(self, ps: PubSub):
        self.ps = ps

        self._topics = set()
        self._s = []

    def __allocate_subscription(self):
        try:
            return self._s.index(None)
        except ValueError:
            self._s.append(None)
            return len(self._s)-1

    def subscribe(self, topic: str):
        t = self.ps.topic(topic)
        if t in self._topics:
            raise KeyError('already subscribed to topic')

        s = self.__allocate_subscription()
        self._s[s] = t
        self._topics.add(t)

        t._subscribers.append((self, s))

        return {'s': s, 'root': t.root}

    def unsubscribe(self, s: int):
        try:
            t = self._s[s]
            if t is None: raise IndexError
        except IndexError as e:
            raise KeyError(f'invalid subscription ID {s!r}') from e

        self._topics.remove(t)
        self._s[s] = None
        while self._s and self._s[-1] is None: self._s.pop()

        t._subscribers.remove((self, s))
        self.receive({'s': s, 'msg': 'close'})

    def unsubscribe_all(self, *, silent=False):
        for s, t in enumerate(self._s):
            if t is None: continue

            self._topics.remove(t)
            t._subscribers.remove((self, s))

            if not silent:
                self.receive({'s': s, 'msg': 'close'})

        del self._s[:]
        assert not self._topics

    def receive(self, data):
        raise NotImplementedError

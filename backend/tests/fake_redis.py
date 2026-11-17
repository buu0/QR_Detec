"""
Minimal in-memory Redis fakes for API tests (no new dependency such as fakeredis).
Only the commands used by app.api.routes / app.core.security are implemented.
"""
import asyncio


class FakePubSub:
    def __init__(self, parent):
        self.parent = parent
        self.channels = set()

    async def subscribe(self, *channels):
        self.channels.update(channels)

    async def unsubscribe(self, *channels):
        for c in channels:
            self.channels.discard(c)

    async def get_message(self, ignore_subscribe_messages=True, timeout=0.0):
        await asyncio.sleep(min(timeout or 0.0, 0.01))
        return None

    async def aclose(self):
        return None


class FakeAsyncRedis:
    def __init__(self):
        self.store = {}
        self.hashes = {}
        self.published = []
        self.zsets = {}
        self.ttls = {}
        self.eval_calls = []
        self.fail = False

    def _check(self):
        if self.fail:
            raise ConnectionError("redis down")

    async def get(self, key):
        self._check()
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self._check()
        self.store[key] = str(value)
        return True

    async def setex(self, key, ttl, value):
        self._check()
        self.store[key] = value if isinstance(value, str) else str(value)
        self.ttls[key] = int(ttl)
        return True

    async def delete(self, *keys):
        self._check()
        n = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                n += 1
            if k in self.hashes:
                del self.hashes[k]
                n += 1
        return n

    async def exists(self, *keys):
        self._check()
        return sum(1 for k in keys if k in self.store or k in self.hashes)

    async def incr(self, key):
        self._check()
        v = int(self.store.get(key, 0)) + 1
        self.store[key] = str(v)
        return v

    async def decr(self, key):
        self._check()
        v = int(self.store.get(key, 0)) - 1
        self.store[key] = str(v)
        return v

    async def expire(self, key, ttl):
        self._check()
        self.ttls[key] = int(ttl)
        return True

    async def hset(self, key, field, value):
        self._check()
        self.hashes.setdefault(key, {})[field] = value
        return 1

    async def hgetall(self, key):
        self._check()
        return dict(self.hashes.get(key, {}))

    async def publish(self, channel, message):
        self._check()
        self.published.append((channel, message))
        return 0

    async def ping(self):
        self._check()
        return True

    def pubsub(self):
        return FakePubSub(self)

    # Sorted sets (global admission control)
    async def zadd(self, key, mapping):
        self._check()
        z = self.zsets.setdefault(key, {})
        added = sum(1 for m in mapping if m not in z)
        z.update({m: float(s) for m, s in mapping.items()})
        return added

    async def zcard(self, key):
        self._check()
        return len(self.zsets.get(key, {}))

    async def zrem(self, key, *members):
        self._check()
        z = self.zsets.get(key, {})
        return sum(1 for m in members if z.pop(m, None) is not None)

    async def zremrangebyscore(self, key, lo, hi):
        self._check()
        z = self.zsets.get(key, {})
        doomed = [m for m, s in z.items() if float(lo) <= s <= float(hi)]
        for m in doomed:
            del z[m]
        return len(doomed)

    async def zscore(self, key, member):
        self._check()
        return self.zsets.get(key, {}).get(member)

    async def ttl(self, key):
        self._check()
        if key not in self.store and key not in self.zsets:
            return -2
        return self.ttls.get(key, -1)

    # Lua scripts used by app.core.security. Real Redis runs a script atomically; here the
    # equivalent Python runs inside ONE coroutine step (no await in between), which gives the
    # same guarantee on a single event loop. Unknown scripts fail loudly.
    async def eval(self, script, numkeys, *keys_and_args):
        self._check()
        self.eval_calls.append(script)
        return _run_slot_script(self, script, int(numkeys), keys_and_args)

    async def aclose(self):
        return None


def _run_slot_script(fake, script, numkeys, keys_and_args):
    from app.core import security as sec

    keys = [str(k) for k in keys_and_args[:numkeys]]
    args = list(keys_and_args[numkeys:])
    if script == sec.ACQUIRE_SLOT_LUA:
        key, limit, ttl = keys[0], int(args[0]), int(args[1])
        current = int(fake.store.get(key, 0) or 0)
        if current >= limit:
            return 0
        fake.store[key] = str(current + 1)
        fake.ttls[key] = ttl
        return 1
    if script == sec.RELEASE_SLOT_LUA:
        key = keys[0]
        current = int(fake.store.get(key, 0) or 0)
        if current <= 1:
            fake.store.pop(key, None)
            fake.ttls.pop(key, None)
            return 0
        fake.store[key] = str(current - 1)
        return current - 1
    if script == sec.ACQUIRE_GLOBAL_SLOT_LUA:
        key = keys[0]
        now, limit, ttl, member = float(args[0]), int(args[1]), int(args[2]), str(args[3])
        z = fake.zsets.setdefault(key, {})
        for m in [m for m, s in z.items() if s <= now - ttl]:
            del z[m]
        if member in z:
            return 1
        if len(z) >= limit:
            return 0
        z[member] = now
        fake.ttls[key] = ttl
        return 1
    raise NotImplementedError("FakeRedis: unknown Lua script")


class FakeSyncRedis:
    """Synchronous view over a FakeAsyncRedis state (worker side: release_job_slot_sync)."""

    def __init__(self, shared: "FakeAsyncRedis"):
        self.shared = shared

    def get(self, key):
        return self.shared.store.get(key)

    def delete(self, *keys):
        n = 0
        for k in keys:
            if self.shared.store.pop(k, None) is not None:
                n += 1
        return n

    def zrem(self, key, *members):
        z = self.shared.zsets.get(key, {})
        return sum(1 for m in members if z.pop(m, None) is not None)

    def eval(self, script, numkeys, *keys_and_args):
        self.shared.eval_calls.append(script)
        return _run_slot_script(self.shared, script, int(numkeys), keys_and_args)

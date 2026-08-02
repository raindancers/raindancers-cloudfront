import { createKvsMock } from './kvs-mock';

describe('KVS mock', () => {
  it('returns seeded values via get()', async () => {
    const kvs = createKvsMock({ initialData: { 'jwt.secret': 'my-secret' } });
    const result = await kvs.get('jwt.secret');
    expect(result).toBe('my-secret');
  });

  it('throws on missing key (matches real KVS behaviour)', async () => {
    const kvs = createKvsMock();
    await expect(kvs.get('nonexistent')).rejects.toThrow('Key not found: nonexistent');
  });

  it('supports set() for test setup', async () => {
    const kvs = createKvsMock();
    kvs.set('jwt.secret', 'added-later');
    const result = await kvs.get('jwt.secret');
    expect(result).toBe('added-later');
  });

  it('supports delete() for simulating key removal', async () => {
    const kvs = createKvsMock({ initialData: { 'jwt.secret': 'value' } });
    kvs.delete('jwt.secret');
    await expect(kvs.get('jwt.secret')).rejects.toThrow();
  });

  it('tracks access log', async () => {
    const kvs = createKvsMock({ initialData: { a: '1', b: '2' } });
    await kvs.get('a');
    await kvs.get('b');
    await kvs.get('a');
    expect(kvs.getAccessLog()).toEqual(['a', 'b', 'a']);
  });

  it('clearAccessLog resets the log', async () => {
    const kvs = createKvsMock({ initialData: { a: '1' } });
    await kvs.get('a');
    kvs.clearAccessLog();
    expect(kvs.getAccessLog()).toEqual([]);
  });

  it('has() checks existence without triggering access log', () => {
    const kvs = createKvsMock({ initialData: { key: 'val' } });
    expect(kvs.has('key')).toBe(true);
    expect(kvs.has('missing')).toBe(false);
    expect(kvs.getAccessLog()).toEqual([]);
  });
});

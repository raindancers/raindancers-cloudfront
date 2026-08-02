/**
 * Mock implementation of the CloudFront KeyValueStore (KVS) interface.
 *
 * CloudFront Functions access KVS via `cf.kvs()` which returns an object
 * with a `get(key)` method. This mock allows tests to configure stored
 * values (HMAC secrets, revocation entries) and assert on access patterns.
 */

export interface KvsMockOptions {
  /** Initial key-value pairs to seed the store. */
  readonly initialData?: Record<string, string>;
}

/**
 * Create a mock KVS handle that mimics the CloudFront `cf.kvs()` interface.
 *
 * @param options - Configuration including initial data
 * @returns An object with `get(key)` that resolves to stored values, plus test helpers
 *
 * @example
 * const kvs = createKvsMock({ initialData: { 'jwt.secret': 'my-secret' } });
 * const secret = await kvs.get('jwt.secret'); // 'my-secret'
 */
export function createKvsMock(options: KvsMockOptions = {}) {
  const store: Map<string, string> = new Map(Object.entries(options.initialData ?? {}));
  const accessLog: string[] = [];

  return {
    /**
     * Retrieve a value by key, mimicking KVS async behaviour.
     *
     * @param key - The KVS key to look up
     * @returns The stored value, or throws if key not found (matches real KVS behaviour)
     * @throws Error if key does not exist in the store
     */
    async get(key: string): Promise<string> {
      accessLog.push(key);
      const value = store.get(key);
      if (value === undefined) {
        throw new Error(`Key not found: ${key}`);
      }
      return value;
    },

    // --- Test helpers (not part of real KVS interface) ---

    /**
     * Set a value in the mock store.
     *
     * @param key - The key to set
     * @param value - The value to store
     */
    set(key: string, value: string): void {
      store.set(key, value);
    },

    /**
     * Delete a key from the mock store.
     *
     * @param key - The key to remove
     */
    delete(key: string): void {
      store.delete(key);
    },

    /**
     * Get the list of keys that were accessed via `get()`.
     *
     * @returns Array of keys accessed in order
     */
    getAccessLog(): string[] {
      return [...accessLog];
    },

    /**
     * Reset the access log.
     */
    clearAccessLog(): void {
      accessLog.length = 0;
    },

    /**
     * Check if a key exists in the store.
     *
     * @param key - The key to check
     * @returns true if the key exists
     */
    has(key: string): boolean {
      return store.has(key);
    },
  };
}

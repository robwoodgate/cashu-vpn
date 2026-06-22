/**
 * A single-promise-chain serializer: every call runs after the previous one
 * settles, so a read-modify-write of a backing file can't interleave with
 * another and lose an update. (orders.ts inlines the same pattern.)
 */
export function serialize(): <T>(fn: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return <T>(fn: () => Promise<T>): Promise<T> => {
    const run = tail.then(fn, fn);
    tail = run.then(() => undefined, () => undefined);
    return run;
  };
}

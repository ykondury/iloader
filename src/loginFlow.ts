// Kept outside the component so rapid submissions share one operation.
export function createLoginRunner() {
  let pending = false;
  return <T>(operation: () => Promise<T>): Promise<T> | null => {
    if (pending) return null;
    pending = true;
    return (async () => {
      try {
        return await operation();
      } finally {
        pending = false;
      }
    })();
  };
}

export function pendingSubscription(registration: Promise<() => void>) {
  let disposed = false;
  let cleanup: (() => void) | undefined;
  const ready = registration.then((unlisten) => {
    if (disposed) unlisten();
    else cleanup = unlisten;
  });
  return {
    ready,
    dispose() {
      disposed = true;
      cleanup?.();
      cleanup = undefined;
    },
  };
}

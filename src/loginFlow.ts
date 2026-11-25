// Kept outside the component so rapid submissions share one operation.
export function createLoginRunner() {
  return <T>(operation: () => Promise<T>): Promise<T> | null => operation();
}

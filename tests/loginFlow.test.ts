import { describe, expect, test } from "bun:test";
import { createLoginRunner, pendingSubscription } from "../src/loginFlow";

describe("login submissions", () => {
  test("a double click starts exactly one Apple login", async () => {
    const run = createLoginRunner();
    let finish!: () => void;
    let started = 0;
    const operation = () => {
      started++;
      return new Promise<void>((resolve) => { finish = resolve; });
    };
    const first = run(operation);
    const duplicate = run(operation);
    expect(started).toBe(1);
    expect(duplicate).toBeNull();
    finish();
    await first;
  });

  test("a failed attempt releases the gate for a manual retry", async () => {
    const run = createLoginRunner();
    const attempt = run(async () => { throw new Error("network unavailable"); });
    await expect(attempt!).rejects.toThrow("network unavailable");
    expect(await run(async () => "signed in")).toBe("signed in");
  });

  test("a completed attempt releases the gate", async () => {
    const run = createLoginRunner();
    expect(await run(async () => "first")).toBe("first");
    expect(await run(async () => "second")).toBe("second");
  });

  test("a synchronous exception also releases the gate", async () => {
    const run = createLoginRunner();
    await expect(run(() => { throw new Error("IPC unavailable"); })!).rejects.toThrow("IPC unavailable");
    expect(await run(async () => "retry")).toBe("retry");
  });
});

describe("event subscriptions", () => {
  test("unmount before registration finishes still removes the listener", async () => {
    let register!: (cleanup: () => void) => void;
    let removed = 0;
    const subscription = pendingSubscription(new Promise((resolve) => { register = resolve; }));
    subscription.dispose();
    register(() => { removed++; });
    await subscription.ready;
    subscription.dispose();
    expect(removed).toBe(1);
  });

  test("StrictMode setup-cleanup-setup leaves the second listener working", async () => {
    let listeners = 0;
    const register = async () => { listeners++; return () => { listeners--; }; };
    const first = pendingSubscription(register());
    first.dispose();
    const second = pendingSubscription(register());
    await Promise.all([first.ready, second.ready]);
    expect(listeners).toBe(1);
    second.dispose();
    second.dispose();
    expect(listeners).toBe(0);
  });
});

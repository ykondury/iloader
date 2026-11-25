import { describe, expect, test } from "bun:test";
import { createLoginRunner } from "../src/loginFlow";

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
});

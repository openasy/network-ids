import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "network-ids-")), "nested", "network-ids.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();
    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("keeps an alert from naming a sensor that does not exist", () => {
    const db = openDb(":memory:");
    expect(() =>
      db
        .prepare(
          "INSERT INTO alerts (uid, sensor_id, time, src_ip, dest_ip, proto, gid, sid, rev, signature, category, severity, action, event) VALUES ('u', 'missing', 't', 'a', 'b', 'TCP', 1, 1, 1, 's', 'c', 'low', 'allowed', '{}')",
        )
        .run(),
    ).toThrow(/FOREIGN KEY/);
  });
});

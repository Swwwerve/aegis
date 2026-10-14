import { test } from "node:test";
import assert from "node:assert/strict";
import {
  canonicalUrl,
  parseFrames,
  safeLink,
  streamScan,
  streamContext,
} from "./api";

test("canonical GitHub URLs handle .git, whitespace and invalid schemes", () => {
  assert.equal(
    canonicalUrl(" https://github.com/OWASP/NodeGoat.git/ "),
    "https://github.com/OWASP/NodeGoat",
  );
  for (const url of [
    "https://gitlab.com/a/b",
    "javascript:alert(1)",
    "https://github.com/a/b/tree/main",
    "https://github.com/a/b?token=secret",
    "https://github.com/a/b#fragment",
  ])
    assert.throws(() => canonicalUrl(url));
});
test("SSE parser handles CRLF, comments, multiline data and incomplete chunks", () => {
  const payload =
    ': keep-alive\r\n\r\nevent: progress\r\ndata: {"stage":\r\ndata: "inventory"}\r\n\r\nevent: result\ndata: {"id":1}';
  const parsed = parseFrames(payload);
  assert.equal(parsed.frames.length, 1);
  assert.deepEqual(JSON.parse(parsed.frames[0].data), { stage: "inventory" });
  assert.equal(parsed.frames[0].event, "progress");
  assert.equal(
    parseFrames(parsed.remainder + "\n\n").frames[0].event,
    "result",
  );
});
test("untrusted reference URLs allow only HTTP and HTTPS", () => {
  assert.equal(safeLink("javascript:alert(1)"), undefined);
  assert.equal(safeLink("file:///secret"), undefined);
  assert.equal(
    safeLink("https://osv.dev/vulnerability/CVE-2021-44228"),
    "https://osv.dev/vulnerability/CVE-2021-44228",
  );
});
test("stream reader handles fragmented UTF-8 and reports a missing terminal result", async () => {
  const original = globalThis.fetch;
  const text =
    'event: progress\ndata: {"stage":"inventory","status":"completed","message":"café"}\n\nevent: result\ndata: {"id":7}\n\nevent: end\ndata: {}\n\n';
  let progress = "",
    result = 0;
  const bytes = new TextEncoder().encode(text);
  globalThis.fetch = async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
          controller.close();
        },
      }),
    );
  try {
    await streamScan(
      1,
      { use_model: false, resolve_dependencies: false },
      new AbortController().signal,
      (e) => {
        progress = e.message;
      },
      (r) => {
        result = r.id;
      },
    );
    assert.equal(progress, "café");
    assert.equal(result, 7);
    globalThis.fetch = async () => new Response("event: end\ndata: {}\n\n");
    await assert.rejects(
      streamScan(
        1,
        { use_model: false, resolve_dependencies: false },
        new AbortController().signal,
        () => {},
        () => {},
      ),
      /before results/,
    );
  } finally {
    globalThis.fetch = original;
  }
});

test("a saved result finishes without waiting for the server to close the stream", async () => {
  const original = globalThis.fetch;
  let cancelled = false;
  let controller: ReadableStreamDefaultController<Uint8Array>;
  let timer: ReturnType<typeof setTimeout>;
  const received: number[] = [];
  globalThis.fetch = async () =>
    new Response(
      new ReadableStream<Uint8Array>({
        start(c) {
          controller = c;
          c.enqueue(
            new TextEncoder().encode('event: result\ndata: {"id":7}\n\n'),
          );
          // The result is persisted; connection cleanup is not scan work.
        },
        cancel() {
          cancelled = true;
        },
      }),
    );
  try {
    await Promise.race([
      streamScan(
        1,
        { use_model: false, resolve_dependencies: false },
        new AbortController().signal,
        () => {},
        (r) => received.push(r.id),
      ),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Still waiting after the saved result")),
          500,
        );
      }),
    ]);
    assert.deepEqual(received, [7]);
    assert.equal(cancelled, true);
  } finally {
    clearTimeout(timer!);
    if (!cancelled) controller!.close();
    globalThis.fetch = original;
  }
});

test("context progress arrives before the final packet and clarification is scoped to the scan", async () => {
  const original = globalThis.fetch;
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let progressSeen!: () => void;
  const started = new Promise<void>((resolve) => {
    progressSeen = resolve;
  });
  let resultReceived = false;
  globalThis.fetch = async (input, init) => {
    assert.equal(input, "/api/remediation/context/stream");
    assert.deepEqual(JSON.parse(init!.body as string), {
      scan_id: 19,
      cve_id: "CVE-2023-45803",
      clarification: "Production uses Client",
    });
    return new Response(
      new ReadableStream<Uint8Array>({
        start(c) {
          controller = c;
          c.enqueue(
            new TextEncoder().encode(
              'event: progress\ndata: {"stage":"context_investigation","status":"running","message":"Checking callers"}\n\n',
            ),
          );
        },
      }),
    );
  };
  try {
    const pending = streamContext(
      19,
      "CVE-2023-45803",
      "Production uses Client",
      new AbortController().signal,
      (event) => {
        assert.equal(event.message, "Checking callers");
        progressSeen();
      },
      () => {
        resultReceived = true;
      },
    );
    await started;
    assert.equal(resultReceived, false);
    controller.enqueue(
      new TextEncoder().encode(
        'event: result\ndata: {"cve_id":"CVE-2023-45803","status":"completed"}\n\n',
      ),
    );
    await pending;
    assert.equal(resultReceived, true);
  } finally {
    globalThis.fetch = original;
  }
});

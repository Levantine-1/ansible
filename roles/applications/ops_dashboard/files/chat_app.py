#!/usr/bin/env python3
"""Chat UI talking to the fleet's Ollama instance.

That's the same Ollama instance (on `incident-agent`) that serves the
incident-triage pipeline's classification step -- reused here rather than
installing a second copy, since there's only one small CPU-only box running
it. A chat conversation and a real incident being triaged will contend for
the same model; acceptable for occasional personal use on a homelab, just
worth knowing if a reply feels slow during an actual incident.

No auth, no server-side conversation storage, by design (not an oversight):
this app isn't gating anything sensitive on its own -- worst case someone on
the LAN burns a few CPU-seconds chatting with a local model -- and the
browser keeping conversation history in memory and resending it each turn is
the simplest thing that actually works, no session store or database needed.

Streaming mirrors the proven pattern in livecam.py: a generator wrapped in
stream_with_context, so an abandoned browser tab stops pulling from Ollama on
its next failed write rather than continuing to burn CPU for nobody.
"""
import json
import os
import urllib.error
import urllib.request

from flask import Flask, Response, request, stream_with_context

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://incident-agent.internal.levantine.io:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "phi4-mini")

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Chat</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {
    color-scheme: light dark;
    --bg: #f5f6f8;
    --card-bg: #ffffff;
    --text: #1a1a1a;
    --muted: #666;
    --border: #e0e0e0;
    --accent: #3b6ef5;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #14161a;
      --card-bg: #1e2127;
      --text: #e8e8e8;
      --muted: #9aa0aa;
      --border: #2c3038;
      --accent: #6d93ff;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  header {
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--border);
  }
  header a { color: var(--muted); font-size: 0.85rem; text-decoration: none; }
  header h1 { font-size: 1.1rem; margin: 0.2rem 0 0; }
  header .model { color: var(--muted); font-size: 0.8rem; }
  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 1.5rem;
    max-width: 780px;
    width: 100%;
    margin: 0 auto;
  }
  .msg { margin-bottom: 1.2rem; white-space: pre-wrap; word-wrap: break-word; }
  .msg .role { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); margin-bottom: 0.3rem; }
  .msg.user .bubble { background: var(--accent); color: #fff; border-radius: 10px; padding: 0.6rem 0.9rem; display: inline-block; }
  .msg.assistant .bubble { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 0.6rem 0.9rem; display: inline-block; }
  .msg.error .bubble { border-color: #d33; color: #d33; }
  form {
    display: flex;
    gap: 0.6rem;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--border);
    max-width: 780px;
    width: 100%;
    margin: 0 auto;
    box-sizing: border-box;
  }
  textarea {
    flex: 1;
    resize: none;
    padding: 0.6rem 0.8rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--card-bg);
    color: var(--text);
    font-family: inherit;
    font-size: 0.95rem;
  }
  button {
    padding: 0 1.2rem;
    border-radius: 8px;
    border: none;
    background: var(--accent);
    color: #fff;
    font-weight: 600;
    cursor: pointer;
  }
  button:disabled { opacity: 0.5; cursor: default; }
</style>
</head>
<body>
<header>
  <a href="/">&larr; Dashboard</a>
  <h1>Chat</h1>
  <div class="model">talking to __MODEL__ on incident-agent</div>
</header>
<div id="messages"></div>
<form id="form">
  <textarea id="input" rows="1" placeholder="Ask something..." autofocus></textarea>
  <button id="send" type="submit">Send</button>
</form>
<script>
  const messages = [];
  const messagesEl = document.getElementById("messages");
  const form = document.getElementById("form");
  const input = document.getElementById("input");
  const sendBtn = document.getElementById("send");

  function appendMessage(role, text) {
    const wrap = document.createElement("div");
    wrap.className = "msg " + role;
    const label = document.createElement("div");
    label.className = "role";
    label.textContent = role;
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = text;
    wrap.appendChild(label);
    wrap.appendChild(bubble);
    messagesEl.appendChild(wrap);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return bubble;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    sendBtn.disabled = true;

    messages.push({ role: "user", content: text });
    appendMessage("user", text);
    const bubble = appendMessage("assistant", "...");

    try {
      const resp = await fetch("/chat/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages }),
      });
      if (!resp.ok || !resp.body) {
        throw new Error("HTTP " + resp.status);
      }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let full = "";
      let first = true;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const piece = decoder.decode(value, { stream: true });
        if (first && piece) { full = ""; first = false; }
        full += piece;
        bubble.textContent = full;
        messagesEl.scrollTop = messagesEl.scrollHeight;
      }
      messages.push({ role: "assistant", content: full });
    } catch (err) {
      bubble.parentElement.classList.add("error");
      bubble.textContent = "Could not reach the model: " + err.message;
    } finally {
      sendBtn.disabled = false;
      input.focus();
    }
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      form.requestSubmit();
    }
  });
</script>
</body>
</html>
""".replace("__MODEL__", OLLAMA_MODEL)


@app.route("/chat/")
def index():
    return PAGE


@app.route("/chat/stream", methods=["POST"])
def stream():
    payload = request.get_json(force=True, silent=True) or {}
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        return Response("(no messages)", status=400)

    def generate():
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=json.dumps({"model": OLLAMA_MODEL, "messages": messages, "stream": True}).encode(),
            method="POST",
        )
        req.add_header("Content-Type", "application/json")
        try:
            # Iterating the response line-by-line is what makes this stream
            # incrementally rather than waiting for the connection to close --
            # HTTPResponse yields each chunk as Ollama flushes it, same as any
            # other chunked-transfer response.
            with urllib.request.urlopen(req, timeout=120) as resp:
                for raw_line in resp:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except ValueError:
                        continue
                    content = (chunk.get("message") or {}).get("content", "")
                    if content:
                        yield content
                    if chunk.get("done"):
                        break
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            yield f"\n\n[could not reach the local model: {e}]"

    return Response(stream_with_context(generate()), mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055)

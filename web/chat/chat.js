(() => {
  "use strict";
  const api = "/api/v1";
  const el = (id) => document.getElementById(id);
  const state = { conversationId: null, turnId: null, aborter: null, assistantNode: null, busy: false };
  const words = {
    am: {
      new: "＋ አዲስ ውይይት", history: "የቀድሞ ውይይቶች",
      welcome: "እንኳን ወደ IROKA በደህና መጡ",
      copy: "ጥያቄዎን በአማርኛ ወይም በEnglish ይጻፉ።",
      placeholder: "መልዕክትዎን እዚህ ይጻፉ...", send: "ላክ", cancel: "አቁም",
      privacy: "የጽሑፍ ውይይት · መሣሪያ አይፈጽምም",
      working: "IROKA እያዘጋጀ ነው…", failed: "መልዕክቱ አልተላከም። እባክዎ እንደገና ይሞክሩ።",
      auth: "ለመቀጠል በIROKA ይግቡ።", empty: "ገና ውይይት የለም።"
    },
    en: {
      new: "＋ New conversation", history: "Recent conversations",
      welcome: "Welcome to IROKA",
      copy: "Ask a question in Amharic or English.",
      placeholder: "Write your message here...", send: "Send", cancel: "Stop",
      privacy: "Text chat · no tools or actions are executed",
      working: "IROKA is preparing an answer…", failed: "Message failed. Please try again.",
      auth: "Sign in to IROKA to continue.", empty: "No conversations yet."
    }
  };
  const locale = () => el("locale").value;
  const text = (id, value) => { el(id).textContent = value; };
  const status = (value) => { text("status", value); };
  const request = async (path, options = {}) => {
    const response = await fetch(api + path, {
      credentials: "same-origin",
      ...options,
      headers: { "Content-Type": "application/json", ...(options.headers || {}) }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const code = body?.error?.code;
      if (response.status === 401 || response.status === 403) throw new Error("AUTH_REQUIRED");
      throw new Error(code || "REQUEST_FAILED");
    }
    return body;
  };
  const idempotencyKey = () => {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  };
  const addMessage = (role, value = "") => {
    const node = document.createElement("article");
    node.className = "message " + role;
    node.dir = "auto";
    node.textContent = value;
    el("messages").append(node);
    node.scrollIntoView({ block: "end", behavior: "smooth" });
    return node;
  };
  const renderConversations = (items) => {
    const list = el("conversation-list"); list.replaceChildren();
    for (const item of items) {
      const li = document.createElement("li");
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = item.title || item.id;
      if (item.id === state.conversationId) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => openConversation(item.id));
      li.append(button); list.append(li);
    }
    if (!items.length) {
      const li = document.createElement("li"); li.textContent = words[locale()].empty; list.append(li);
    }
  };
  const loadConversations = async () => {
    const data = await request("/conversations");
    renderConversations(data.conversations || data.items || []);
  };
  const openConversation = async (id) => {
    state.conversationId = id;
    el("messages").replaceChildren();
    el("welcome").hidden = true;
    const data = await request("/conversations/" + encodeURIComponent(id) + "/messages");
    for (const message of (data.messages || data.items || [])) {
      addMessage(message.role === "user" ? "user" : "assistant", message.text || message.content || "");
    }
    await loadConversations();
  };
  const createConversation = async () => {
    const data = await request("/conversations", {
      method: "POST",
      body: JSON.stringify({ client_request_id: idempotencyKey() })
    });
    const id = data.conversation?.id;
    if (!id) throw new Error("INVALID_RESPONSE");
    state.conversationId = id;
    el("messages").replaceChildren();
    el("welcome").hidden = true;
    await loadConversations();
  };
  const consumeEvents = async (url, signal) => {
    const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "text/event-stream" }, signal });
    if (!response.ok || !response.body) throw new Error("STREAM_FAILED");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) >= 0) {
        const frame = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
        const dataLine = frame.split("\n").find(line => line.startsWith("data:"));
        if (!dataLine) continue;
        const event = JSON.parse(dataLine.slice(5).trim());
        if (event.type === "message.delta") {
          const delta = event.payload?.text || "";
          if (state.assistantNode) state.assistantNode.textContent += delta;
        } else if (event.type === "generation.completed") {
          status("");
        } else if (event.type === "generation.interrupted") {
          status(locale() === "am" ? "ውይይቱ ተቋርጧል።" : "Generation interrupted.");
        } else if (event.type === "generation.failed") {
          status(words[locale()].failed);
        }
      }
    }
  };
  const send = async (message) => {
    if (!state.conversationId) await createConversation();
    state.busy = true; setBusy(true); status(words[locale()].working);
    addMessage("user", message);
    state.assistantNode = addMessage("assistant", "");
    state.aborter = new AbortController();
    try {
      const data = await request("/conversations/" + encodeURIComponent(state.conversationId) + "/turns", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey() },
        body: JSON.stringify({
          client_request_id: idempotencyKey(),
          input: { type: "text", text: message },
          locale: locale()
        })
      });
      state.turnId = data.turn?.id || null;
      if (!data.events_url || !data.events_url.startsWith("/api/v1/generations/") || data.events_url.includes("..")) {
        throw new Error("INVALID_EVENTS_URL");
      }
      el("cancel").disabled = false;
      await consumeEvents(data.events_url, state.aborter.signal);
      if (!statusText()) status("");
    } catch (error) {
      if (error.name !== "AbortError") {
        status(error.message === "AUTH_REQUIRED" ? words[locale()].auth : words[locale()].failed);
      }
    } finally {
      state.busy = false; state.aborter = null; setBusy(false); state.turnId = null;
      await loadConversations().catch(() => {});
    }
  };
  const statusText = () => el("status").textContent;
  const setBusy = (busy) => {
    el("send").disabled = busy;
    el("cancel").disabled = !busy || !state.turnId;
    el("prompt").disabled = busy;
  };
  const cancel = async () => {
    if (!state.busy || !state.conversationId || !state.turnId) return;
    try {
      await request("/conversations/" + encodeURIComponent(state.conversationId) +
        "/turns/" + encodeURIComponent(state.turnId) + "/cancel", { method: "POST", body: "{}" });
    } catch (_) {
      status(locale() === "am" ? "ማቋረጥ አልተረጋገጠም።" : "Cancellation could not be confirmed.");
    } finally {
      state.aborter?.abort();
    }
  };
  const applyLocale = () => {
    const w = words[locale()];
    document.documentElement.lang = locale();
    text("new-conversation", w.new); text("history-label", w.history);
    text("welcome-title", w.welcome); text("welcome-copy", w.copy);
    text("send", w.send); text("cancel", w.cancel); text("privacy-note", w.privacy);
    el("prompt").placeholder = w.placeholder;
    loadConversations().catch(() => {});
  };
  el("composer").addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = el("prompt").value.trim();
    if (!value || state.busy) return;
    el("prompt").value = "";
    await send(value);
  });
  el("new-conversation").addEventListener("click", async () => {
    try { await createConversation(); status(""); }
    catch (error) { status(error.message === "AUTH_REQUIRED" ? words[locale()].auth : words[locale()].failed); }
  });
  el("cancel").addEventListener("click", cancel);
  el("locale").addEventListener("change", applyLocale);
  applyLocale();
  loadConversations().catch((error) => {
    if (error.message === "AUTH_REQUIRED") status(words[locale()].auth);
    else status(words[locale()].failed);
  });
})();

// The 30-line event emitter node:events would provide, because the session state
// machine in session-core.js is imported by the browser as well as by Node.

export class Emitter {
  constructor() {
    this.listeners = new Map();
  }

  on(event, handler) {
    const list = this.listeners.get(event) ?? [];
    list.push(handler);
    this.listeners.set(event, list);
    return this;
  }

  once(event, handler) {
    const wrap = (payload) => {
      this.off(event, wrap);
      handler(payload);
    };
    return this.on(event, wrap);
  }

  off(event, handler) {
    const list = this.listeners.get(event);
    if (!list) return this;
    const at = list.indexOf(handler);
    if (at !== -1) list.splice(at, 1);
    return this;
  }

  emit(event, payload) {
    const list = this.listeners.get(event);
    if (!list) return false;
    // Copy first: a handler that unsubscribes must not shift the iteration.
    for (const handler of list.slice()) handler(payload);
    return true;
  }
}

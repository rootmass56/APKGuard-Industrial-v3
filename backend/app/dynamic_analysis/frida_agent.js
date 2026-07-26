/* APKGuard Phase 4 observation-only Frida agent.
 *
 * The agent records bounded metadata about selected Java API calls. It does not
 * alter return values, bypass controls, or exfiltrate application data.
 */
(function () {
  "use strict";

  const PREFIX = "APKGuardEvent:";
  const MAX_TEXT = 512;

  function safe(value) {
    try {
      const text = String(value);
      return text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) + "...[truncated]" : text;
    } catch (_) {
      return "[unavailable]";
    }
  }

  function emit(category, eventType, title, description, severity, payload) {
    const event = {
      category: category,
      event_type: eventType,
      title: title,
      description: description,
      severity: severity,
      timestamp_ms: Date.now(),
      process_id: Process.id,
      thread_id: Process.getCurrentThreadId(),
      payload: payload || {},
    };
    console.log(PREFIX + JSON.stringify(event));
  }

  if (!Java.available) {
    emit("SYSTEM", "java_unavailable", "Java runtime unavailable", "Frida attached before the Java VM was ready.", "INFO", {});
    return;
  }

  Java.perform(function () {
    try {
      const Runtime = Java.use("java.lang.Runtime");
      Runtime.exec.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const args = Array.prototype.slice.call(arguments).map(safe);
          emit("COMMAND", "runtime_exec", "Runtime command execution observed", "java.lang.Runtime.exec was invoked.", "HIGH", {
            api: "java.lang.Runtime.exec",
            class_name: "java.lang.Runtime",
            args: args,
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
      DexClassLoader.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const args = Array.prototype.slice.call(arguments).map(safe);
          emit("PROCESS", "dynamic_dex_load", "Dynamic DEX loading observed", "DexClassLoader was constructed at runtime.", "HIGH", {
            api: "dalvik.system.DexClassLoader.$init",
            class_name: "dalvik.system.DexClassLoader",
            args: args,
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const Cipher = Java.use("javax.crypto.Cipher");
      Cipher.getInstance.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const algorithm = safe(arguments[0]);
          emit("CRYPTO", "cipher_instance", "Cryptographic primitive used", "Cipher.getInstance was invoked.", "INFO", {
            algorithm: algorithm,
            purpose: "Runtime cipher construction",
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const URL = Java.use("java.net.URL");
      URL.openConnection.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const url = safe(this.toString());
          emit("NETWORK", "url_connection", "URL connection attempted", "java.net.URL.openConnection was invoked while the offline policy was active.", "MEDIUM", {
            method: "CONNECT",
            url: url,
            blocked_by_policy: true,
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const Socket = Java.use("java.net.Socket");
      Socket.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const args = Array.prototype.slice.call(arguments).map(safe);
          emit("NETWORK", "socket_connect", "Socket construction observed", "A java.net.Socket constructor was invoked.", "MEDIUM", {
            method: "CONNECT",
            host: args[0] || null,
            port: args[1] || null,
            blocked_by_policy: true,
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const FileOutputStream = Java.use("java.io.FileOutputStream");
      FileOutputStream.$init.overloads.forEach(function (overload) {
        overload.implementation = function () {
          const path = safe(arguments[0]);
          emit("FILE", "file_write_open", "File write opened", "FileOutputStream was constructed.", "INFO", {
            operation: "open_write",
            path: path,
            size_bytes: 0,
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    try {
      const WebView = Java.use("android.webkit.WebView");
      WebView.addJavascriptInterface.overloads.forEach(function (overload) {
        overload.implementation = function () {
          emit("PROCESS", "webview_js_interface", "WebView JavaScript interface added", "addJavascriptInterface was invoked at runtime.", "HIGH", {
            api: "android.webkit.WebView.addJavascriptInterface",
            class_name: "android.webkit.WebView",
            args: ["[object redacted]", safe(arguments[1])],
          });
          return overload.apply(this, arguments);
        };
      });
    } catch (_) {}

    emit("SYSTEM", "agent_ready", "Frida observation agent loaded", "Observation-only Java hooks were installed.", "INFO", {});
  });
})();

(function () {
  const MODULE_DIR = "/data/adb/modules/ai.adaptive.firewall";

  function shQuote(value) {
    return `'${String(value || "").replace(/'/g, `'"'"'`)}'`;
  }

  async function getBridgeExec() {
    if (window.ksu && typeof window.ksu.exec === "function") return async (cmd) => window.ksu.exec(cmd);
    if (window.KernelSU && typeof window.KernelSU.exec === "function") return async (cmd) => window.KernelSU.exec(cmd);
    try {
      const mod = await import("kernelsu");
      if (mod && typeof mod.exec === "function") return async (cmd) => mod.exec(cmd);
    } catch {}
    return null;
  }

  async function execRoot(command) {
    const bridge = await getBridgeExec();
    if (!bridge) throw new Error("KSU bridge tidak tersedia");
    const out = await bridge(command);
    if (out && typeof out === "object") {
      if (typeof out.stdout === "string" && out.stdout.trim()) return out.stdout.trim();
      if (typeof out.output === "string" && out.output.trim()) return out.output.trim();
      return JSON.stringify(out);
    }
    return String(out || "").trim();
  }

  function buildExecScript(scriptRelPath, query) {
    const script = `${MODULE_DIR}/${scriptRelPath.replace(/^\//, "")}`;
    const inner = query && String(query).length > 0
      ? `QUERY_STRING=${shQuote(query)} sh ${shQuote(script)}`
      : `sh ${shQuote(script)}`;
    return `su -c ${shQuote(inner)}`;
  }

  async function runScript(scriptRelPath, query) {
    return execRoot(buildExecScript(scriptRelPath, query));
  }

  window.KSUBridge = {
    MODULE_DIR,
    shQuote,
    getBridgeExec,
    execRoot,
    runScript,
    buildExecScript,
  };
})();

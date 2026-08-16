// raw2pcap web UI logic. All input-shaping logic lives server-side (and is
// covered by pytest); this file is deliberately thin DOM wiring.
const reqBox = document.querySelector('textarea[name="inputRequest"]');
const btn = document.getElementById("btn");

function syncBtn() {
  btn.disabled = !reqBox.value.trim();
}
reqBox.addEventListener("input", syncBtn);
syncBtn();

const serverIpBox = document.getElementById("serverIp");
const DEFAULT_SERVER_IP = "10.0.0.2";
let serverIpEdited = false;

function hostIpv4(text) {
  const m = text.match(/^Host:\s*([0-9]+(?:\.[0-9]+){3})/im);
  // Mirror the server-side special case: Host: 127.0.0.1 is not treated as
  // the destination address, so the default is shown instead.
  return m && m[1] !== "127.0.0.1" ? m[1] : null;
}

// Mirror the server-side rule in the UI: the destination IP auto-fills from
// a literal IPv4 in the Host header, falling back to the synthetic default.
// Once the user edits the field by hand, stop touching it.
function syncServerIp() {
  if (serverIpEdited) return;
  serverIpBox.value = hostIpv4(reqBox.value) || DEFAULT_SERVER_IP;
}

reqBox.addEventListener("input", syncServerIp);
serverIpBox.addEventListener("input", () => {
  serverIpEdited = true;
});
syncServerIp();

function showIssues(el, items, prefix) {
  const list = Array.isArray(items) ? items : [items];
  el.innerHTML = list.map((m) => "<div>" + prefix + " " + m + "</div>").join("");
  el.style.display = list.length ? "block" : "none";
}

function downloadName(resp) {
  const cd = resp.headers.get("Content-Disposition") || "";
  const m = cd.match(/filename="([^"]+)"/);
  return m ? m[1] : "raw2pcap-result.pcap";
}

document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const err = document.getElementById("err");
  const warn = document.getElementById("warn");
  err.style.display = "none";
  warn.style.display = "none";
  btn.disabled = true;
  try {
    const resp = await fetch("/api/pcap", { method: "POST", body: new FormData(e.target) });
    if (!resp.ok) {
      showIssues(err, (await resp.json()).detail || "failed", "✕");
      return;
    }
    const warnings = JSON.parse(resp.headers.get("X-Raw2pcap-Warnings") || "[]");
    if (warnings.length) showIssues(warn, warnings, "⚠");
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = downloadName(resp);
    a.click();
    URL.revokeObjectURL(url);
  } finally {
    syncBtn();
  }
});

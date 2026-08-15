// raw2pcap web UI logic. All input-shaping logic lives server-side (and is
// covered by pytest); this file is deliberately thin DOM wiring.
const reqBox = document.querySelector('textarea[name="inputRequest"]');
const btn = document.getElementById("btn");

function syncBtn() {
  btn.disabled = !reqBox.value.trim();
}
reqBox.addEventListener("input", syncBtn);
syncBtn();

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

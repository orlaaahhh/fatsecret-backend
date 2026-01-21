const outEl = document.getElementById("out");
const out = (x) => {
  outEl.textContent = typeof x === "string" ? x : JSON.stringify(x, null, 2);
};

function adminKey() {
  return document.getElementById("adminKey").value.trim();
}

document.getElementById("btnFind").onclick = async () => {
  try {
    const key = adminKey();
    const email = document.getElementById("email").value.trim().toLowerCase();
    if (!key) return out("❌ Incolla prima ADMIN_API_KEY");
    if (!email) return out("❌ Inserisci email");

    const r = await fetch(`/admin/users?email=${encodeURIComponent(email)}`, {
      headers: { "x-admin-key": key }
    });
    const j = await r.json();
    out(j);

    if (j.user?.id) {
      document.getElementById("userIdLabel").textContent = j.user.id;
      document.getElementById("userId").value = j.user.id;
    }
  } catch (e) {
    out(String(e));
  }
};

document.getElementById("btnCreate").onclick = async () => {
  try {
    const key = adminKey();
    if (!key) return out("❌ Incolla prima ADMIN_API_KEY");

    const body = {
      userId: Number(document.getElementById("userId").value),
      title: document.getElementById("title").value.trim(),
      start: document.getElementById("start").value.trim(),
      end: document.getElementById("end").value.trim(),
      zoomUrl: document.getElementById("zoomUrl").value.trim(),
    };

    const r = await fetch(`/meetings`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-admin-key": key },
      body: JSON.stringify(body),
    });

    const j = await r.json();
    out(j);
  } catch (e) {
    out(String(e));
  }
};

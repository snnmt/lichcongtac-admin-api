// Express API: quản trị user qua firebase-admin (tạo/sửa/xoá)
// Endpoint chính: POST /admin  { action, data }

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

// Khởi tạo Admin SDK từ ENV (Render cung cấp)
if (!admin.apps.length) {
  const privateKey = process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
    : undefined;

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey,
    }),
  });
}

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json());

// Xác thực: kiểm tra Firebase ID token + role=admin trong Firestore
async function assertAdminFromIdToken(req) {
  const h = req.headers.authorization || "";
  const idToken = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!idToken) { const e = new Error("unauthenticated"); e.status = 401; throw e; }
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;
  const snap = await db.collection("users").doc(uid).get();
  if (!snap.exists || snap.get("role") !== "admin") {
    const e = new Error("permission-denied"); e.status = 403; throw e;
  }
  return uid;
}

// Handlers
async function handleCreateUser(data) {
  const { email, password, fullName, role, departmentId } = data || {};
  if (!email || !password || !fullName || !role) {
    const e = new Error("invalid-argument"); e.status = 400; throw e;
  }
  const userRecord = await admin.auth().createUser({
    email, password, displayName: fullName, emailVerified: false, disabled: false,
  });
  const uid = userRecord.uid;
  await db.collection("users").doc(uid).set({
    uid, email, fullName, role,
    departmentId: departmentId || null,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });
  return { uid };
}

async function handleUpdateUser(data) {
  const { uid, email, fullName, role, departmentId } = data || {};
  if (!uid) { const e = new Error("invalid-argument"); e.status = 400; throw e; }

  const authUpdate = {};
  if (email) authUpdate.email = email;
  if (fullName) authUpdate.displayName = fullName;
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  const fsUpdate = {};
  if (email !== undefined) fsUpdate.email = email;
  if (fullName !== undefined) fsUpdate.fullName = fullName;
  if (role !== undefined) fsUpdate.role = role;
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId;
  if (Object.keys(fsUpdate).length) await db.collection("users").doc(uid).set(fsUpdate, { merge: true });

  return { ok: true };
}

async function handleDeleteUser(data) {
  const { uid, cascade } = data || {};
  if (!uid) { const e = new Error("invalid-argument"); e.status = 400; throw e; }

  await db.collection("users").doc(uid).delete().catch(() => {});

  if (cascade) {
    const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
    let batch = db.batch(), count = 0; const commits = [];
    qs.forEach(doc => {
      batch.delete(doc.ref); count++;
      if (count === 400) { commits.push(batch.commit()); batch = db.batch(); count = 0; }
    });
    commits.push(batch.commit());
    await Promise.all(commits);
  }

  await admin.auth().deleteUser(uid);
  return { ok: true };
}

// Endpoint health check (GET /) để Render kiểm tra
app.get("/", (req, res) => res.send("OK"));

app.post("/admin", async (req, res) => {
  try {
    await assertAdminFromIdToken(req);
    const { action, data } = req.body || {};
    if (!action) return res.status(400).json({ error: "missing action" });

    let result;
    if (action === "createUser") result = await handleCreateUser(data);
    else if (action === "updateUser") result = await handleUpdateUser(data);
    else if (action === "deleteUser") result = await handleDeleteUser(data);
    else return res.status(400).json({ error: "unknown action" });

    return res.json(result);
  } catch (e) {
    console.error(e);
    return res.status(e.status || 500).json({ error: e.message || "internal" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

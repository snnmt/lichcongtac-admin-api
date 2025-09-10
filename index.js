// index.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

// --- Init firebase-admin (ENV trên Render) ---
try {
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
    console.log("[BOOT] firebase-admin initialized");
  }
} catch (e) {
  console.error("[BOOT] admin.initializeApp FAILED:", e);
  setTimeout(() => process.exit(1), 1500);
}

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Logging đơn giản
app.use((req, res, next) => {
  res.on("finish", () => {
    if (req.path !== "/health" && req.path !== "/") {
      console.log("[RES]", req.method, req.url, res.statusCode);
    }
  });
  next();
});

// Health check
app.head("/", (req, res) => res.sendStatus(200));
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/health", (req, res) => res.json({ ok: true }));

// --- Helper: chỉ cho admin/superadmin ---
async function assertAdminFromIdToken(req) {
  const h = req.headers.authorization || "";
  const idToken = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!idToken) {
    const err = new Error("unauthenticated");
    err.status = 401;
    throw err;
  }

  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  // Ưu tiên đọc role từ Firestore users/{uid}
  const snap = await db.collection("users").doc(uid).get();
  const roleFS = snap.exists ? snap.get("role") : null;

  // Fallback: role từ custom claims (nếu có)
  const roleClaim = decoded.role;
  const role = roleFS || roleClaim;

  if (!["admin", "superadmin"].includes(role)) {
    const err = new Error("permission-denied");
    err.status = 403;
    throw err;
  }
  return { uid, role };
}

// --- Actions ---
async function handleCreateUser(data) {
  const { email, password, fullName, role, orgId, departmentId } = data || {};
  if (!email || !password || !fullName || !role || !orgId) {
    const err = new Error("invalid-argument");
    err.status = 400;
    err.details = "email, password, fullName, role, orgId là bắt buộc";
    throw err;
  }

  const userRecord = await admin.auth().createUser({
    email,
    password,
    displayName: fullName,
    emailVerified: false,
    disabled: false,
  });
  const uid = userRecord.uid;

  const now = admin.firestore.FieldValue.serverTimestamp();

  await db
    .collection("users")
    .doc(uid)
    .set(
      {
        uid,
        email,
        fullName,
        role,
        orgId,
        departmentId: departmentId || null,
        createdAt: now,
        updatedAt: now,
      },
      { merge: true }
    );

  // set custom claims để client có thể đọc nhanh
  await admin.auth().setCustomUserClaims(uid, { role, orgId });

  return { uid };
}

async function handleUpdateUser(data) {
  const { uid, email, fullName, role, orgId, departmentId, password } = data || {};
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  // Cập nhật Auth
  const authUpdate = {};
  if (email) authUpdate.email = email;
  if (fullName) authUpdate.displayName = fullName;
  if (password) authUpdate.password = password;
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  if (role || orgId) {
    const claims = {};
    if (role) claims.role = role;
    if (orgId) claims.orgId = orgId;
    if (Object.keys(claims).length) await admin.auth().setCustomUserClaims(uid, claims);
  }

  // Cập nhật Firestore
  const fsUpdate = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
  if (email !== undefined) fsUpdate.email = email;
  if (fullName !== undefined) fsUpdate.fullName = fullName;
  if (role !== undefined) fsUpdate.role = role;
  if (orgId !== undefined) fsUpdate.orgId = orgId;
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId || null;

  await db.collection("users").doc(uid).set(fsUpdate, { merge: true });

  return { ok: true };
}

async function handleDeleteUser(data) {
  const { uid, cascade } = data || {};
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  // Xoá Firestore
  await db.collection("users").doc(uid).delete().catch(() => {});
  if (cascade) {
    const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
    let batch = db.batch(),
      count = 0;
    const commits = [];
    qs.forEach((doc) => {
      batch.delete(doc.ref);
      count++;
      if (count === 400) {
        commits.push(batch.commit());
        batch = db.batch();
        count = 0;
      }
    });
    commits.push(batch.commit());
    await Promise.all(commits);
  }

  // Xoá Auth
  await admin.auth().deleteUser(uid);
  return { ok: true };
}

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
    const status = e.status || 500;
    console.error("[/admin] ERROR:", e, e.details || "");
    return res.status(status).json({ error: e.message || "internal", details: e.details });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

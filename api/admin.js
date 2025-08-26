// Vercel serverless function: /api/admin
const admin = require("firebase-admin");

// Khởi tạo admin SDK 1 lần
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

async function assertAdminFromIdToken(idToken) {
  if (!idToken) {
    const err = new Error("unauthenticated");
    err.status = 401;
    throw err;
  }
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;
  const snap = await db.collection("users").doc(uid).get();
  if (!snap.exists || snap.get("role") !== "admin") {
    const err = new Error("permission-denied");
    err.status = 403;
    throw err;
  }
  return uid;
}

async function handleCreateUser(data) {
  const { email, password, fullName, role, departmentId } = data || {};
  if (!email || !password || !fullName || !role) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
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
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  const authUpdate = {};
  if (email) authUpdate.email = email;
  if (fullName) authUpdate.displayName = fullName;
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  const fsUpdate = {};
  if (email !== undefined) fsUpdate.email = email;
  if (fullName !== undefined) fsUpdate.fullName = fullName;
  if (role !== undefined) fsUpdate.role = role;
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId;
  if (Object.keys(fsUpdate).length) {
    await db.collection("users").doc(uid).set(fsUpdate, { merge: true });
  }

  return { ok: true };
}

async function handleDeleteUser(data) {
  const { uid, cascade } = data || {};
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  await db.collection("users").doc(uid).delete().catch(() => {});

  if (cascade) {
    const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
    let batch = db.batch(); let count = 0; const commits = [];
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

module.exports = async (req, res) => {
  // CORS cho web; mobile app không bị CORS nhưng để sẵn
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

  try {
    const authHeader = req.headers.authorization || "";
    const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    await assertAdminFromIdToken(idToken);

    const { action, data } = req.body || {};
    if (!action) return res.status(400).json({ error: "missing action" });

    let result;
    if (action === "createUser") result = await handleCreateUser(data);
    else if (action === "updateUser") result = await handleUpdateUser(data);
    else if (action === "deleteUser") result = await handleDeleteUser(data);
    else return res.status(400).json({ error: "unknown action" });

    return res.status(200).json(result);
  } catch (e) {
    console.error(e);
    return res.status(e.status || 500).json({ error: e.message || "internal" });
  }
};

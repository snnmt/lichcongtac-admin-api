// index.js (Express API – Multi-tenant, admin/superadmin, có orgId & department kiểm tra chéo)

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

// --- Init firebase-admin (từ ENV trên Render) ---
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
  }
} catch (e) {
  console.error("[BOOT] admin.initializeApp FAILED:", e);
  setTimeout(() => process.exit(1), 1500);
}

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json());

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
app.head("/", (_req, res) => res.sendStatus(200));
app.get("/",  (_req, res) => res.status(200).send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Helpers & AuthZ ----------

async function getCallerProfile(uid) {
  const snap = await db.collection("users").doc(uid).get();
  return snap.exists ? snap.data() : null;
}

async function assertAdminFromIdToken(req) {
  const h = req.headers.authorization || "";
  const idToken = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!idToken) {
    const err = new Error("unauthenticated"); err.status = 401; throw err;
  }
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  // Ưu tiên đọc role/orgId từ Firestore; fallback từ custom claims
  const profile = await getCallerProfile(uid);
  const role = profile?.role || decoded.role || decoded.claims?.role;
  const orgId = profile?.orgId || decoded.orgId || decoded.claims?.orgId;

  const isSuperadmin = role === "superadmin";
  const isAdmin = isSuperadmin || role === "admin";

  if (!isAdmin) {
    const err = new Error("permission-denied"); err.status = 403; throw err;
  }
  return { uid, role, orgId, isAdmin, isSuperadmin };
}

async function assertDepartmentBelongsToOrg(departmentId, orgId) {
  if (!departmentId) return true; // cho phép null
  const qs = await db.collection("departments")
    .where("orgId", "==", orgId)
    .where("id", "==", departmentId)   // field id nội bộ = mã phòng ban
    .limit(1)
    .get();
  return !qs.empty;
}

// ---------- Actions ----------

async function handleCreateUser(data, caller) {
  const { email, password, fullName, role, orgId, departmentId } = data || {};

  if (!email || !password || !fullName || !role || !orgId) {
    const err = new Error("invalid-argument: email, password, fullName, role, orgId là bắt buộc");
    err.status = 400; throw err;
  }
  if (!caller.isSuperadmin && caller.orgId !== orgId) {
    const err = new Error("permission-denied: admin chỉ được tạo user trong org của mình");
    err.status = 403; throw err;
  }
  const okDept = await assertDepartmentBelongsToOrg(departmentId, orgId);
  if (!okDept) {
    const err = new Error("invalid-argument: departmentId không thuộc orgId");
    err.status = 400; throw err;
  }

  // Tạo Auth user
  let userRecord;
  try {
    userRecord = await admin.auth().createUser({
      email: String(email).trim().toLowerCase(),
      password: String(password),
      displayName: String(fullName),
      emailVerified: false,
      disabled: false,
    });
  } catch (e) {
    const err = new Error(e.message || "createUser failed");
    err.status = 409; throw err; // already exists/conflict
  }
  const uid = userRecord.uid;

  // Custom claims (hữu ích cho client)
  try {
    await admin.auth().setCustomUserClaims(uid, { role, orgId });
  } catch (e) {
    console.warn("setCustomUserClaims failed:", e.message);
  }

  // Hồ sơ Firestore
  await db.collection("users").doc(uid).set({
    uid,
    email: String(email).trim().toLowerCase(),
    fullName: String(fullName),
    role: String(role),
    orgId: String(orgId),
    departmentId: departmentId || null,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  }, { merge: true });

  return { uid };
}

async function handleUpdateUser(data, caller) {
  const { uid, email, fullName, role, departmentId, password, orgId } = data || {};
  if (!uid) { const err = new Error("invalid-argument: uid là bắt buộc"); err.status = 400; throw err; }

  // Lấy hồ sơ hiện tại để kiểm tra quyền theo org
  const target = await getCallerProfile(uid);
  const targetOrg = target?.orgId || null;

  // Nếu truyền orgId mới -> chỉ superadmin được đổi org; admin bị chặn
  if (orgId && !caller.isSuperadmin) {
    const err = new Error("permission-denied: chỉ superadmin được đổi org của user");
    err.status = 403; throw err;
  }

  // Admin chỉ có thể sửa user trong org của mình
  if (!caller.isSuperadmin && targetOrg && targetOrg !== caller.orgId) {
    const err = new Error("permission-denied: không thể sửa user ngoài org");
    err.status = 403; throw err;
  }

  // Validate department theo org đích (nếu có)
  const finalOrgForCheck = orgId || targetOrg || caller.orgId;
  if (departmentId !== undefined) {
    const okDept = await assertDepartmentBelongsToOrg(departmentId, finalOrgForCheck);
    if (!okDept) {
      const err = new Error("invalid-argument: departmentId không thuộc org hiện tại");
      err.status = 400; throw err;
    }
  }

  // Cập nhật Auth
  const authUpdate = {};
  if (email)    authUpdate.email = String(email).trim().toLowerCase();
  if (fullName) authUpdate.displayName = String(fullName);
  if (password) authUpdate.password = String(password);
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  // Cập nhật claims nếu đổi role/org
  const claims = {};
  if (role) claims.role = String(role);
  if (orgId) claims.orgId = String(orgId);
  if (Object.keys(claims).length) {
    try { await admin.auth().setCustomUserClaims(uid, claims); }
    catch (e) { console.warn("setCustomUserClaims(update) failed:", e.message); }
  }

  // Cập nhật Firestore
  const fsUpdate = {};
  if (email !== undefined)        fsUpdate.email = String(email).trim().toLowerCase();
  if (fullName !== undefined)     fsUpdate.fullName = String(fullName);
  if (role !== undefined)         fsUpdate.role = String(role);
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId || null;
  if (orgId !== undefined)        fsUpdate.orgId = String(orgId);

  if (Object.keys(fsUpdate).length)
    await db.collection("users").doc(uid).set(fsUpdate, { merge: true });

  return { ok: true };
}

async function handleDeleteUser(data, caller) {
  const { uid, cascade } = data || {};
  if (!uid) { const err = new Error("invalid-argument: uid là bắt buộc"); err.status = 400; throw err; }

  const target = await getCallerProfile(uid);
  const targetOrg = target?.orgId || null;
  if (!caller.isSuperadmin && targetOrg && targetOrg !== caller.orgId) {
    const err = new Error("permission-denied: không thể xóa user ngoài org");
    err.status = 403; throw err;
  }

  // Xoá hồ sơ Firestore
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

  // Xoá Auth
  try { await admin.auth().deleteUser(uid); } catch (e) {
    // nếu không tồn tại, bỏ qua
  }
  return { ok: true };
}

// ---------- Router ----------

app.post("/admin", async (req, res) => {
  try {
    const caller = await assertAdminFromIdToken(req);
    const { action, data } = req.body || {};
    if (!action) return res.status(400).json({ error: "missing action" });

    let result;
    if (action === "createUser")      result = await handleCreateUser(data, caller);
    else if (action === "updateUser") result = await handleUpdateUser(data, caller);
    else if (action === "deleteUser") result = await handleDeleteUser(data, caller);
    else return res.status(400).json({ error: "unknown action" });

    return res.json(result);
  } catch (e) {
    console.error("[/admin] ERROR:", e);
    return res.status(e.status || 500).json({ error: e.message || "internal" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

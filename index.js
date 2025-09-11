// index.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

// ====== BOOT ======
function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`[BOOT] Missing ENV ${name}`);
    setTimeout(() => process.exit(1), 1500);
  }
  return v;
}

try {
  if (!admin.apps.length) {
    const privateKey = required("FIREBASE_PRIVATE_KEY").replace(/\\n/g, "\n");
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: required("FIREBASE_PROJECT_ID"),
        clientEmail: required("FIREBASE_CLIENT_EMAIL"),
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

// ====== LOG ======
app.use((req, res, next) => {
  res.on("finish", () => {
    if (!["/health", "/"].includes(req.path)) {
      console.log("[RES]", req.method, req.url, res.statusCode);
    }
  });
  next();
});

// ====== HEALTH ======
app.head("/", (req, res) => res.sendStatus(200));
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/health", (req, res) => res.json({ ok: true }));

// ====== HINT FOR GET /admin ======
app.get("/admin", (req, res) => {
  res.status(405).json({
    error: "method-not-allowed",
    message:
      "Hãy gọi POST /admin với header Authorization: Bearer <idToken> và body JSON.",
  });
});

// ====== AUTHZ HELPER ======
function parseSuperAdmins() {
  const raw = process.env.SUPER_ADMINS || "";
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

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
  const email = (decoded.email || "").toLowerCase();

  // 1) Firestore role/orgId
  let roleFS = null;
  let orgIdFS = null;
  try {
    const snap = await db.collection("users").doc(uid).get();
    if (snap.exists) {
      roleFS = snap.get("role") || null;
      orgIdFS = snap.get("orgId") || null;
    }
  } catch (e) {
    console.warn("[AUTHZ] Read users/{uid} failed:", e?.message || e);
  }

  // 2) Custom claim role/org
  const roleClaim = decoded.role || null;
  const orgClaim = decoded.orgId || null;

  // 3) Bootstrap bằng ENV SUPER_ADMINS (theo email)
  const supers = parseSuperAdmins();
  const isBootstrapSuper = email && supers.includes(email);

  const role = roleFS || roleClaim || (isBootstrapSuper ? "superadmin" : null);
  const orgId = orgIdFS || orgClaim || null;

  if (!["admin", "superadmin"].includes(role)) {
    console.error(
      "[AUTHZ] Denied, uid/email:",
      uid,
      email,
      "roleFS:",
      roleFS,
      "claim:",
      roleClaim
    );
    const err = new Error("permission-denied");
    err.status = 403;
    throw err;
  }

  return { uid, email, role, orgId };
}

// ====== DEBUG WHOAMI ======
app.get("/debug/whoami", async (req, res) => {
  try {
    const me = await assertAdminFromIdToken(req);
    return res.json({ ok: true, me });
  } catch (e) {
    return res.status(e.status || 500).json({ error: e.message || "internal" });
  }
});

// ====== VALIDATION HELPERS ======
async function assertDepartmentBelongsToOrg(departmentId, orgId) {
  if (!departmentId) return null; // optional
  const ref = db.collection("departments").doc(departmentId);
  const snap = await ref.get();
  if (!snap.exists) {
    const err = new Error("department-not-found");
    err.status = 400;
    throw err;
  }
  const data = snap.data() || {};
  if (data.orgId !== orgId) {
    const err = new Error("department-org-mismatch");
    err.status = 400;
    err.details = `Department ${departmentId} không thuộc org ${orgId}`;
    throw err;
  }
  return data;
}

async function getUserDoc(uid) {
  const s = await db.collection("users").doc(uid).get();
  return s.exists ? s.data() : null;
}

// ====== ACTIONS ======
async function handleCreateUser(data, caller) {
  const { email, password, fullName, role, orgId, departmentId } = data || {};
  if (!email || !password || !fullName || !role || !orgId) {
    const err = new Error("invalid-argument");
    err.status = 400;
    err.details = "email, password, fullName, role, orgId là bắt buộc";
    throw err;
  }

  // Admin chỉ được tạo trong org của mình & không tạo superadmin
  if (caller.role === "admin") {
    if (role === "superadmin") {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin không được tạo superadmin";
      throw err;
    }
    if (caller.orgId && orgId !== caller.orgId) {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin chỉ được tạo user trong org của mình";
      throw err;
    }
  }

  // Validate department thuộc org
  await assertDepartmentBelongsToOrg(departmentId, orgId).catch((e) => {
    // Không chặn superadmin nếu muốn bỏ qua kiểm tra phòng ban trống
    if (departmentId) throw e;
  });

  try {
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

    await admin.auth().setCustomUserClaims(uid, { role, orgId });

    console.log("[CREATE_USER] ok", {
      by: caller.email,
      newUid: uid,
      role,
      orgId,
      departmentId,
    });
    return { uid };
  } catch (e) {
    const code = e?.errorInfo?.code || e?.code || "";
    if (code === "auth/email-already-exists") {
      const err = new Error("email-already-exists");
      err.status = 409;
      throw err;
    }
    if (code === "auth/invalid-password") {
      const err = new Error("invalid-password");
      err.status = 400;
      err.details = "Mật khẩu không đạt yêu cầu";
      throw err;
    }
    console.error("[CREATE_USER] failed:", e);
    const err = new Error("internal");
    err.status = 500;
    err.details = e?.message;
    throw err;
  }
}

async function handleUpdateUser(data, caller) {
  const { uid, email, fullName, role, orgId, departmentId, password } = data || {};
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  const target = await getUserDoc(uid);
  if (!target) {
    const err = new Error("user-not-found");
    err.status = 404;
    throw err;
  }

  // Admin chỉ được sửa user cùng org, không gán superadmin
  if (caller.role === "admin") {
    if (target.orgId && caller.orgId && target.orgId !== caller.orgId) {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin chỉ được sửa user trong org của mình";
      throw err;
    }
    if (role === "superadmin") {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin không được gán role superadmin";
      throw err;
    }
    if (orgId && orgId !== caller.orgId) {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin không được chuyển user sang org khác";
      throw err;
    }
  }

  // Xác định org áp dụng để validate department
  const effectiveOrg = orgId || target.orgId || caller.orgId || null;
  await assertDepartmentBelongsToOrg(departmentId, effectiveOrg).catch((e) => {
    if (departmentId) throw e;
  });

  // Auth
  const authUpdate = {};
  if (email) authUpdate.email = email;
  if (fullName) authUpdate.displayName = fullName;
  if (password) authUpdate.password = password;
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  // Claims
  const claimChanges = {};
  if (role) claimChanges.role = role;
  if (orgId) claimChanges.orgId = orgId;
  if (Object.keys(claimChanges).length) await admin.auth().setCustomUserClaims(uid, claimChanges);

  // Firestore
  const fsUpdate = { updatedAt: admin.firestore.FieldValue.serverTimestamp() };
  if (email !== undefined) fsUpdate.email = email;
  if (fullName !== undefined) fsUpdate.fullName = fullName;
  if (role !== undefined) fsUpdate.role = role;
  if (orgId !== undefined) fsUpdate.orgId = orgId;
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId || null;

  await db.collection("users").doc(uid).set(fsUpdate, { merge: true });
  console.log("[UPDATE_USER] ok", {
    by: caller.email,
    uid,
    role: role ?? target.role,
    orgId: orgId ?? target.orgId,
    departmentId: departmentId ?? target.departmentId,
  });
  return { ok: true };
}

async function handleDeleteUser(data, caller) {
  const { uid, cascade } = data || {};
  if (!uid) {
    const err = new Error("invalid-argument");
    err.status = 400;
    throw err;
  }

  const target = await getUserDoc(uid);
  if (!target) {
    const err = new Error("user-not-found");
    err.status = 404;
    throw err;
  }

  if (caller.role === "admin") {
    if (caller.orgId && target.orgId && caller.orgId !== target.orgId) {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin chỉ được xoá user trong org của mình";
      throw err;
    }
    if (target.role === "superadmin") {
      const err = new Error("permission-denied");
      err.status = 403;
      err.details = "admin không được xoá superadmin";
      throw err;
    }
  }

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
    if (count > 0) commits.push(batch.commit());
    await Promise.all(commits);
  }

  await admin.auth().deleteUser(uid);
  console.log("[DELETE_USER] ok", { by: caller.email, uid });
  return { ok: true };
}

// ====== ROUTE ======
app.post("/admin", async (req, res) => {
  try {
    const caller = await assertAdminFromIdToken(req);
    const { action, data } = req.body || {};
    if (!action) return res.status(400).json({ error: "missing action" });

    console.log("[ADMIN]", action, "by", caller.email, "dataKeys:", Object.keys(data || {}));

    let result;
    if (action === "createUser") result = await handleCreateUser(data, caller);
    else if (action === "updateUser") result = await handleUpdateUser(data, caller);
    else if (action === "deleteUser") result = await handleDeleteUser(data, caller);
    else return res.status(400).json({ error: "unknown action" });

    return res.json(result);
  } catch (e) {
    const status = e.status || 500;
    console.error("[/admin] ERROR:", e?.message || e, e?.details || "");
    return res.status(status).json({ error: e.message || "internal", details: e.details });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

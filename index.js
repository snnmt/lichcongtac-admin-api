// index.js
"use strict";

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

/* ----------------------------- INIT ADMIN SDK ----------------------------- */
/* Ưu tiên init bằng 3 ENV biến: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY
   Nếu không đủ, fallback sang ADC (GOOGLE_APPLICATION_CREDENTIALS). */
(function initAdmin() {
  if (admin.apps.length) return;
  try {
    const { FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY } = process.env;

    if (FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY) {
      const privateKey = FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: FIREBASE_PROJECT_ID,
          clientEmail: FIREBASE_CLIENT_EMAIL,
          privateKey,
        }),
      });
      console.log("[BOOT] admin initialized via CERT env.");
    } else {
      admin.initializeApp(); // GOOGLE_APPLICATION_CREDENTIALS / metadata
      console.log("[BOOT] admin initialized via ADC.");
    }
  } catch (e) {
    console.error("[BOOT] admin.initializeApp FAILED:", e);
    setTimeout(() => process.exit(1), 1500);
  }
})();

const db = admin.firestore();

/* ------------------------------ EXPRESS APP ------------------------------ */
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Logging nhẹ
app.use((req, res, next) => {
  const t0 = Date.now();
  res.on("finish", () => {
    if (req.path !== "/" && req.path !== "/health") {
      console.log(
        `[RES] ${req.method} ${req.originalUrl} ${res.statusCode} - ${Date.now() - t0}ms`
      );
    }
  });
  next();
});

// Health check
app.head("/", (req, res) => res.sendStatus(200));
app.get("/", (req, res) => res.status(200).send("OK"));
app.get("/health", (req, res) => res.json({ ok: true }));

/* ------------------------------ AUTH HELPERS ----------------------------- */
async function verifyBearerIdToken(req) {
  const h = req.headers.authorization || "";
  const idToken = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!idToken) {
    const err = new Error("unauthenticated");
    err.status = 401;
    throw err;
  }
  const decoded = await admin.auth().verifyIdToken(idToken);
  return decoded.uid;
}

/** Lấy userInfo trong FS, trả { uid, role, orgId }.
 *  Yêu cầu: user doc phải có role, orgId (theo mẫu app).
 */
async function getActor(uid) {
  const snap = await db.collection("users").doc(uid).get();
  if (!snap.exists) {
    const err = new Error("actor-not-found");
    err.status = 403;
    throw err;
  }
  const role = snap.get("role");
  const orgId = snap.get("orgId");
  if (!role) {
    const err = new Error("no-role");
    err.status = 403;
    throw err;
  }
  return { uid, role, orgId };
}

/** Chỉ cho phép:
 *  - superadmin: mọi thao tác
 *  - admin: chỉ thao tác trong orgId của chính mình
 */
function assertOrgScope(actor, targetOrgId) {
  if (actor.role === "superadmin") return;
  if (!actor.orgId || actor.orgId !== targetOrgId) {
    const err = new Error("permission-denied");
    err.status = 403;
    throw err;
  }
}

/* ------------------------------ VALIDATORS ------------------------------- */
function requireString(v, name) {
  if (!v || typeof v !== "string") {
    const err = new Error(`invalid-${name}`);
    err.status = 400;
    throw err;
  }
  return v.trim();
}

async function assertDepartmentBelongsToOrg(departmentId, orgId) {
  if (!departmentId) return; // optional
  const depDoc = await db.collection("departments").doc(departmentId).get();
  if (!depDoc.exists) {
    const err = new Error("department-not-found");
    err.status = 400;
    throw err;
  }
  const depOrg = depDoc.get("orgId") || depDoc.get("organizationId");
  if (depOrg && depOrg !== orgId) {
    const err = new Error("department-org-mismatch");
    err.status = 400;
    throw err;
  }
}

/* ------------------------------- ACTIONS --------------------------------- */
/** Tạo user Auth + users/{uid} trong đúng org, có thể gán departmentId.
 *  body.data: { email, password, fullName, role, orgId, departmentId? }
 */
async function handleCreateUser(actor, data) {
  const email = requireString(data?.email, "email");
  const password = requireString(data?.password, "password");
  const fullName = requireString(data?.fullName, "fullName");
  const role = requireString(data?.role, "role"); // "member" | "admin" | "superadmin"
  const orgId = requireString(data?.orgId, "orgId");
  const departmentId = data?.departmentId ? String(data.departmentId).trim() : null;

  // admin (thường) chỉ được tạo user trong org của mình
  assertOrgScope(actor, orgId);

  // Không cho admin tạo superadmin
  if (role === "superadmin" && actor.role !== "superadmin") {
    const err = new Error("cannot-create-superadmin");
    err.status = 403;
    throw err;
  }

  await assertDepartmentBelongsToOrg(departmentId, orgId);

  // Tạo Auth
  const userRecord = await admin.auth().createUser({
    email,
    password,
    displayName: fullName,
    emailVerified: false,
    disabled: false,
  });
  const uid = userRecord.uid;

  // Ghi Firestore
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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

  // Custom claims
  await admin.auth().setCustomUserClaims(uid, { role, orgId });

  return { uid };
}

/** Cập nhật thông tin người dùng.
 *  body.data: { uid, email?, fullName?, role?, departmentId?, password?, orgId?* }
 *  - orgId?: chỉ superadmin mới được đổi orgId của người dùng.
 */
async function handleUpdateUser(actor, data) {
  const uid = requireString(data?.uid, "uid");

  // Lấy user hiện tại trong FS để xác định org gốc (scope check)
  const curSnap = await db.collection("users").doc(uid).get();
  if (!curSnap.exists) {
    const err = new Error("user-not-found");
    err.status = 404;
    throw err;
  }
  const curOrgId = curSnap.get("orgId");

  // Admin chỉ được sửa user thuộc org của mình
  assertOrgScope(actor, curOrgId);

  const email = data?.email;
  const fullName = data?.fullName;
  const role = data?.role;
  const departmentId = data?.departmentId;
  const password = data?.password;
  const newOrgId = data?.orgId; // tuỳ chọn: chỉ superadmin

  // Nếu truyền orgId mới -> chỉ superadmin
  if (newOrgId !== undefined) {
    if (actor.role !== "superadmin") {
      const err = new Error("cannot-change-org-as-admin");
      err.status = 403;
      throw err;
    }
    requireString(newOrgId, "orgId");
  }

  if (departmentId !== undefined) {
    const checkDep = departmentId ? String(departmentId).trim() : null;
    const validateOrg = newOrgId !== undefined ? newOrgId : curOrgId;
    await assertDepartmentBelongsToOrg(checkDep, validateOrg);
  }

  // Cập nhật Auth nếu cần
  const authUpdate = {};
  if (email) authUpdate.email = String(email).trim();
  if (fullName) authUpdate.displayName = String(fullName).trim();
  if (password) authUpdate.password = String(password);
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);

  // Cập nhật custom claims nếu thay role hoặc org
  const claimsUpdate = {};
  if (role !== undefined) claimsUpdate.role = role;
  if (newOrgId !== undefined) claimsUpdate.orgId = newOrgId;
  if (Object.keys(claimsUpdate).length)
    await admin.auth().setCustomUserClaims(uid, {
      role: claimsUpdate.role ?? curSnap.get("role"),
      orgId: claimsUpdate.orgId ?? curOrgId,
    });

  // Cập nhật Firestore
  const fsUpdate = {};
  if (email !== undefined) fsUpdate.email = email;
  if (fullName !== undefined) fsUpdate.fullName = fullName;
  if (role !== undefined) fsUpdate.role = role;
  if (departmentId !== undefined) fsUpdate.departmentId = departmentId || null;
  if (newOrgId !== undefined) fsUpdate.orgId = newOrgId;

  if (Object.keys(fsUpdate).length) {
    await db.collection("users").doc(uid).set(fsUpdate, { merge: true });
  }

  return { ok: true };
}

/** Xoá người dùng.
 *  body.data: { uid, cascade? }
 *  - Chỉ xoá được trong org của mình (trừ superadmin).
 *  - cascade: xoá schedules do user tạo (lọc theo createdBy == uid).
 */
async function handleDeleteUser(actor, data) {
  const uid = requireString(data?.uid, "uid");
  const cascade = !!data?.cascade;

  // Scope check
  const snap = await db.collection("users").doc(uid).get();
  if (!snap.exists) {
    const err = new Error("user-not-found");
    err.status = 404;
    throw err;
  }
  const targetOrgId = snap.get("orgId");
  assertOrgScope(actor, targetOrgId);

  // Xoá Firestore user doc
  await db.collection("users").doc(uid).delete().catch(() => {});

  // Xoá lịch (nếu yêu cầu)
  if (cascade) {
    const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
    let batch = db.batch();
    let count = 0;
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

  // Xoá Auth
  await admin.auth().deleteUser(uid);

  return { ok: true };
}

/* ------------------------------- MAIN ROUTE ------------------------------ */
/** POST /admin
 *  headers: Authorization: Bearer <ID_TOKEN>
 *  body: { action: "createUser"|"updateUser"|"deleteUser", data: {...} }
 */
app.post("/admin", async (req, res) => {
  try {
    const actorUid = await verifyBearerIdToken(req);
    const actor = await getActor(actorUid); // { uid, role, orgId }

    const { action, data } = req.body || {};
    if (!action) return res.status(400).json({ error: "missing action" });

    let result;
    if (action === "createUser") {
      result = await handleCreateUser(actor, data);
    } else if (action === "updateUser") {
      result = await handleUpdateUser(actor, data);
    } else if (action === "deleteUser") {
      result = await handleDeleteUser(actor, data);
    } else {
      return res.status(400).json({ error: "unknown action" });
    }

    return res.json(result);
  } catch (e) {
    console.error("[/admin] ERROR:", e);
    return res.status(e.status || 500).json({ error: e.message || "internal" });
  }
});

/* --------------------------- OPTIONAL: LIST USERS ------------------------ */
/** GET /users?orgId=...&departmentId=...
 *  - Chỉ để test/đối soát; app có thể không dùng endpoint này.
 *  - admin chỉ xem được org của mình, superadmin xem được mọi org.
 */
app.get("/users", async (req, res) => {
  try {
    const actorUid = await verifyBearerIdToken(req);
    const actor = await getActor(actorUid);

    const orgId = requireString(req.query.orgId, "orgId");
    const departmentId = req.query.departmentId ? String(req.query.departmentId).trim() : null;

    assertOrgScope(actor, orgId);

    let q = db.collection("users").where("orgId", "==", orgId);
    if (departmentId) q = q.where("departmentId", "==", departmentId);
    const qs = await q.orderBy("fullName").get();

    const users = qs.docs.map((d) => {
      const x = d.data();
      return {
        uid: d.id,
        email: x.email || "",
        fullName: x.fullName || "",
        role: x.role || "member",
        orgId: x.orgId || null,
        departmentId: x.departmentId || null,
      };
    });

    res.json({ users });
  } catch (e) {
    console.error("[/users] ERROR:", e);
    res.status(e.status || 500).json({ error: e.message || "internal" });
  }
});

/* ------------------------------- START APP ------------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

// index.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

const app = express();
app.use(cors({ origin: "*"}));
app.use(bodyParser.json({ limit: "1mb" }));

// ===== ENV =====
const {
  FIREBASE_PROJECT_ID,
  FIREBASE_CLIENT_EMAIL,
  FIREBASE_PRIVATE_KEY,
  SUPER_ADMINS = "",
  PORT = 3000,
} = process.env;

if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) {
  console.error("[BOOT] Missing Firebase envs");
  process.exit(1);
}

// ===== Firebase Admin init =====
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: (FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
  });
}
const db = admin.firestore();
const auth = admin.auth();

const SUPER_ADMIN_EMAILS = SUPER_ADMINS
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// ===== Helpers =====
app.get("/", (_req, res) => res.type("text").send("lichcongtac-admin-api is running"));
app.get("/ping", (_req, res) => res.json({ ok: true, ts: Date.now() }));

async function authMiddleware(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    if (!hdr.startsWith("Bearer ")) {
      return res.status(401).json({ error: "missing bearer token" });
    }
    const idToken = hdr.slice("Bearer ".length);
    const decoded = await auth.verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: "invalid token", details: String(e) });
  }
}

// Chuẩn hoá vai trò hiệu lực: đọc profile, nếu email thuộc SUPER_ADMINS thì coi là superadmin
async function requireAdmin(req, res, next) {
  try {
    const uid = req.user.uid;
    const email = (req.user.email || "").toLowerCase();
    const isSuperByEmail = SUPER_ADMIN_EMAILS.includes(email);

    const meSnap = await db.collection("users").doc(uid).get();
    const profile = meSnap.exists ? (meSnap.data() || {}) : {};
    const roleDb = (profile.role || "").toLowerCase();

    const roleEffective = isSuperByEmail ? "superadmin" : roleDb; // ưu tiên qua env
    const isAdminEffective =
      roleEffective === "admin" || roleEffective === "superadmin";

    if (!isAdminEffective) {
      return res.status(403).json({ error: "forbidden" });
    }

    // gắn thông tin đã chuẩn hoá cho downstream
    req.me = {
      ...profile,
      email,
      roleEffective,
      isSuper: roleEffective === "superadmin",
    };
    return next();
  } catch (e) {
    return res.status(500).json({ error: "auth check failed", details: String(e) });
  }
}

app.get("/health", authMiddleware, (_req, res) => res.json({ ok: true }));

// ===== Core handler dùng cho /admin & /admin/:action =====
async function adminHandler(req, res) {
  const action =
    (req.params.action || (req.body || {}).action || req.query.action || "").trim();
  const data = (req.body || {}).data || {};
  console.log("[ADMIN]", { action, by: req.user?.email, dataKeys: Object.keys(data) });

  try {
    // ---- CREATE USER ----
    if (action === "createUser") {
      const { email, password, fullName, role, orgId, departmentId } = data || {};
      if (!email || !password || !fullName || !role || !orgId) {
        return res.status(400).json({ error: "missing fields" });
      }

      // chỉ admin mới bị ràng buộc org; superadmin thì bỏ qua
      if (!req.me.isSuper) {
        const myOrgId = req.me.orgId;
        if (!myOrgId || orgId !== myOrgId) {
          return res.status(403).json({ error: "admin can only create in own org" });
        }
      }

      const userRecord = await auth.createUser({
        email,
        password,
        displayName: fullName,
        emailVerified: false,
        disabled: false,
      });

      const payload = {
        uid: userRecord.uid,
        email,
        fullName,
        role: (role || "user").toLowerCase(),
        orgId,
        departmentId: departmentId || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      await db.collection("users").doc(userRecord.uid).set(payload, { merge: true });
      return res.json({ uid: userRecord.uid });
    }

    // ---- UPDATE USER PROFILE/EMAIL/NAME ----
    if (action === "updateUser") {
      const { uid, ...rest } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });

      // chỉ admin mới bị ràng buộc org; superadmin bỏ qua
      if (!req.me.isSuper && rest.orgId) {
        if (!req.me.orgId || rest.orgId !== req.me.orgId) {
          return res.status(403).json({ error: "admin can only move within own org" });
        }
      }

      await db.collection("users").doc(uid).set(rest, { merge: true });
      try {
        if (rest.fullName) await auth.updateUser(uid, { displayName: rest.fullName });
        if (rest.email) await auth.updateUser(uid, { email: rest.email });
      } catch (_) {}
      return res.json({ ok: true });
    }

    // ---- RESET PASSWORD (alias) ----
    if (["setPassword", "resetPassword", "adminResetPassword"].includes(action)) {
      const { uid, password, newPassword } = data || {};
      const pwd = password || newPassword;
      if (!uid || !pwd) return res.status(400).json({ error: "missing uid/password" });

      const targetSnap = await db.collection("users").doc(uid).get();

      if (!req.me.isSuper) {
        // admin: phải cùng org với target nếu target có profile
        if (targetSnap.exists) {
          const target = targetSnap.data() || {};
          if (!req.me.orgId || target.orgId !== req.me.orgId) {
            return res.status(403).json({ error: "admin can only reset password within own org" });
          }
        } else {
          // target chưa có profile: admin thường không được phép
          return res.status(403).json({ error: "only superadmin can reset users without profile" });
        }
      }

      try {
        await auth.updateUser(uid, { password: pwd });
        return res.json({ ok: true });
      } catch (e) {
        const code = e?.code || "";
        if (String(code).includes("auth/user-not-found")) {
          return res.status(404).json({ error: "auth user not found" });
        }
        return res.status(500).json({ error: "updateUser failed", details: String(e?.message || e) });
      }
    }

    // ---- DELETE USER ----
    if (action === "deleteUser") {
      const { uid, cascade } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });

      await db.collection("users").doc(uid).delete();
      try { await auth.deleteUser(uid); } catch (_) {}

      if (cascade) {
        const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
        const batch = db.batch();
        qs.forEach(d => batch.delete(d.ref));
        await batch.commit();
      }
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: "unknown action" });
  } catch (e) {
    console.error("[ADMIN ERROR]", e);
    return res.status(500).json({ error: "server error", details: String(e) });
  }
}

// Nhận cả dạng body action lẫn path action
app.post("/admin", authMiddleware, requireAdmin, adminHandler);
app.post("/admin/:action", authMiddleware, requireAdmin, adminHandler);

// Kéo dài timeout tránh cold-start cắt sớm
const server = app.listen(PORT, () => {
  console.log("Admin API listening on", server.address().port);
});
server.setTimeout(120000);

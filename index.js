// index.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

const app = express();
app.use(cors({ origin: "*"}));
app.use(bodyParser.json({ limit: "1mb" }));

// ----- Firebase Admin init -----
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

// ----- tiện ích -----
app.get("/", (_req, res) => res.type("text").send("lichcongtac-admin-api is running"));
app.get("/ping", (_req, res) => res.json({ ok: true, ts: Date.now() })); // wake

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

async function requireAdmin(req, res, next) {
  try {
    const uid = req.user.uid;
    const meDoc = await db.collection("users").doc(uid).get();
    const profile = meDoc.exists ? meDoc.data() : {};
    const role = (profile.role || "").toLowerCase();
    const email = (req.user.email || "").toLowerCase();

    if (role === "superadmin" || role === "admin" || SUPER_ADMIN_EMAILS.includes(email)) {
      req.me = profile;
      return next();
    }
    return res.status(403).json({ error: "forbidden" });
  } catch (e) {
    return res.status(500).json({ error: "auth check failed", details: String(e) });
  }
}

app.get("/health", authMiddleware, (_req, res) => res.json({ ok: true }));

// ----- handler lõi dùng lại cho /admin và /admin/:action -----
async function adminHandler(req, res) {
  const action = (req.params.action || (req.body || {}).action || req.query.action || "").trim();
  const data = (req.body || {}).data || {};
  console.log("[ADMIN]", { action, by: req.user?.email, dataKeys: Object.keys(data) });

  try {
    // ---- Tạo user ----
    if (action === "createUser") {
      const { email, password, fullName, role, orgId, departmentId } = data || {};
      if (!email || !password || !fullName || !role || !orgId) {
        return res.status(400).json({ error: "missing fields" });
      }
      const myRole = (req.me.role || "").toLowerCase();
      const myOrgId = req.me.orgId;
      if (myRole !== "superadmin" && orgId !== myOrgId) {
        return res.status(403).json({ error: "admin can only create in own org" });
      }
      const userRecord = await auth.createUser({
        email, password, displayName: fullName, emailVerified: false, disabled: false,
      });
      const payload = {
        uid: userRecord.uid, email, fullName,
        role: (role || "user").toLowerCase(),
        orgId, departmentId: departmentId || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      await db.collection("users").doc(userRecord.uid).set(payload, { merge: true });
      return res.json({ uid: userRecord.uid });
    }

    // ---- Cập nhật hồ sơ / email / tên hiển thị ----
    if (action === "updateUser") {
      const { uid, ...rest } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });
      if (rest.orgId) {
        const myRole = (req.me.role || "").toLowerCase();
        if (myRole !== "superadmin" && rest.orgId !== req.me.orgId) {
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

    // ---- Đổi mật khẩu (nhiều alias) ----
    if (["setPassword", "resetPassword", "adminResetPassword"].includes(action)) {
      const { uid, password, newPassword } = data || {};
      const pwd = password || newPassword;
      if (!uid || !pwd) return res.status(400).json({ error: "missing uid/password" });

      const myRole = (req.me.role || "").toLowerCase();
      const myOrg  = req.me.orgId || null;

      // Cho phép user tạo trực tiếp trên điện thoại:
      // - Nếu có profile Firestore: kiểm tra org như cũ.
      // - Nếu KHÔNG có profile: chỉ cho SUPERADMIN đặt lại (admin thường bị chặn vì không xác thực được org).
      const targetDoc = await db.collection("users").doc(uid).get();
      if (targetDoc.exists) {
        const target = targetDoc.data() || {};
        if (myRole === "admin" && (!myOrg || target.orgId !== myOrg)) {
          return res.status(403).json({ error: "admin can only reset password within own org" });
        }
      } else if (myRole !== "superadmin" && !SUPER_ADMIN_EMAILS.includes((req.user.email || "").toLowerCase())) {
        return res.status(403).json({ error: "only superadmin can reset password for users without profile" });
      }

      try {
        await auth.updateUser(uid, { password: pwd });
        return res.json({ ok: true });
      } catch (e) {
        const s = String(e && e.code ? e.code : e);
        if (s.includes("auth/user-not-found")) return res.status(404).json({ error: "auth user not found" });
        return res.status(500).json({ error: "updateUser failed", details: String(e?.message || e) });
      }
    }

    // ---- Xoá user ----
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

    // ---- Không khớp action ----
    return res.status(400).json({ error: "unknown action" });
  } catch (e) {
    console.error("[ADMIN ERROR]", e);
    return res.status(500).json({ error: "server error", details: String(e) });
  }
}

// Nhận cả dạng body action lẫn path action:
app.post("/admin", authMiddleware, requireAdmin, adminHandler);
app.post("/admin/:action", authMiddleware, requireAdmin, adminHandler);

// Kéo dài timeout tránh cold-start cắt sớm
const server = app.listen(PORT, () => {
  console.log("Admin API listening on", server.address().port);
});
server.setTimeout(120000);

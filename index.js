// index.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
  });
}
const db = admin.firestore();

const SUPER_ADMINS = (process.env.SUPER_ADMINS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// ===== NEW: public ping to warm server =====
app.get("/ping", (_req, res) => res.json({ ok: true, ts: Date.now() }));

async function authMiddleware(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    if (!hdr.startsWith("Bearer ")) return res.status(401).json({ error: "missing bearer token" });
    const idToken = hdr.slice("Bearer ".length);
    const decoded = await admin.auth().verifyIdToken(idToken);
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

    if (role === "superadmin" || role === "admin" || SUPER_ADMINS.includes(email)) {
      req.me = profile;
      return next();
    }
    return res.status(403).json({ error: "forbidden" });
  } catch (e) {
    return res.status(500).json({ error: "auth check failed", details: String(e) });
  }
}

// Health (có auth)
app.get("/health", authMiddleware, (_req, res) => res.json({ ok: true }));

app.post("/admin", authMiddleware, requireAdmin, async (req, res) => {
  const { action, data } = req.body || {};
  console.log("[ADMIN] action =", action, "by", req.user?.email);

  try {
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
      const userRecord = await admin.auth().createUser({
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
        if (rest.fullName) await admin.auth().updateUser(uid, { displayName: rest.fullName });
        if (rest.email) await admin.auth().updateUser(uid, { email: rest.email });
      } catch (_) {}
      return res.json({ ok: true });
    }

    // Accept multiple aliases to avoid mismatch
    if (action === "setPassword" || action === "resetPassword" || action === "adminResetPassword") {
      const { uid, password, newPassword } = data || {};
      const pwd = password || newPassword;
      if (!uid || !pwd) return res.status(400).json({ error: "missing uid/password" });

      const myRole = (req.me.role || "").toLowerCase();
      const myOrg  = req.me.orgId || null;

      const targetDoc = await db.collection("users").doc(uid).get();
      if (!targetDoc.exists) return res.status(404).json({ error: "user profile not found in Firestore" });
      const target = targetDoc.data() || {};
      if (myRole === "admin" && (!myOrg || target.orgId !== myOrg)) {
        return res.status(403).json({ error: "admin can only reset password within own org" });
      }

      try {
        await admin.auth().updateUser(uid, { password: pwd });
        return res.json({ ok: true });
      } catch (e) {
        const s = String(e);
        if (s.includes("auth/user-not-found")) return res.status(404).json({ error: "auth user not found" });
        return res.status(500).json({ error: "updateUser failed", details: s });
      }
    }

    if (action === "deleteUser") {
      const { uid, cascade } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });
      await db.collection("users").doc(uid).delete();
      try { await admin.auth().deleteUser(uid); } catch (_) {}
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
    console.error(e);
    return res.status(500).json({ error: "server error", details: String(e) });
  }
});

const server = app.listen(process.env.PORT || 3000, () => {
  console.log("Admin API listening on", server.address().port);
});
server.setTimeout(120000);

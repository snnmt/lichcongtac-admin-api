const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

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
  setTimeout(() => process.exit(1), 2000);
}

const db = admin.firestore();
const app = express();
app.use(cors());
app.use(express.json());

// Health check
app.head("/", (req, res) => res.status(200).end());
app.get("/", (req, res) => res.status(200).send("OK"));

// ... giữ nguyên /admin như bạn đã có ...

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Admin API listening on", PORT));

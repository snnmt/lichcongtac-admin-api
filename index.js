// functions/index.js
const functions = require("firebase-functions");
const admin = require("firebase-admin");

try { admin.app(); } catch (e) { admin.initializeApp(); }
const db = admin.firestore();

/**
 * Payload: { email, password, fullName, role, orgId, departmentId }
 * Yêu cầu:
 *  - Caller phải đăng nhập.
 *  - superadmin: tạo user cho bất kỳ org.
 *  - admin: chỉ tạo user trong org của chính mình.
 * Kết quả: { uid }
 */
exports.adminCreateUser = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError("unauthenticated", "Bạn cần đăng nhập.");
  }

  const email = (data.email || "").trim().toLowerCase();
  const password = (data.password || "").trim();
  const fullName = (data.fullName || "").trim();
  const role = (data.role || "user").trim();
  const orgId = (data.orgId || "").trim();
  const departmentId = (data.departmentId || null);

  if (!email || !password || !fullName || !orgId) {
    throw new functions.https.HttpsError("invalid-argument", "Thiếu tham số bắt buộc.");
  }

  // Lấy hồ sơ caller để kiểm tra quyền + org
  const callerUid = context.auth.uid;
  const callerDoc = await db.collection("users").doc(callerUid).get();
  if (!callerDoc.exists) {
    throw new functions.https.HttpsError("permission-denied", "Không tìm thấy hồ sơ của bạn.");
  }
  const caller = callerDoc.data();
  const callerRole = caller.role || "user";
  const callerOrg = caller.orgId;

  const isSuper = callerRole === "superadmin";
  const isAdmin = isSuper || callerRole === "admin";
  if (!isAdmin) {
    throw new functions.https.HttpsError("permission-denied", "Bạn không có quyền tạo người dùng.");
  }
  if (!isSuper && callerOrg !== orgId) {
    throw new functions.https.HttpsError("permission-denied", "Admin chỉ được tạo trong tổ chức của mình.");
  }

  // Tạo Auth user
  let userRecord;
  try {
    userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: fullName,
      disabled: false
    });
  } catch (e) {
    // nếu user đã tồn tại, có thể trả lỗi cụ thể
    throw new functions.https.HttpsError("already-exists", e.message);
  }

  const uid = userRecord.uid;

  // (Tuỳ chọn) set custom claims cho nhanh trong client (không bắt buộc vì rules đọc từ users/{uid})
  try {
    await admin.auth().setCustomUserClaims(uid, {
      orgId: orgId,
      role: role
    });
  } catch (e) {
    console.warn("setCustomUserClaims fail", e);
  }

  // Tạo hồ sơ Firestore
  const userDoc = {
    uid,
    email,
    fullName,
    role: role || "user",
    orgId,
    departmentId: departmentId || null,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  };

  await db.collection("users").doc(uid).set(userDoc, { merge: true });

  return { uid };
});

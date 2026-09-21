const { onCall, onRequest } = require("firebase-functions/v2/https");
const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();

const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

/*
 * TrackFlow backend
 *
 * Important:
 * - Financial values are calculated server-side.
 * - Client cannot create clicks/conversions/withdrawals directly.
 * - Affiliate-network tracking/postback parameters are intentionally NOT guessed.
 * - Configure the real network integration only after the network's documentation
 *   is available.
 */

const POSTBACK_SECRET = defineSecret("TRACKFLOW_POSTBACK_SECRET");

const ROLES = ["Pending", "Admin", "Publisher", "Creator"];
const OFFER_STATUSES = ["Active", "Inactive"];
const ASSIGNMENT_STATUSES = ["Active", "Inactive"];
const CONVERSION_STATUSES = ["Approved", "Reversed", "Declined"];

function requireAuth(request) {
  if (!request.auth) {
    throw new Error("Authentication required.");
  }
}

async function getUser(uid) {
  const snap = await db.collection("users").doc(uid).get();

  if (!snap.exists) {
    throw new Error("User profile not found.");
  }

  return {
    id: uid,
    ...snap.data()
  };
}

async function requireRole(uid, allowedRoles) {
  const user = await getUser(uid);

  if (!allowedRoles.includes(user.role)) {
    throw new Error("Permission denied.");
  }

  return user;
}

function cleanString(value, maxLength = 500) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().slice(0, maxLength);
}

function positiveNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number) || number < 0) {
    throw new Error("Invalid numeric value.");
  }

  return number;
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function deterministicAssignmentId(offerId, creatorId) {
  return `${offerId}_${creatorId}`;
}

function serverTimestamp() {
  return FieldValue.serverTimestamp();
}

/* =========================================================
   PROFILE
   ========================================================= */

exports.ensureMyProfile = onCall(async (request) => {
  requireAuth(request);

  const uid = request.auth.uid;
  const userRef = db.collection("users").doc(uid);
  const userSnap = await userRef.get();

  if (userSnap.exists) {
    return {
      success: true,
      created: false,
      user: {
        id: uid,
        ...userSnap.data()
      }
    };
  }

  /*
   * A newly authenticated user can only become Pending.
   * Admin/Publisher/Creator roles must be assigned by trusted backend logic.
   */
  const profile = {
    uid,
    email: request.auth.token.email || "",
    displayName: request.auth.token.name || "",
    photoURL: request.auth.token.picture || "",
    role: "Pending",
    earnings: 0,
    reservedEarnings: 0,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  };

  await userRef.create(profile);

  return {
    success: true,
    created: true,
    user: {
      id: uid,
      ...profile
    }
  };
});


/* =========================================================
   ADMIN - USER ROLE
   ========================================================= */

exports.setUserRole = onCall(async (request) => {
  requireAuth(request);

  const adminUser = await requireRole(request.auth.uid, ["Admin"]);

  const data = request.data || {};

  const userId = cleanString(data.userId, 150);
  const role = cleanString(data.role, 50);
  const publisherId = cleanString(data.publisherId, 150);

  if (!userId) {
    throw new Error("userId is required.");
  }

  if (!ROLES.includes(role)) {
    throw new Error("Invalid role.");
  }

  const targetRef = db.collection("users").doc(userId);
  const targetSnap = await targetRef.get();

  if (!targetSnap.exists) {
    throw new Error("Target user does not exist.");
  }

  const target = targetSnap.data();

  /*
   * Prevent removing the final Admin.
   */
  if (target.role === "Admin" && role !== "Admin") {
    const admins = await db
      .collection("users")
      .where("role", "==", "Admin")
      .limit(2)
      .get();

    if (admins.size <= 1) {
      throw new Error("At least one Admin must remain.");
    }
  }

  let update = {
    role,
    updatedAt: serverTimestamp()
  };

  if (role === "Creator") {
    if (!publisherId) {
      throw new Error("publisherId is required for a Creator.");
    }

    const publisherRef = db.collection("users").doc(publisherId);
    const publisherSnap = await publisherRef.get();

    if (!publisherSnap.exists) {
      throw new Error("Publisher does not exist.");
    }

    if (publisherSnap.data().role !== "Publisher") {
      throw new Error("Selected publisher is not a Publisher.");
    }

    update.publisherId = publisherId;
  } else {
    update.publisherId = FieldValue.delete();
  }

  await targetRef.update(update);

  return {
    success: true,
    updatedBy: adminUser.id,
    userId,
    role
  };
});


/* =========================================================
   MASTER OFFERS
   ========================================================= */

exports.createMasterOffer = onCall(async (request) => {
  requireAuth(request);

  await requireRole(request.auth.uid, ["Admin"]);

  const data = request.data || {};

  const title = cleanString(data.offerTitle, 200);
  const trackingLink = cleanString(data.networkTrackingLink, 2000);
  const networkPayout = positiveNumber(data.networkPayout);
  const goal = cleanString(data.goal, 500);
  const status = cleanString(data.status || "Active", 30);

  if (!title) {
    throw new Error("Offer Title is required.");
  }

  if (!trackingLink) {
    throw new Error("Network Tracking Link is required.");
  }

  if (!goal) {
    throw new Error("Goal / Conversion Event is required.");
  }

  if (!OFFER_STATUSES.includes(status)) {
    throw new Error("Invalid offer status.");
  }

  /*
   * Master Offer intentionally contains ONLY:
   * 1. Offer Title
   * 2. Network Tracking Link
   * 3. Network Payout
   * 4. Goal / Conversion Event
   * 5. Status
   */

  const offerRef = db.collection("masterOffers").doc();

  await offerRef.set({
    offerTitle: title,
    networkTrackingLink: trackingLink,
    networkPayout,
    goal,
    status,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
    createdBy: request.auth.uid
  });

  return {
    success: true,
    offerId: offerRef.id
  };
});


exports.updateMasterOffer = onCall(async (request) => {
  requireAuth(request);

  await requireRole(request.auth.uid, ["Admin"]);

  const data = request.data || {};

  const offerId = cleanString(data.offerId, 150);

  if (!offerId) {
    throw new Error("offerId is required.");
  }

  const offerRef = db.collection("masterOffers").doc(offerId);
  const offerSnap = await offerRef.get();

  if (!offerSnap.exists) {
    throw new Error("Offer not found.");
  }

  const update = {};

  if (data.offerTitle !== undefined) {
    const title = cleanString(data.offerTitle, 200);

    if (!title) {
      throw new Error("Offer Title cannot be empty.");
    }

    update.offerTitle = title;
  }

  if (data.networkTrackingLink !== undefined) {
    const link = cleanString(data.networkTrackingLink, 2000);

    if (!link) {
      throw new Error("Network Tracking Link cannot be empty.");
    }

    update.networkTrackingLink = link;
  }

  if (data.networkPayout !== undefined) {
    update.networkPayout = positiveNumber(data.networkPayout);
  }

  if (data.goal !== undefined) {
    const goal = cleanString(data.goal, 500);

    if (!goal) {
      throw new Error("Goal / Conversion Event cannot be empty.");
    }

    update.goal = goal;
  }

  if (data.status !== undefined) {
    const status = cleanString(data.status, 30);

    if (!OFFER_STATUSES.includes(status)) {
      throw new Error("Invalid offer status.");
    }

    update.status = status;
  }

  if (Object.keys(update).length === 0) {
    throw new Error("Nothing to update.");
  }

  update.updatedAt = serverTimestamp();

  await offerRef.update(update);

  return {
    success: true,
    offerId
  };
});


/* =========================================================
   ASSIGNMENT
   ========================================================= */

exports.getActiveOffersForAssignment = onCall(async (request) => {
  requireAuth(request);

  await requireRole(request.auth.uid, ["Admin", "Publisher"]);

  const snap = await db
    .collection("masterOffers")
    .where("status", "==", "Active")
    .get();

  const offers = [];

  snap.forEach((doc) => {
    const data = doc.data();

    /*
     * Network tracking link is sensitive.
     * Do not expose it to publishers/creators through this response.
     */
    offers.push({
      id: doc.id,
      offerTitle: data.offerTitle,
      networkPayout: data.networkPayout,
      goal: data.goal,
      status: data.status
    });
  });

  return {
    success: true,
    offers
  };
});


exports.assignOffer = onCall(async (request) => {
  requireAuth(request);

  const actor = await requireRole(request.auth.uid, ["Admin", "Publisher"]);

  const data = request.data || {};

  const offerId = cleanString(data.offerId, 150);
  const creatorId = cleanString(data.creatorId, 150);
  const creatorPayout = positiveNumber(data.creatorPayout);

  if (!offerId || !creatorId) {
    throw new Error("offerId and creatorId are required.");
  }

  const offerRef = db.collection("masterOffers").doc(offerId);
  const creatorRef = db.collection("users").doc(creatorId);

  const [offerSnap, creatorSnap] = await Promise.all([
    offerRef.get(),
    creatorRef.get()
  ]);

  if (!offerSnap.exists) {
    throw new Error("Offer not found.");
  }

  if (!creatorSnap.exists) {
    throw new Error("Creator not found.");
  }

  const offer = offerSnap.data();
  const creator = creatorSnap.data();

  if (offer.status !== "Active") {
    throw new Error("Offer is inactive.");
  }

  if (creator.role !== "Creator") {
    throw new Error("Selected user is not a Creator.");
  }

  /*
   * Publisher can assign only to their own Creator.
   * publisherId is read from the trusted Creator document.
   */
  if (actor.role === "Publisher") {
    if (creator.publisherId !== actor.id) {
      throw new Error("This Creator does not belong to the Publisher.");
    }
  }

  if (creatorPayout > Number(offer.networkPayout)) {
    throw new Error("Creator payout cannot exceed network payout.");
  }

  const assignmentId = deterministicAssignmentId(
    offerId,
    creatorId
  );

  const assignmentRef = db
    .collection("assignments")
    .doc(assignmentId);

  const existingSnap = await assignmentRef.get();

  const publisherId =
    creator.publisherId || null;

  const assignmentData = {
    offerId,
    creatorId,
    publisherId,
    offerTitle: offer.offerTitle,
    goal: offer.goal,
    networkPayout: Number(offer.networkPayout),
    creatorPayout,
    status: "Active",
    updatedAt: serverTimestamp()
  };

  if (!existingSnap.exists) {
    assignmentData.createdAt = serverTimestamp();
  }

  await assignmentRef.set(
    assignmentData,
    { merge: true }
  );

  return {
    success: true,
    assignmentId,
    trackingUrl: null,
    message:
      "Assignment created. Tracking URL is generated by the trusted tracking endpoint."
  };
});


/* =========================================================
   DASHBOARD
   ========================================================= */

exports.getDashboard = onCall(async (request) => {
  requireAuth(request);

  const user = await getUser(request.auth.uid);

  if (!["Admin", "Publisher", "Creator"].includes(user.role)) {
    throw new Error("Dashboard is not available for Pending users.");
  }

  let conversionsQuery = db.collection("conversions");

  if (user.role === "Publisher") {
    conversionsQuery = conversionsQuery
      .where("publisherId", "==", user.id);
  }

  if (user.role === "Creator") {
    conversionsQuery = conversionsQuery
      .where("creatorId", "==", user.id);
  }

  const conversionsSnap = await conversionsQuery.get();

  let approvedConversions = 0;
  let networkRevenue = 0;
  let creatorEarnings = 0;

  conversionsSnap.forEach((doc) => {
    const conversion = doc.data();

    if (conversion.status === "Approved") {
      approvedConversions += 1;
      networkRevenue += Number(conversion.networkPayout || 0);
      creatorEarnings += Number(conversion.creatorPayout || 0);
    }
  });

  let clicks = 0;

  /*
   * Click documents are backend-only.
   * Count them only for Admin to avoid exposing raw click data.
   */
  if (user.role === "Admin") {
    const clickSnap = await db.collection("clicks").get();
    clicks = clickSnap.size;
  }

  const margin = networkRevenue - creatorEarnings;

  return {
    success: true,
    role: user.role,
    clicks,
    approvedConversions,
    networkRevenue,
    creatorEarnings,
    margin,
    earnings: Number(user.earnings || 0),
    reservedEarnings: Number(user.reservedEarnings || 0)
  };
});


/* =========================================================
   TRACKING ENDPOINT
   ========================================================= */

exports.track = onRequest(async (req, res) => {
  try {
    if (req.method !== "GET") {
      return res.status(405).send("Method Not Allowed");
    }

    const assignmentId = cleanString(
      req.query.assignmentId,
      300
    );

    if (!assignmentId) {
      return res.status(400).send("Missing assignmentId.");
    }

    const assignmentRef = db
      .collection("assignments")
      .doc(assignmentId);

    const assignmentSnap = await assignmentRef.get();

    if (!assignmentSnap.exists) {
      return res.status(404).send("Assignment not found.");
    }

    const assignment = assignmentSnap.data();

    if (assignment.status !== "Active") {
      return res.status(410).send("Campaign inactive.");
    }

    const offerRef = db
      .collection("masterOffers")
      .doc(assignment.offerId);

    const offerSnap = await offerRef.get();

    if (!offerSnap.exists) {
      return res.status(404).send("Offer not found.");
    }

    const offer = offerSnap.data();

    if (offer.status !== "Active") {
      return res.status(410).send("Offer inactive.");
    }

    const clickRef = db.collection("clicks").doc();

    await clickRef.set({
      assignmentId,
      offerId: assignment.offerId,
      creatorId: assignment.creatorId,
      publisherId: assignment.publisherId || null,
      createdAt: serverTimestamp(),
      userAgent: String(req.get("user-agent") || "").slice(0, 1000),
      referrer: String(req.get("referer") || "").slice(0, 1000),
      ipHash: sha256(
        String(req.ip || "")
      )
    });

    /*
     * IMPORTANT:
     *
     * We intentionally do NOT append a guessed click-id macro
     * to the network URL.
     *
     * The real affiliate network's documentation must define:
     * - click ID parameter/macro
     * - transaction ID
     * - postback parameters
     * - authentication/signature
     *
     * Until those values are configured, do not pretend the
     * network integration is live.
     */

    if (!offer.networkTrackingLink) {
      return res.status(503).send(
        "Tracking integration is not configured."
      );
    }

    /*
     * This redirect currently uses the exact saved network URL.
     * If the network requires a click ID parameter, configure
     * that parameter from the network documentation before
     * enabling production tracking.
     */
    return res.redirect(302, offer.networkTrackingLink);

  } catch (error) {
    console.error("TRACK ERROR:", error);
    return res.status(500).send("Tracking error.");
  }
});


/* =========================================================
   POSTBACK / S2S
   ========================================================= */

exports.postback = onRequest(
  {
    secrets: [POSTBACK_SECRET]
  },
  async (req, res) => {
    try {
      if (req.method !== "GET" && req.method !== "POST") {
        return res.status(405).send("Method Not Allowed");
      }

      const configuredSecret = POSTBACK_SECRET.value();

      if (!configuredSecret) {
        return res.status(503).send(
          "Postback integration is not configured."
        );
      }

      /*
       * Secret should be supplied in a header.
       * Example:
       * x-trackflow-secret: YOUR_SECRET
       *
       * Do NOT put secrets in public query parameters.
       */
      const suppliedSecret =
        req.get("x-trackflow-secret") || "";

      if (suppliedSecret !== configuredSecret) {
        return res.status(401).send("Unauthorized.");
      }

      const body = req.body || {};

      /*
       * These names are intentionally generic.
       * Replace them only after receiving the actual affiliate
       * network's postback documentation.
       */
      const transactionId = cleanString(
        body.transactionId || req.query.transactionId,
        500
      );

      const clickId = cleanString(
        body.clickId || req.query.clickId,
        500
      );

      const status = cleanString(
        body.status || req.query.status,
        50
      );

      if (!transactionId || !clickId || !status) {
        return res.status(400).send(
          "Missing transactionId, clickId or status."
        );
      }

      if (!CONVERSION_STATUSES.includes(status)) {
        return res.status(400).send("Invalid conversion status.");
      }

      /*
       * Find the trusted click.
       */
      const clickQuery = await db
        .collection("clicks")
        .where("clickId", "==", clickId)
        .limit(1)
        .get();

      /*
       * Current TrackFlow clicks do not invent clickId values.
       * The real network click-id mapping must be configured
       * from the network documentation.
       */
      if (clickQuery.empty) {
        return res.status(404).send(
          "Click not found. Network click-ID mapping is not configured."
        );
      }

      const clickDoc = clickQuery.docs[0];
      const click = clickDoc.data();

      const conversionId = sha256(transactionId);

      const conversionRef = db
        .collection("conversions")
        .doc(conversionId);

      const conversionSnap = await conversionRef.get();

      /*
       * Idempotency:
       * same transaction cannot create multiple conversions.
       */
      if (conversionSnap.exists) {
        const existing = conversionSnap.data();

        if (
          existing.transactionId !== transactionId ||
          existing.assignmentId !== click.assignmentId
        ) {
          return res.status(409).send(
            "Transaction conflict."
          );
        }

        if (existing.status === status) {
          return res.status(200).send("Already processed.");
        }
      }

      const assignmentRef = db
        .collection("assignments")
        .doc(click.assignmentId);

      const assignmentSnap = await assignmentRef.get();

      if (!assignmentSnap.exists) {
        return res.status(404).send("Assignment not found.");
      }

      const assignment = assignmentSnap.data();

      /*
       * Financial values are taken from the assignment snapshot,
       * not from the client.
       */
      const networkPayout = Number(
        assignment.networkPayout || 0
      );

      const creatorPayout = Number(
        assignment.creatorPayout || 0
      );

      const conversionData = {
        transactionId,
        clickId,
        clickDocumentId: clickDoc.id,
        assignmentId: click.assignmentId,
        offerId: click.offerId,
        creatorId: click.creatorId,
        publisherId: click.publisherId || null,
        networkPayout,
        creatorPayout,
        status,
        updatedAt: serverTimestamp()
      };
  


import * as admin from "firebase-admin";
import { setGlobalOptions } from "firebase-functions/v2/options";
import { beforeUserCreated } from "firebase-functions/v2/identity";
import { onDocumentUpdated } from "firebase-functions/v2/firestore";
import { onSchedule } from "firebase-functions/v2/scheduler";
import { HttpsError, onCall } from "firebase-functions/v2/https";

const TIMEZONE = "America/Chicago";

setGlobalOptions({ maxInstances: 10 });

admin.initializeApp();

const ALLOWED_DOMAINS_DOC_PATH = "config/emailDomains";
let cachedDomains: string[] | null = null;
let lastFetchMs = 0;
const CACHE_TTL_MS = 60_000;
const frontendBaseUrl = (process.env.FRONTEND_BASE_URL ?? "https://peerride.app").replace(/\/$/, "");

async function getAllowedDomains(): Promise<string[]> {
  const now = Date.now();
  if (cachedDomains && now - lastFetchMs < CACHE_TTL_MS) {
    return cachedDomains;
  }

  const snapshot = await admin.firestore().doc(ALLOWED_DOMAINS_DOC_PATH).get();

  const domains = snapshot.get("domains");
  if (!Array.isArray(domains) || domains.some((item) => typeof item !== "string")) {
    throw new HttpsError(
      "failed-precondition",
      "Allowed email domains configuration is missing or invalid.",
    );
  }

  cachedDomains = domains.map((domain) => domain.toLowerCase().trim());
  lastFetchMs = now;
  return cachedDomains;
}

export const restrictUserSignupByDomain = beforeUserCreated(async (event) => {
  const user = event.data;

  if (!user || !user.email) {
    throw new HttpsError("invalid-argument", "Email is required for registration.");
  }

  const allowedDomains = await getAllowedDomains();
  const userDomain = user.email.split("@")[1]?.toLowerCase();

  if (!userDomain || !allowedDomains.includes(userDomain)) {
    throw new HttpsError(
      "permission-denied",
      `Unauthorized email domain "${userDomain ?? "unknown"}". Please use an allowed campus email.`,
    );
  }

  return;
});

type CreatePairRequestPayload = {
  tripId?: unknown;
  luggage?: unknown;
  note?: unknown;
  requesterName?: unknown;
  requesterContactMethod?: unknown;
  requesterContactValue?: unknown;
};



const isFiniteNonNegative = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;

const isIsoString = (value: unknown): value is string => typeof value === "string" && value.length > 0;

export const createPairRequest = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) {
    throw new HttpsError("unauthenticated", "Sign in to submit a pairing request.");
  }

  const { tripId, luggage, note, requesterName, requesterContactMethod, requesterContactValue } = request.data as CreatePairRequestPayload;

  if (!tripId || typeof tripId !== "string") {
    throw new HttpsError("invalid-argument", "tripId is required.");
  }

  // Validate contact method
  const validMethods = ["chat", "email", "phone"];
  const method = (typeof requesterContactMethod === "string" && validMethods.includes(requesterContactMethod))
    ? requesterContactMethod
    : "chat";

  let contactValue: string | null = null;
  if (method === "email" || method === "phone") {
    if (typeof requesterContactValue !== "string" || !requesterContactValue.trim()) {
      // If email is selected but not provided, try to use auth email
      if (method === "email" && request.auth?.token?.email) {
        contactValue = request.auth.token.email;
      } else {
        throw new HttpsError("invalid-argument", `Contact value is required for ${method}.`);
      }
    } else {
      contactValue = requesterContactValue.trim();
    }
  }

  const luggageInput = luggage as Record<string, unknown> | undefined;
  const carryOnSmall = luggageInput?.carryOnSmall;
  const carryOnLarge = luggageInput?.carryOnLarge;
  const checkedSmall = luggageInput?.checkedSmall;
  const checkedLarge = luggageInput?.checkedLarge;

  if (
    !luggageInput ||
    !isFiniteNonNegative(carryOnSmall) ||
    !isFiniteNonNegative(carryOnLarge) ||
    !isFiniteNonNegative(checkedSmall) ||
    !isFiniteNonNegative(checkedLarge)
  ) {
    throw new HttpsError("invalid-argument", "Luggage counts must be non-negative numbers.");
  }

  const tripSnapshot = await admin.firestore().doc(`trips/${tripId}`).get();
  if (!tripSnapshot.exists) {
    throw new HttpsError("not-found", "Trip not found.");
  }

  const tripData = tripSnapshot.data() as {
    hostId?: string;
    hostNickname?: string;
    status?: string;
    departureStart?: admin.firestore.Timestamp;
    departureEnd?: admin.firestore.Timestamp;
    origin: {
      name: string;
    }
    destination: {
      name: string;
    }
  };

  if (!tripData.hostId) {
    throw new HttpsError("failed-precondition", "Trip host is missing.");
  }

  if (tripData.status && tripData.status !== "open") {
    throw new HttpsError("failed-precondition", "This trip is not accepting pairing requests.");
  }

  if (tripData.hostId === uid) {
    throw new HttpsError("failed-precondition", "You are the host for this trip.");
  }

  const existing = await admin
    .firestore()
    .collection("pairRequests")
    .where("tripId", "==", tripId)
    .where("requesterId", "==", uid)
    .where("status", "in", ["pending", "accepted"])
    .limit(1)
    .get();

  if (!existing.empty) {
    throw new HttpsError("already-exists", "You already have an active pairing request for this trip.");
  }

  const requesterDisplayName = typeof requesterName === "string" && requesterName.trim().length > 0
    ? requesterName.trim()
    : request.auth?.token?.name ?? "Anonymous";

  const docRef = await admin.firestore().collection("pairRequests").add({
    tripId,
    hostId: tripData.hostId,
    hostNickname: tripData.hostNickname ?? "Host",
    requesterId: uid,
    requesterName: requesterDisplayName,
    requesterContactMethod: method,
    requesterContactValue: contactValue,
    luggage: { carryOnSmall, carryOnLarge, checkedSmall, checkedLarge },
    note: typeof note === "string" && note.trim() ? note.trim() : null,
    status: "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  const pendingSnapshot = await admin
    .firestore()
    .collection("pairRequests")
    .where("hostId", "==", tripData.hostId)
    .where("status", "==", "pending")
    .get();

  const tripUrl = `${frontendBaseUrl}/trips/${tripId}`;

  try {
    const hostRecord = await admin.auth().getUser(tripData.hostId);
    const hostEmail = hostRecord.email;

    if (hostEmail) {
      const origin = tripData.origin.name;
      const destination = tripData.destination.name;
      const start = tripData.departureStart?.toDate().toLocaleString("en-US", { timeZone: TIMEZONE }) ?? "";
      const end = tripData.departureEnd?.toDate().toLocaleString("en-US", { timeZone: TIMEZONE }) ?? "";

      await admin.firestore().collection("mail").add({
        to: hostEmail,
        message: {
          subject: `New pairing request for your trip ${origin} → ${destination}`,
          html: `
            <p>Hi ${tripData.hostNickname ?? ""},</p>
            <p><strong>${requesterDisplayName}</strong> just sent a pairing request.</p>
            <ul>
              <li>Route: ${origin} → ${destination}</li>
              <li>Window: ${start} – ${end}</li>
              <li>Pending requests awaiting action: ${pendingSnapshot.size}</li>
            </ul>
            <p><a href="${tripUrl}">Open trip requests</a></p>
          `,
        },
      });
    }
  } catch (emailError) {
    console.warn("Email dispatch failed", emailError);
  }

  return {
    id: docRef.id,
    createdAt: Date.now(),
  };
});

export const createTrip = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) {
    throw new HttpsError("unauthenticated", "Sign in to create a trip.");
  }

  const { origin, destination, departureStart, departureEnd, luggage, note, hostNickname, hostContactMethod, hostContactValue } =
    request.data as any;

  if (!origin || typeof origin !== "object" || !origin.id || !origin.name) {
    throw new HttpsError("invalid-argument", "origin is required and must be a valid location object.");
  }
  if (!destination || typeof destination !== "object" || !destination.id || !destination.name) {
    throw new HttpsError("invalid-argument", "destination is required and must be a valid location object.");
  }
  if (!isIsoString(departureStart) || !isIsoString(departureEnd)) {
    throw new HttpsError("invalid-argument", "departureStart and departureEnd are required ISO strings.");
  }

  // Validate contact method
  const validMethods = ["chat", "email", "phone"];
  const method = (typeof hostContactMethod === "string" && validMethods.includes(hostContactMethod))
    ? hostContactMethod
    : "chat";

  let contactValue: string | null = null;
  if (method === "email" || method === "phone") {
    if (typeof hostContactValue !== "string" || !hostContactValue.trim()) {
      // If email is selected but not provided, try to use auth email
      if (method === "email" && request.auth?.token?.email) {
        contactValue = request.auth.token.email;
      } else {
        throw new HttpsError("invalid-argument", `Contact value is required for ${method}.`);
      }
    } else {
      contactValue = hostContactValue.trim();
    }
  }

  const luggageInput = luggage as Record<string, unknown> | undefined;
  const luggageValid =
    luggageInput &&
    ["carry-on-small", "carry-on-large", "checked-small", "checked-large"].every(
      (key) => typeof luggageInput[key] === "number" && Number.isFinite(luggageInput[key] as number) && (luggageInput[key] as number) >= 0,
    );

  if (!luggageValid) {
    throw new HttpsError("invalid-argument", "Luggage must include numeric counts for each size.");
  }

  // Limit: max 5 active trips (open or paired)
  const active = await admin
    .firestore()
    .collection("trips")
    .where("hostId", "==", uid)
    .where("status", "in", ["open", "paired"])
    .where("departureEnd", ">=", new Date())
    .get();

  if (active.size >= 5) {
    throw new HttpsError(
      "resource-exhausted",
      "You can host up to 5 active trips. Complete or cancel one before creating a new trip.",
    );
  }

  const departureStartDate = new Date(departureStart as string);
  const departureEndDate = new Date(departureEnd as string);

  const docRef = await admin.firestore().collection("trips").add({
    hostId: uid,
    hostNickname: typeof hostNickname === "string" && hostNickname.trim() ? hostNickname.trim() : request.auth?.token?.name ?? "Host",
    hostContactMethod: method,
    hostContactValue: contactValue,
    origin,
    destination,
    departureStart: departureStartDate,
    departureEnd: departureEndDate,
    luggage: luggageInput,
    note: typeof note === "string" && note.trim() ? note.trim() : null,
    status: "open",
    guest: null,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { id: docRef.id };
});

type AcceptPairRequestPayload = {
  requestId?: unknown;
};

export const acceptPairRequest = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) {
    throw new HttpsError("unauthenticated", "Sign in to accept pairing requests.");
  }

  const { requestId } = request.data as AcceptPairRequestPayload;
  if (!requestId || typeof requestId !== "string") {
    throw new HttpsError("invalid-argument", "requestId is required.");
  }

  const reqRef = admin.firestore().doc(`pairRequests/${requestId}`);
  const tripRefFromReq = (tripId: string) => admin.firestore().doc(`trips/${tripId}`);

  await admin.firestore().runTransaction(async (txn) => {
    const reqSnap = await txn.get(reqRef);
    if (!reqSnap.exists) {
      throw new HttpsError("not-found", "Pair request not found.");
    }
    const reqData = reqSnap.data() as any;
    if (reqData.status !== "pending") {
      throw new HttpsError("failed-precondition", "Only pending requests can be accepted.");
    }

    const tripId = reqData.tripId as string | undefined;
    if (!tripId) {
      throw new HttpsError("failed-precondition", "Request is missing tripId.");
    }

    const tripSnap = await txn.get(tripRefFromReq(tripId));
    if (!tripSnap.exists) {
      throw new HttpsError("not-found", "Trip not found.");
    }

    const tripData = tripSnap.data() as any;
    if (tripData.hostId !== uid) {
      throw new HttpsError("permission-denied", "Only the host can accept requests for this trip.");
    }
    if (tripData.status && tripData.status !== "open") {
      throw new HttpsError("failed-precondition", "Trip is not open for pairing.");
    }

    txn.update(reqRef, { status: "accepted", updatedAt: admin.firestore.FieldValue.serverTimestamp() });
    txn.update(tripRefFromReq(tripId), {
      guest: {
        id: reqData.requesterId,
        nickname: reqData.requesterName,
        luggage: reqData.luggage,
        note: reqData.note ?? null,
        guestContactMethod: reqData.requesterContactMethod ?? "email",
        guestContactValue: reqData.requesterContactValue ?? null,
      },
      status: "paired",
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
  });

  // Decline other pending requests for this trip outside the transaction.
  const reqSnap = await reqRef.get();
  const tripId = (reqSnap.data() as any).tripId as string;
  const pending = await admin
    .firestore()
    .collection("pairRequests")
    .where("tripId", "==", tripId)
    .where("status", "==", "pending")
    .get();

  const batch = admin.firestore().batch();
  pending.docs
    .filter((doc) => doc.id !== requestId)
    .forEach((doc) => batch.update(doc.ref, { status: "declined", updatedAt: admin.firestore.FieldValue.serverTimestamp() }));
  if (!pending.empty) {
    await batch.commit().catch((err) => console.warn("Decline others failed", err));
  }

  return { ok: true };
});

const getHoursToTrip = (departureStart: Date): number => {
  const now = new Date();
  const diffMs = departureStart.getTime() - now.getTime();
  return Math.round(diffMs / (1000 * 60 * 60));
};

const getCommonEmailData = (
  tripData: any,
  tripId: string
) => {
  const origin = tripData.origin.name;
  const destination = tripData.destination.name;
  const start = tripData.departureStart?.toDate().toLocaleString("en-US", { timeZone: TIMEZONE }) ?? "";
  const end = tripData.departureEnd?.toDate().toLocaleString("en-US", { timeZone: TIMEZONE }) ?? "";
  const tripUrl = `${frontendBaseUrl}/trips/${tripId}`;

  const departureDate = tripData.departureStart?.toDate();
  const hoursToTrip = departureDate ? getHoursToTrip(departureDate) : 0;
  const isWithin30Hours = hoursToTrip <= 30;

  const contactInfoText = isWithin30Hours
    ? `<strong>Because your trip is within 30 hours</strong>, it might be helpful to exchange phone numbers or emails to facilitate prompt finalisation of details.`
    : `Feel free to exchange emails or phone numbers if you'd like to facilitate easier communication.`;

  return { origin, destination, start, end, tripUrl, hoursToTrip, contactInfoText };
};

const getContactDetailsHtml = (method: unknown, value: unknown, name: string): string => {
  if (method === "email" && typeof value === "string" && value.trim()) {
    return `<p>You can also contact <strong>${name}</strong> via email: <a href="mailto:${value}">${value}</a></p>`;
  }
  if (method === "phone" && typeof value === "string" && value.trim()) {
    return `<p>You can also contact <strong>${name}</strong> via phone: <a href="tel:${value}">${value}</a></p>`;
  }
  return "";
};

const sendGuestAcceptanceEmail = async (
  email: string,
  hostNickname: string,
  commonData: any,
  contactMethod?: unknown,
  contactValue?: unknown
) => {
  const { origin, destination, start, end, tripUrl, hoursToTrip, contactInfoText } = commonData;
  const specificContactHtml = getContactDetailsHtml(contactMethod, contactValue, hostNickname);

  await admin.firestore().collection("mail").add({
    to: email,
    message: {
      subject: `Peer-Ride: Your pairing request was accepted by ${hostNickname}`,
      html: `
        <p>Great news! Your pairing request for <strong>${origin} -> ${destination}</strong> was accepted by <strong>${hostNickname}</strong>. Your pairing is now confirmed.</p>
        <ul>
          <li>Window: ${start} – ${end}</li>
          <li>Time to trip: ${hoursToTrip} hours</li>
        </ul>
        <p>Please <a href="${tripUrl}">open trip details</a> to coordinate via our in-app live chat, which can also be found by selecting the <strong>"Me"</strong> page, then the <strong>"View"</strong> button on the correct card.</p>
        ${specificContactHtml}
        <p>${contactInfoText}</p>
        <p>Please consider using Uber and Lyft's two stop functionality when booking a ride, which may save you some walking.</p>
        <br>
        <p>Best regards,</p>
        <p>Peer-ride support team</p>
      `,
    },
  });
};

const sendHostAcceptanceEmail = async (
  email: string,
  guestNickname: string,
  commonData: any,
  contactMethod?: unknown,
  contactValue?: unknown
) => {
  const { origin, destination, start, end, tripUrl, hoursToTrip, contactInfoText } = commonData;
  const specificContactHtml = getContactDetailsHtml(contactMethod, contactValue, guestNickname);

  await admin.firestore().collection("mail").add({
    to: email,
    message: {
      subject: `Peer-Ride: You have confirmed your pairing with ${guestNickname}`,
      html: `
        <p>You have confirmed your pairing with <strong>${guestNickname}</strong> for <strong>${origin} -> ${destination}</strong>!</p>
        <ul>
          <li>Window: ${start} – ${end}</li>
          <li>Time to trip: ${hoursToTrip} hours</li>
        </ul>
        <p>Please <a href="${tripUrl}">open trip details</a> to coordinate via our in-app live chat, which can also be found by selecting the <strong>"Me"</strong> page, then the <strong>"View"</strong> button on the correct card.</p>
        ${specificContactHtml}
        <p>${contactInfoText}</p>
        <p>Please consider using Uber and Lyft's two stop functionality when booking a ride, which may save you some walking.</p>
        <br>
        <p>Best regards,</p>
        <p>Peer-ride support team</p>
      `,
    },
  });
};

export const notifyPairAcceptance = onDocumentUpdated("pairRequests/{requestId}", async (event) => {
  const beforeStatus = event.data?.before.data()?.status as string | undefined;
  const afterData = event.data?.after.data() as Record<string, unknown> | undefined;
  const afterStatus = afterData?.status as string | undefined;

  if (!afterData || beforeStatus === afterStatus) {
    return;
  }

  const requesterId = afterData.requesterId as string | undefined;
  const tripId = afterData.tripId as string | undefined;
  const guestNickname = (afterData.requesterName as string | undefined) ?? "Guest";
  const hostNickname = (afterData.hostNickname as string | undefined) ?? "Host";

  if (!requesterId || !tripId) return;

  const tripSnapshot = await admin.firestore().doc(`trips/${tripId}`).get();
  const tripData = tripSnapshot.data();

  if (!tripData) return;

  const commonData = getCommonEmailData(tripData, tripId);

  if (afterStatus === "accepted") {
    // Notify Guest
    try {
      const user = await admin.auth().getUser(requesterId);
      if (user.email) {
        // Guest receives Host's contact info
        await sendGuestAcceptanceEmail(
          user.email,
          hostNickname,
          commonData,
          tripData.hostContactMethod,
          tripData.hostContactValue
        );
      }
    } catch (err) {
      console.warn("Could not load requester user for email", err);
    }

    // Notify Host
    try {
      if (tripData.hostId) {
        const hostUser = await admin.auth().getUser(tripData.hostId);
        if (hostUser.email) {
          // Host receives Guest's contact info
          await sendHostAcceptanceEmail(
            hostUser.email,
            guestNickname,
            commonData,
            afterData.requesterContactMethod,
            afterData.requesterContactValue
          );
        }
      }
    } catch (err) {
      console.warn("Could not load host user for email", err);
    }
  }

  if (afterStatus === "declined") {
    try {
      const user = await admin.auth().getUser(requesterId);
      if (user.email) {
        await admin.firestore().collection("mail").add({
          to: user.email,
          message: {
            subject: `Your pairing request was declined by ${tripData.hostNickname ?? hostNickname}`,
            html: `
              <p>Your request for <strong>${commonData.origin} → ${commonData.destination}</strong> was declined.</p>
              <p>You can browse more trips and send another request.</p>
              <p><a href="${frontendBaseUrl}">Open Peer Ride</a></p>
            `,
          },
        });
      }
    } catch (err) {
      console.warn("Could not notify guest of decline", err);
    }
  }
});

// Scheduled cleanup: daily. Removes stale open trips (2+ days past departureEnd) and old mails.
export const cleanupStaleData = onSchedule({
  schedule: "0 8 * * *",
  timeZone: TIMEZONE,
  retryCount: 3,
}, async () => {
  const db = admin.firestore();
  const now = new Date();
  const cutoffOpenTrip = new Date(now.getTime() - 1 * 24 * 60 * 60 * 1000);
  const cutoffAllTrip = new Date(cutoffOpenTrip.getTime() - 2 * 24 * 60 * 60 * 1000);
  const cutoffMail = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  // Find open/expired trips
  const tripsSnapOpen = await db
    .collection("trips")
    .where("status", "==", "open")
    .where("departureEnd", "<", cutoffOpenTrip)
    .get();

  const tripsSnapAll = await db
    .collection("trips")
    .where("departureEnd", "<", cutoffAllTrip)
    .get();

  let tripsToDelete = tripsSnapOpen.docs;
  for (const doc of tripsSnapAll.docs) {
    if (!tripsToDelete.find((d) => d.id === doc.id)) {
      tripsToDelete.push(doc);
    }
  }

  for (const tripDoc of tripsToDelete) {
    const tripId = tripDoc.id;

    // delete pairing requests for this trip
    const reqs = await db.collection("pairRequests").where("tripId", "==", tripId).get();
    const batch = db.batch();
    reqs.docs.forEach((doc) => batch.delete(doc.ref));

    // delete chat messages subcollection
    const messages = await db.collection(`tripChats/${tripId}/messages`).get();
    messages.docs.forEach((msg) => batch.delete(msg.ref));

    batch.delete(tripDoc.ref);
    await batch.commit();
  }

  // Cleanup old mail docs
  const mailSnap = await db.collection("mail").get();
  const mailBatch = db.batch();
  let mailDeletes = 0;
  mailSnap.docs.forEach((doc) => {
    const createdField = doc.get("created") as admin.firestore.Timestamp | undefined;
    const created = createdField?.toDate() ?? doc.createTime.toDate();
    if (created < cutoffMail) {
      mailBatch.delete(doc.ref);
      mailDeletes += 1;
    }
  });
  if (mailDeletes > 0) {
    await mailBatch.commit().catch((err) => console.warn("mail cleanup failed", err));
  }
});

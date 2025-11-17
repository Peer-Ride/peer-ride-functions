
import * as admin from "firebase-admin";
import { setGlobalOptions } from "firebase-functions/v2/options";
import { beforeUserCreated } from "firebase-functions/v2/identity";
import { onDocumentUpdated } from "firebase-functions/v2/firestore";
import { HttpsError, onCall } from "firebase-functions/v2/https";

setGlobalOptions({ maxInstances: 10 });

admin.initializeApp();

const ALLOWED_DOMAINS_DOC_PATH = "config/emailDomains";
let cachedDomains: string[] | null = null;
let lastFetchMs = 0;
const CACHE_TTL_MS = 60_000;

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

const frontendBaseUrl = (process.env.FRONTEND_BASE_URL ?? "https://peer-ride-2cea2.web.app").replace(/\/$/, "");

type CreatePairRequestPayload = {
  tripId?: unknown;
  luggage?: unknown;
  note?: unknown;
  requesterName?: unknown;
};

type CreateTripPayload = {
  originId?: unknown;
  destinationId?: unknown;
  departureStart?: unknown;
  departureEnd?: unknown;
  luggage?: unknown;
  note?: unknown;
  hostNickname?: unknown;
};

const isFiniteNonNegative = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;

export const createPairRequest = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) {
    throw new HttpsError("unauthenticated", "Sign in to submit a pairing request.");
  }

  const { tripId, luggage, note, requesterName } = request.data as CreatePairRequestPayload;

  if (!tripId || typeof tripId !== "string") {
    throw new HttpsError("invalid-argument", "tripId is required.");
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
    originId?: string;
    destinationId?: string;
    departureStart?: admin.firestore.Timestamp;
    departureEnd?: admin.firestore.Timestamp;
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
      const origin = tripData.originId ?? "Origin";
      const destination = tripData.destinationId ?? "Destination";
      const start = tripData.departureStart?.toDate().toLocaleString("en-US", { timeZone: "UTC" }) ?? "";
      const end = tripData.departureEnd?.toDate().toLocaleString("en-US", { timeZone: "UTC" }) ?? "";

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

const isIsoString = (value: unknown): value is string => typeof value === "string" && value.length > 0;

export const createTrip = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) {
    throw new HttpsError("unauthenticated", "Sign in to create a trip.");
  }

  const { originId, destinationId, departureStart, departureEnd, luggage, note, hostNickname } =
    request.data as CreateTripPayload;

  if (!originId || typeof originId !== "string") {
    throw new HttpsError("invalid-argument", "originId is required.");
  }
  if (!destinationId || typeof destinationId !== "string") {
    throw new HttpsError("invalid-argument", "destinationId is required.");
  }
  if (!isIsoString(departureStart) || !isIsoString(departureEnd)) {
    throw new HttpsError("invalid-argument", "departureStart and departureEnd are required ISO strings.");
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

  // Limit: max 3 active trips (open or paired)
  const active = await admin
    .firestore()
    .collection("trips")
    .where("hostId", "==", uid)
    .where("status", "in", ["open", "paired"])
    .get();

  if (active.size >= 3) {
    throw new HttpsError(
      "resource-exhausted",
      "You can host up to 3 active trips. Complete or cancel one before creating a new trip.",
    );
  }

  const departureStartDate = new Date(departureStart as string);
  const departureEndDate = new Date(departureEnd as string);

  const docRef = await admin.firestore().collection("trips").add({
    hostId: uid,
    hostNickname: typeof hostNickname === "string" && hostNickname.trim() ? hostNickname.trim() : request.auth?.token?.name ?? "Host",
    originId,
    destinationId,
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

export const notifyPairAcceptance = onDocumentUpdated("pairRequests/{requestId}", async (event) => {
  const beforeStatus = event.data?.before.data()?.status as string | undefined;
  const afterData = event.data?.after.data() as Record<string, unknown> | undefined;
  const afterStatus = afterData?.status as string | undefined;

  if (!afterData || beforeStatus === afterStatus || afterStatus !== "accepted") {
    return;
  }

  const requesterId = afterData.requesterId as string | undefined;
  const hostNickname = (afterData.hostNickname as string | undefined) ?? "Host";
  const tripId = afterData.tripId as string | undefined;

  if (!requesterId || !tripId) return;

  let requesterEmail: string | undefined;
  try {
    const user = await admin.auth().getUser(requesterId);
    requesterEmail = user.email ?? undefined;
  } catch (err) {
    console.warn("Could not load requester user for email", err);
  }

  if (!requesterEmail) return;

  const tripSnapshot = await admin.firestore().doc(`trips/${tripId}`).get();
  const tripData = tripSnapshot.data() as {
    originId?: string;
    destinationId?: string;
    departureStart?: admin.firestore.Timestamp;
    departureEnd?: admin.firestore.Timestamp;
    hostNickname?: string;
  } | undefined;

  const origin = tripData?.originId ?? "Origin";
  const destination = tripData?.destinationId ?? "Destination";
  const start = tripData?.departureStart?.toDate().toLocaleString("en-US", { timeZone: "UTC" }) ?? "";
  const end = tripData?.departureEnd?.toDate().toLocaleString("en-US", { timeZone: "UTC" }) ?? "";
  const tripUrl = `${frontendBaseUrl}/trips/${tripId}`;

  await admin.firestore().collection("mail").add({
    to: requesterEmail,
    message: {
      subject: `Your pairing request was accepted by ${tripData?.hostNickname ?? hostNickname}`,
      html: `
        <p>Great news!</p>
        <p>Your pairing request for <strong>${origin} → ${destination}</strong> was accepted.</p>
        <ul>
          <li>Host: ${tripData?.hostNickname ?? hostNickname}</li>
          <li>Window: ${start} – ${end}</li>
        </ul>
        <p><a href="${tripUrl}">Open trip details</a> to coordinate.</p>
      `,
    },
  });
});

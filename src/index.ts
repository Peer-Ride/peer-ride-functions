
import * as admin from "firebase-admin";
import { setGlobalOptions } from "firebase-functions/v2/options";
import { beforeUserCreated } from "firebase-functions/v2/identity";
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import fetch from "node-fetch";

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

const recaptchaSecretKey = defineSecret("RECAPTCHA_SECRET_KEY");
const recaptchaDisabled = process.env.RECAPTCHA_DISABLED === "true";
const frontendBaseUrl = (process.env.FRONTEND_BASE_URL ?? "https://peer-ride-2cea2.web.app").replace(/\/$/, "");

export const verifyRecaptcha = onCall({ secrets: [recaptchaSecretKey] }, async (request) => {
  if (recaptchaDisabled) return { success: true };

  const recaptchaSecret = recaptchaSecretKey.value();
  if (!recaptchaSecret) {
    throw new HttpsError("failed-precondition", "reCAPTCHA secret is not configured.");
  }

  const token = request.data?.token;
  const action = request.data?.action;

  if (!token || typeof token !== "string") {
    throw new HttpsError("invalid-argument", "reCAPTCHA token is required.");
  }

  const params = new URLSearchParams({ secret: recaptchaSecret, response: token });
  const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });

  if (!response.ok) {
    throw new HttpsError("unavailable", "Failed to verify reCAPTCHA token.");
  }

  const result = (await response.json()) as { success: boolean; score?: number; action?: string };

  if (!result.success || (typeof result.score === "number" && result.score < 0.5)) {
    throw new HttpsError("permission-denied", "reCAPTCHA verification failed.");
  }

  if (action && result.action && result.action !== action) {
    throw new HttpsError("permission-denied", "reCAPTCHA action mismatch.");
  }

  return { success: true };
});

type CreatePairRequestPayload = {
  tripId?: unknown;
  luggage?: unknown;
  note?: unknown;
  requesterName?: unknown;
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

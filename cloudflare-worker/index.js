/**
 * FriendConnect push relay — free alternative to a paid Firebase Cloud
 * Function.
 *
 * Firestore's "run code when a new document is written" trigger only works
 * through Cloud Functions, which requires Firebase's paid Blaze plan even
 * when actual usage is free. This Worker gets the same result without any
 * Google billing: instead of a server noticing a new Firestore document on
 * its own, the app/CRM calls this Worker directly, at the exact moment it
 * writes that document (right after creating a call session, or right
 * after an admin sends an announcement). The Worker then does the one
 * thing a server actually has to do — sign a request with a private key —
 * and forwards it to FCM, which delivers the push to the device even if
 * FriendConnect is fully closed.
 *
 * Deploy: paste this file into a Cloudflare Worker (free plan, no card
 * required) via the dashboard's Quick Edit, or `wrangler deploy`. Then set
 * these as *encrypted* Worker secrets (Settings → Variables):
 *   - GCP_CLIENT_EMAIL   the "client_email" field from a Firebase service
 *                        account JSON key (Firebase Console → Project
 *                        Settings → Service accounts → Generate new
 *                        private key)
 *   - GCP_PRIVATE_KEY    the "private_key" field from that same JSON file
 *                        (paste it exactly as-is, including the
 *                        "-----BEGIN PRIVATE KEY-----" lines)
 *   - GCP_PROJECT_ID     the Firebase project id (friendconnect-88a41)
 *   - RELAY_SECRET       any random string you make up — the app and CRM
 *                        send this back on every request so randos on the
 *                        internet can't use your Worker to spam pushes
 */

function base64UrlEncode(bytes) {
  let binary = '';
  const arr = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem) {
  const b64 = pem
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// A Google OAuth2 access token (from the signed-JWT exchange below) is
// valid for ~1 hour. Cloudflare tends to reuse the same Worker instance
// for a stretch of time, so caching it here in module scope avoids
// re-signing a JWT on every single push — this is just an optimization,
// not something the relay depends on for correctness.
let cachedToken = null;
let cachedTokenExpiry = 0;

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && now < cachedTokenExpiry - 60) return cachedToken;

  const header = {alg: 'RS256', typ: 'JWT'};
  const claimSet = {
    iss: env.GCP_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedClaimSet = base64UrlEncode(JSON.stringify(claimSet));
  const unsigned = `${encodedHeader}.${encodedClaimSet}`;

  const key = await crypto.subtle.importKey(
      'pkcs8',
      pemToArrayBuffer(env.GCP_PRIVATE_KEY),
      {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
      false,
      ['sign'],
  );
  const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      key,
      new TextEncoder().encode(unsigned),
  );
  const jwt = `${unsigned}.${base64UrlEncode(new Uint8Array(signature))}`;

  const resp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: `grant_type=${encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer')}&assertion=${jwt}`,
  });
  const tokenData = await resp.json();
  if (!resp.ok || !tokenData.access_token) {
    throw new Error(`Token exchange failed: ${JSON.stringify(tokenData)}`);
  }
  cachedToken = tokenData.access_token;
  cachedTokenExpiry = now + (tokenData.expires_in || 3600);
  return cachedToken;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('POST only', {status: 405});
    }

    let body;
    try {
      body = await request.json();
    } catch (_) {
      return new Response('Invalid JSON body', {status: 400});
    }

    if (!env.RELAY_SECRET || body.secret !== env.RELAY_SECRET) {
      return new Response('Unauthorized', {status: 401});
    }

    const {token, title, message, data, channelId} = body;
    if (!token || !title || !message) {
      return new Response('token, title and message are required', {status: 400});
    }

    try {
      const accessToken = await getAccessToken(env);
      const fcmResp = await fetch(
          `https://fcm.googleapis.com/v1/projects/${env.GCP_PROJECT_ID}/messages:send`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              message: {
                token,
                notification: {title, body: message},
                data: data || {},
                android: {
                  priority: 'high',
                  notification: channelId ? {channel_id: channelId} : undefined,
                },
                apns: {payload: {aps: {sound: 'default'}}},
              },
            }),
          },
      );
      const fcmData = await fcmResp.json();
      if (!fcmResp.ok) {
        return new Response(JSON.stringify(fcmData), {status: fcmResp.status, headers: {'Content-Type': 'application/json'}});
      }
      return new Response(JSON.stringify({ok: true, fcm: fcmData}), {headers: {'Content-Type': 'application/json'}});
    } catch (err) {
      return new Response(`Relay error: ${err.message}`, {status: 500});
    }
  },
};

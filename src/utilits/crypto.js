const PBKDF2_ITERATIONS = 100000;
const HASH_BYTES = 32;

/* =========================================================
   RANDOM BYTES
========================================================= */

function randomBytes(length) {
  const bytes = new Uint8Array(length);

  crypto.getRandomValues(bytes);

  return bytes;
}

/* =========================================================
   BASE64
========================================================= */

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/* =========================================================
   SHA-256
========================================================= */

export async function sha256Base64(value) {
  const data =
    new TextEncoder().encode(String(value));

  const hash =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return bytesToBase64(
    new Uint8Array(hash)
  );
}

/* =========================================================
   PASSWORD HASH
========================================================= */

async function hashPassword(password) {
  const salt = randomBytes(16);

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        String(password)
      ),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      key,
      HASH_BYTES * 8
    );

  return {
    hash: bytesToBase64(
      new Uint8Array(bits)
    ),

    salt: bytesToBase64(
      salt
    )
  };
}

/* =========================================================
   CREATE PASSWORD HASH
========================================================= */

export async function createPasswordHash(password) {
  const result =
    await hashPassword(password);

  return (
    result.salt +
    "$" +
    result.hash
  );
}

/* =========================================================
   VERIFY PASSWORD
========================================================= */

export async function verifyPassword(
  password,
  stored
) {
  try {
    if (!stored) {
      return false;
    }

    const parts =
      String(stored).split("$");

    if (parts.length !== 2) {
      return false;
    }

    const salt =
      base64ToBytes(parts[0]);

    const expected =
      base64ToBytes(parts[1]);

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(
          String(password)
        ),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

    const bits =
      await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt,
          iterations: PBKDF2_ITERATIONS,
          hash: "SHA-256"
        },
        key,
        HASH_BYTES * 8
      );

    const actual =
      new Uint8Array(bits);

    if (
      actual.length !==
      expected.length
    ) {
      return false;
    }

    let difference = 0;

    for (
      let i = 0;
      i < actual.length;
      i++
    ) {
      difference |=
        actual[i] ^
        expected[i];
    }

    return difference === 0;

  } catch {
    return false;
  }
}

/* =========================================================
   TOKEN
========================================================= */

export function createToken() {
  return bytesToBase64(
    randomBytes(32)
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

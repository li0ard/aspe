import { base32nopad, base64urlnopad } from "@scure/base";
import type { ECJWK, JWTHeader } from "./types.js";
import { sha512 } from "@noble/hashes/sha2.js";

export const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const computeJWKThumbprint = (jwk: ECJWK): string => {
    // RFC 7638, section 3.2 (lexicographic order)
    const encoded = new TextEncoder().encode(JSON.stringify({
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y
    }));

    return base32nopad.encode(sha512(encoded).subarray(0,16));
}

export const generateJWK = (publicKey: Uint8Array, privateKey?: Uint8Array): ECJWK => {
    const jwk: ECJWK = {
        crv: "P-256",
        kty: "EC",
        x: base64urlnopad.encode(publicKey.slice(1,33)),
        y: base64urlnopad.encode(publicKey.slice(33, 65))
    }
    if(privateKey) jwk.d = base64urlnopad.encode(privateKey);

    return jwk;
}

export const getUncompressedPubKeyFromJWK = (jwk: ECJWK): Uint8Array => {
    const x = base64urlnopad.decode(jwk.x);
    const y = base64urlnopad.decode(jwk.y);

    // ANSI X9.62 uncompressed EC point
    const publicKey = new Uint8Array(65);
    publicKey[0] = 4;
    publicKey.set(x, 1);
    publicKey.set(y, 33);
        
    return publicKey;
}

export const generateHeaderFromJWK = (jwk: ECJWK): JWTHeader => ({
    typ: "JWT",
    alg: "ES256",
    kid: computeJWKThumbprint(jwk),
    jwk
});

export const decodeJsonFromBase64 = <T>(base64: string): T => JSON.parse(new TextDecoder().decode(base64urlnopad.decode(base64)));
export const encodeJsonToBase64 = (obj: object): string => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
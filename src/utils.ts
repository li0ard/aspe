import { base32nopad, base64urlnopad } from "@scure/base";
import { KeyType, type ECJWK, type EDJWK, type JWTHeader } from "./types.js";
import { sha512 } from "@noble/hashes/sha2.js";

export const xor = (a: Uint8Array, b: Uint8Array): Uint8Array => {
    const mlen = Math.min(a.length, b.length);
    const result = new Uint8Array(mlen);
    for(let i = 0; i < mlen; i++) result[i] = a[i] ^ b[i];

    return result;
}

export const computeJWKThumbprint = <T extends Record<string, any>>(jwk: T): string => {
    // RFC 7638, section 3.2 (lexicographic order)
    const object: Record<string, any> = {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x
    }
    if(jwk.y) object.y = jwk.y;
    const encoded = new TextEncoder().encode(JSON.stringify(object));

    return base32nopad.encode(sha512(encoded).subarray(0,16));
}

export const generateHeaderFromJWK = (jwk: EDJWK | ECJWK, keyType: KeyType): JWTHeader => ({
    typ: "JWT",
    alg: keyType == KeyType.EDDSA ? "EdDSA" : "ES256",
    kid: computeJWKThumbprint(jwk),
    jwk
});

export const decodeJsonFromBase64 = <T>(base64: string): T => JSON.parse(new TextDecoder().decode(base64urlnopad.decode(base64)));
export const encodeJsonToBase64 = (obj: object): string => base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
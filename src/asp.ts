import { base64nopad, base64urlnopad } from "@scure/base";
import { RequestAction, type ASPProfilePayload, type ASPRequest, type ECJWK, type JWTHeader } from "./types.js";
import { computeJWKThumbprint, decodeJsonFromBase64, encodeJsonToBase64, generateHeaderFromJWK, generateJWK, getUncompressedPubKeyFromJWK } from "./utils.js";
import { p256 } from "@noble/curves/nist.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { SecretKey } from "./secret_key.js";
import { equalBytes } from "@noble/curves/utils.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";

/** Ariadne Signature Profile (ASP) */
export class ASPProfile {
    /**
     * Ariadne Signature Profile (ASP)
     * @param publicKey Profile public key (ANSI X9.62 uncompressed P-256 point)
     * @param name Profile name
     * @param description Profile description
     * @param claims Profile claims
     * @param color Profile color
     * @param signature Profile signature (Optional. Needed for export only)
     */
    constructor(
        public publicKey: Uint8Array,
        public name: string = "",
        public description: string = "",
        public claims: string[] = [],
        public color: string = "",
        public signature?: Uint8Array
    ) {
        if(publicKey.length != 65 && publicKey[0] != 4)
            throw new Error("Public key MUST be ANSI X9.62 uncompressed P-256 point");
    }

    /** Public key as JWK */
    private get pkAsJWK(): ECJWK { return generateJWK(this.publicKey); }

    /** Data to be signed (according to JWT spec.) */
    private get dataToBeSigned(): string { 
        const header = encodeJsonToBase64(generateHeaderFromJWK(this.pkAsJWK));
        const payload = encodeJsonToBase64(this.toJSON());

        return `${header}.${payload}`;
    }

    /** Profile thumbprint */
    get thumbprint(): string { return computeJWKThumbprint(this.pkAsJWK); }

    /** Sign profile with secret key */
    sign(secretKey: SecretKey) {
        if(!equalBytes(secretKey.publicKey, this.publicKey)) throw new Error("Secret key doesn't match profile public key");

        this.signature = p256.sign(
            utf8ToBytes(this.dataToBeSigned),
            secretKey.privateKey
        );
    }

    /** Verify profile signature */
    verify(): boolean {
        if(!this.signature) throw new Error("Can't verify unsigned profile. Sign profile first");
        return p256.verify(this.signature, utf8ToBytes(this.dataToBeSigned), this.publicKey);
    }

    /** Get profile avatar URL */
    getAvatarUrl(dicebearApiHostname = 'api.dicebear.com'): string {
        return `https://${dicebearApiHostname}/7.x/shapes/svg?seed=${this.thumbprint}&size=128`
    }

    /** Get profile ASPE URI (aka Direct proof) */
    getURI(domain = "keyoxide.org"): string { return `aspe:${domain}:${this.thumbprint}`; }

    /** Get hashed profile proof */
    async getHashedProof(domain = "keyoxide.org"): Promise<string> {
        const salt = randomBytes(16);
        const hash = await argon2idAsync(
            utf8ToBytes(this.getURI(domain).toLowerCase()), salt,
            {
                m: 512,
                t: 256,
                p: 1,
                version: 19
            }
        );

        return `$argon2id$v=19$m=512,t=256,p=1$${base64nopad.encode(salt)}$${base64nopad.encode(hash)}`;
    }

    /** Generate action request to ASPE server */
    generateActionRequest(action: RequestAction, secretKey: SecretKey): string {
        if(!equalBytes(secretKey.publicKey, this.publicKey)) throw new Error("Secret key doesn't match profile public key");

        const requestData: ASPRequest = {
            'http://ariadne.id/version': 0,
            'http://ariadne.id/type': 'request',
            'http://ariadne.id/action': action,
            iat: (Date.now() / 1000) | 0
        }
        if (action === RequestAction.CREATE || action === RequestAction.UPDATE) requestData['http://ariadne.id/profile_jws'] = this.toBase64();

        const header = encodeJsonToBase64(generateHeaderFromJWK(this.pkAsJWK));
        const payload = encodeJsonToBase64(requestData);

        const signature = p256.sign(
            utf8ToBytes(`${header}.${payload}`),
            secretKey.privateKey
        );

        return `${header}.${payload}.${base64urlnopad.encode(signature)}`;
    }

    /** Convert profile to JSON object */
    toJSON(): ASPProfilePayload {
        const profileJson: ASPProfilePayload = {
            "http://ariadne.id/version": 0,
            "http://ariadne.id/type": "profile",
            "http://ariadne.id/name": this.name,
            "http://ariadne.id/claims": this.claims.filter(i => i.length > 0)
        }
        if (this.description.length > 0) profileJson['http://ariadne.id/description'] = this.description
        if (this.color.length === 7) profileJson['http://ariadne.id/color'] = this.color;

        return profileJson;
    }

    /** Export profile as base64 (signature needed) */
    toBase64(): string {
        if(!this.signature) throw new Error("Can't export unsigned profile. Sign profile first");

        return `${this.dataToBeSigned}.${base64urlnopad.encode(this.signature)}`;
    }

    /** Import profile from base64 */
    static fromBase64(base64: string): ASPProfile {
        const [header, payload, signature] = base64.split(".");

        const headerJson = decodeJsonFromBase64<JWTHeader>(header);
        if(headerJson.typ != "JWT") throw new Error('Wrong JWK typ');
        if(headerJson.alg != "ES256") throw new Error('Wrong JWK alg');
        if(headerJson.kid != computeJWKThumbprint(headerJson.jwk)) throw new Error('Wrong JWK fingerprint');

        const payloadJson = decodeJsonFromBase64<ASPProfilePayload>(payload);

        if (payloadJson['http://ariadne.id/version'] > 0) throw new Error('Unsupported ASP version');
        if (payloadJson['http://ariadne.id/type'] !== 'profile') throw new Error('JWS is not a profile');

        const claims = Array.isArray(payloadJson['http://ariadne.id/claims']) ? payloadJson['http://ariadne.id/claims'] : [];

        const publicKey = getUncompressedPubKeyFromJWK(headerJson.jwk);
        const signatureBytes = base64urlnopad.decode(signature);
        if(!p256.verify(
            signatureBytes,
            utf8ToBytes(`${header}.${payload}`),
            publicKey,
            { lowS: false }
        )) throw new Error("Invalid profile signature");

        return new ASPProfile(
            publicKey,
            payloadJson["http://ariadne.id/name"],
            payloadJson['http://ariadne.id/description'],
            claims,
            payloadJson['http://ariadne.id/color'],
            signatureBytes
        );
    }
}
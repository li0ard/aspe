import { base64nopad, base64urlnopad } from "@scure/base";
import { KeyType, RequestAction, type ASPProfilePayload, type ASPRequest, type ECJWK, type EDJWK, type JWTHeader, type KeyAlgorithm } from "./types.js";
import { computeJWKThumbprint, decodeJsonFromBase64, encodeJsonToBase64, generateHeaderFromJWK } from "./utils.js";
import { ES256Algorithm } from "./algorithm/es256.js";
import { EdDSAAlgorithm } from "./algorithm/eddsa.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { SecretKey } from "./secret_key.js";
import { equalBytes } from "@noble/curves/utils.js";
import { argon2idAsync } from "@noble/hashes/argon2.js";

/** Ariadne Signature Profile (ASP) */
export class ASPProfile {
    /** Public key algorithm */
    private algorithm: KeyAlgorithm;
    /**
     * Ariadne Signature Profile (ASP)
     * @param keyType Key type (ES256 or EdDSA)
     * @param publicKey Profile public key (ANSI X9.62 uncompressed P-256 point)
     * @param name Profile name
     * @param description Profile description
     * @param claims Profile claims
     * @param color Profile color
     * @param avatar_url Profile Avatar URL
     * @param email Profile Email
     * @param exp Expire claim
     * @param signature Profile signature (Optional. Needed for export only)
     */
    constructor(
        public keyType: KeyType,
        public publicKey: Uint8Array,
        public name: string = "",
        public description: string = "",
        public claims: string[] = [],
        public color: string = "",
        public avatar_url: string = "",
        public email: string = "",
        public exp: number = 0,
        public signature?: Uint8Array
    ) {
        this.algorithm = keyType == KeyType.EDDSA ? EdDSAAlgorithm : ES256Algorithm;
        this.algorithm.validatePublicKeyBlob(publicKey);
    }

    /** Public key as JWK */
    private get pkAsJWK(): EDJWK | ECJWK {
        return this.algorithm.generateJWKFromPubKey(this.publicKey);
    }

    /** Data to be signed (according to JWT spec.) */
    private get dataToBeSigned(): string { 
        const header = encodeJsonToBase64(generateHeaderFromJWK(this.pkAsJWK, this.keyType));
        const payload = encodeJsonToBase64(this.toJSON());

        return `${header}.${payload}`;
    }

    /** Profile thumbprint */
    get thumbprint(): string { return computeJWKThumbprint(this.pkAsJWK); }

    /** Sign profile with secret key */
    sign(secretKey: SecretKey) {
        if(!equalBytes(secretKey.publicKey, this.publicKey)) throw new Error("Secret key doesn't match profile public key");

        this.signature = this.algorithm.sign(secretKey.privateKey, utf8ToBytes(this.dataToBeSigned))
    }

    /** Verify profile signature */
    verify(): boolean {
        if(!this.signature) throw new Error("Can't verify unsigned profile. Sign profile first");
        return this.algorithm.verify(this.publicKey, utf8ToBytes(this.dataToBeSigned), this.signature)
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
            { m: 512, t: 256, p: 1, version: 19 }
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
        if (action === RequestAction.CREATE || action === RequestAction.UPDATE)
            requestData['http://ariadne.id/profile_jws'] = this.toBase64();

        const header = encodeJsonToBase64(generateHeaderFromJWK(this.pkAsJWK, this.keyType));
        const payload = encodeJsonToBase64(requestData);
        const signature = this.algorithm.sign(secretKey.privateKey, utf8ToBytes(this.dataToBeSigned));

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
        if(this.description.length > 0) profileJson['http://ariadne.id/description'] = this.description
        if(this.color.length === 7) profileJson['http://ariadne.id/color'] = this.color;
        if(this.avatar_url.length > 0) profileJson['http://ariadne.id/avatar_url'] = this.avatar_url;
        if(this.email.length > 0) profileJson['http://ariadne.id/email'] = this.email;
        if(this.exp > 0) profileJson['exp'] = this.exp;

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
        let algorithm: KeyAlgorithm, keyType: KeyType;
        switch(headerJson.alg) {
            case "ES256":
                algorithm = ES256Algorithm;
                keyType = KeyType.ES256;
            break;
            case "EdDSA":
                algorithm = EdDSAAlgorithm;
                keyType = KeyType.EDDSA;
            break;
            default:
                throw("Wrong JWK alg");
        }
        if(headerJson.kid != computeJWKThumbprint(headerJson.jwk)) throw new Error('Wrong JWK fingerprint');

        const payloadJson = decodeJsonFromBase64<ASPProfilePayload>(payload);
        if (payloadJson['http://ariadne.id/version'] > 0) throw new Error('Unsupported ASP version');
        if (payloadJson['http://ariadne.id/type'] !== 'profile') throw new Error('JWS is not a profile');

        const claims = Array.isArray(payloadJson['http://ariadne.id/claims']) ? payloadJson['http://ariadne.id/claims'] : [];

        const publicKey = algorithm.getUncompressedPubKeyFromJWK(headerJson.jwk);
        const signatureBytes = base64urlnopad.decode(signature);
        if(!algorithm.verify(
            publicKey,
            utf8ToBytes(`${header}.${payload}`),
            signatureBytes
        )) throw new Error("Invalid profile signature");

        return new ASPProfile(
            keyType,
            publicKey,
            payloadJson["http://ariadne.id/name"],
            payloadJson['http://ariadne.id/description'],
            claims,
            payloadJson['http://ariadne.id/color'],
            payloadJson['http://ariadne.id/avatar_url'],
            payloadJson['http://ariadne.id/email'],
            payloadJson['exp'],
            signatureBytes
        );
    }
}
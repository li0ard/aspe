/** Encrypted data */
export interface EncryptedData {
    /** PBKDF algorithm */
    alg: "scrypt";
    /** PBKDF parameters (scrypt)*/
    prm: {
        /** Iterations count */
        N: number;
        /** Block size */
        r: number;
        /** Parallelism factor */
        p: number;
    }
    /** Salt */
    slt: string;
    /** Encrypted key */
    key: string;
}

/** EdDSA JWK */
export interface EDJWK {
    /** Curve */
    crv: string;
    /** Key type */
    kty: string;
    /** X coordinate */ 
    x: string;
}

/** ES256 JWK */
export interface ECJWK extends EDJWK {
    /** Y coordinate */
    y: string;
}

/** ASP base profile/request object */
export interface ASPBase {
    /** Version */
    "http://ariadne.id/version": number;
    /** Type */
    "http://ariadne.id/type": string;
}

/** ASP profile object */
export interface ASPProfilePayload extends ASPBase {
    /** Profile name */
    "http://ariadne.id/name"?: string;
    /** Profile claims */
    "http://ariadne.id/claims"?: string[];
    /** Profile description */
    "http://ariadne.id/description"?: string;
    /** Profile color */
    "http://ariadne.id/color"?: string;
    /** Profile Avatar URL */
    "http://ariadne.id/avatar_url"?: string;
    /** Profile Email */
    "http://ariadne.id/email"?: string;
    /** Expire claim */
    "exp"?: number;
}

/** ASP request object */
export interface ASPRequest extends ASPBase {
    /** Request action */
    'http://ariadne.id/action': RequestAction,
    /** Profile JWS */
    'http://ariadne.id/profile_jws'?: string;
    /** Issued at */
    "iat": number;
}

/** JWT header (for JWS) */
export interface JWTHeader {
    /** Type */
    typ: "JWT";
    /** Algorithm */
    alg: string;
    /** Key ID */
    kid: string;
    /** Key JWK object */
    jwk: EDJWK | ECJWK;
}

/** Request actions */
export enum RequestAction {
    /** Create profile */
    CREATE = "create",
    /** Update profile */
    UPDATE = "update",
    /** Delete profile */
    DELETE = "delete"
}

/** Key types */
export enum KeyType {
    /** ES256 (ECDSA P-256) */
    ES256,
    /** EdDSA (ED25519) */
    EDDSA
}

export interface KeyAlgorithm {
    validatePublicKeyBlob(publicKey: Uint8Array): void;
    getPublicKey(privateKey: Uint8Array): Uint8Array;
    getRandomPrivateKey(): Uint8Array;
    sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array;
    verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
    generateJWKFromPubKey(publicKey: Uint8Array): EDJWK | ECJWK;
    getUncompressedPubKeyFromJWK(jwk: EDJWK | ECJWK): Uint8Array;
    serializePrivateKeyToDER(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
} 
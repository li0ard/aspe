/** Encrypted secret key */
export interface EncryptedSecretKey {
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

/** ES256 JWK */
export interface ECJWK {
    /** Curve */
    crv: string;
    /** Key type */
    kty: string;
    /** X coordinate */ 
    x: string;
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
    jwk: ECJWK;
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
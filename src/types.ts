export interface EncryptedSecretKey {
    alg: "scrypt";
    prm: {
        N: number;
        r: number;
        p: number;
    }
    slt: string;
    key: string;
}

export interface ECJWK {
    crv: string;
    kty: string;
    d?: string;
    x: string;
    y: string;
}

export interface ASPBase {
    "http://ariadne.id/version": number;
    "http://ariadne.id/type": string;
}

export interface ASPProfilePayload extends ASPBase {
    "http://ariadne.id/name"?: string;
    "http://ariadne.id/claims"?: string[];
    "http://ariadne.id/description"?: string;
    "http://ariadne.id/color"?: string;
}

export interface ASPRequest extends ASPBase {
    'http://ariadne.id/action': RequestAction,
    'http://ariadne.id/profile_jws'?: string;
    "iat": number;
}

export interface JWTHeader {
    typ: "JWT";
    alg: string;
    kid: string;
    jwk: ECJWK;
}

export enum RequestAction {
    CREATE = "create",
    UPDATE = "update",
    DELETE = "delete"
}
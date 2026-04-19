import { p256 } from "@noble/curves/nist.js";
import { base64urlnopad } from "@scure/base";
import type { ECJWK } from "../types.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { ECPrivateKey, id_ecPublicKey } from "@peculiar/asn1-ecc";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { hexToBytes } from "@noble/hashes/utils.js";

export class ES256Algorithm {
    static validatePublicKeyBlob(publicKey: Uint8Array) {
        if(publicKey.length != 65 && publicKey[0] != 4)
            throw new Error("[ES256] Public key MUST be ANSI X9.62 uncompressed P-256 point");
    }

    static getPublicKey(privateKey: Uint8Array): Uint8Array {
        return p256.getPublicKey(privateKey, false);
    }

    static getRandomPrivateKey(): Uint8Array {
        return p256.utils.randomSecretKey();
    }

    static sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
        return p256.sign(message, privateKey);
    }

    static verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
        return p256.verify(signature, message, publicKey, { lowS: false });
    }

    static generateJWKFromPubKey(publicKey: Uint8Array): ECJWK {
        return {
            crv: "P-256",
            kty: "EC",
            x: base64urlnopad.encode(publicKey.slice(1,33)),
            y: base64urlnopad.encode(publicKey.slice(33, 65))
        }
    }

    static getUncompressedPubKeyFromJWK(jwk: ECJWK): Uint8Array {
        const x = base64urlnopad.decode(jwk.x);
        const y = base64urlnopad.decode(jwk.y);
        // ANSI X9.62 uncompressed EC point
        const publicKey = new Uint8Array(65);
        publicKey[0] = 4;
        publicKey.set(x, 1);
        publicKey.set(y, 33);
        
        return publicKey;
    }

    static serializePrivateKeyToDER(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
        const privateKeyOctetString = new OctetString();
        privateKeyOctetString.buffer = privateKey.buffer as ArrayBuffer;

        const ecPrivateKey = new ECPrivateKey({
            version: 1,
            privateKey: privateKeyOctetString,
            publicKey: publicKey.buffer as ArrayBuffer
        });

        const ecPrivateKeyOctetString = new OctetString();
        ecPrivateKeyOctetString.buffer = AsnConvert.serialize(ecPrivateKey);

        const privateKeyInfo = new PrivateKeyInfo({
            version: 0,
            privateKeyAlgorithm: new AlgorithmIdentifier({
                algorithm: id_ecPublicKey,
                parameters: hexToBytes("06082A8648CE3D030107").buffer // 1.2.840.10045.3.1.7 prime256v1
            }),
            privateKey: ecPrivateKeyOctetString
        });

        return new Uint8Array(AsnConvert.serialize(privateKeyInfo));
    }
}
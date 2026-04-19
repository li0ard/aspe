import { ed25519 } from "@noble/curves/ed25519.js";
import { base64urlnopad } from "@scure/base";
import type { EDJWK } from "../types.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";

const id_ed25519PublicKey = "1.3.101.112";

export class EdDSAAlgorithm {
    static validatePublicKeyBlob(publicKey: Uint8Array) {
        if(publicKey.length != 32)
            throw new Error("[EdDSA] Public key MUST have 32 bytes");
    }

    static getPublicKey(privateKey: Uint8Array): Uint8Array {
        return ed25519.getPublicKey(privateKey);
    }

    static getRandomPrivateKey(): Uint8Array {
        return ed25519.utils.randomSecretKey();
    }

    static sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
        return ed25519.sign(message, privateKey);
    }

    static verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
        return ed25519.verify(signature, message, publicKey);
    }

    static generateJWKFromPubKey(publicKey: Uint8Array): EDJWK {
        return {
            crv: "Ed25519",
            kty: "OKP",
            x: base64urlnopad.encode(publicKey)
        }
    }

    static getUncompressedPubKeyFromJWK(jwk: EDJWK): Uint8Array {
        return base64urlnopad.decode(jwk.x);
    }

    static serializePrivateKeyToDER(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
        const privateKeyOctetString = new OctetString();
        privateKeyOctetString.buffer = privateKey.buffer as ArrayBuffer;

        const edPrivateKeyOctetString = new OctetString();
        edPrivateKeyOctetString.buffer = AsnConvert.serialize(privateKeyOctetString);

        const privateKeyInfo = new PrivateKeyInfo({
            version: 0,
            privateKeyAlgorithm: new AlgorithmIdentifier({
                algorithm: id_ed25519PublicKey,
            }),
            privateKey: edPrivateKeyOctetString
        });

        return new Uint8Array(AsnConvert.serialize(privateKeyInfo));
    }
}
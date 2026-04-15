import { scryptAsync } from "@noble/hashes/scrypt.js";
import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { p256 } from "@noble/curves/nist.js";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { ECPrivateKey, id_ecPublicKey } from "@peculiar/asn1-ecc";
import { base64 } from "@scure/base";
import type {EncryptedSecretKey } from "./types.js";
import { computeJWKThumbprint, xor, generateJWK } from "./utils.js";

/** ASP Secret key */
export class SecretKey {
    /** Public key */
    public publicKey: Uint8Array;

    /**
     * ASP Secret key
     * @param privateKey Private key
     * @param publicKey Public key (Optional. ANSI X9.62 uncompressed EC point)
     */
    constructor(public privateKey: Uint8Array, publicKey?: Uint8Array) {
        if(publicKey && publicKey.length != 65 && publicKey[0] != 4)
            throw new Error("Public key MUST be ANSI X9.62 uncompressed P-256 point");
        this.publicKey ||= p256.getPublicKey(privateKey, false);
    }

    /** Public key (ASP profile) thumbprint */
    get thumbprint(): string { return computeJWKThumbprint(generateJWK(this.publicKey)); }

    /** Export secret key to password-protected base64 */
    async toBase64(password: string): Promise<string> {
        const privateKeyOctetString = new OctetString();
        privateKeyOctetString.buffer = this.privateKey.buffer as ArrayBuffer;

        const ecPrivateKey = new ECPrivateKey({
            version: 1,
            privateKey: privateKeyOctetString,
            publicKey: this.publicKey.buffer as ArrayBuffer
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

        const privateKeyInfoSerialized = new Uint8Array(AsnConvert.serialize(privateKeyInfo));

        const salt = randomBytes(16),
            prmN = 16384,
            prmR = 8,
            prmP = 1;
        const derivedKey = await scryptAsync(password, salt, {
            N: prmN,
            p: prmP,
            r: prmR,
            dkLen: privateKeyInfoSerialized.length
        });

        const encryptedKey = xor(privateKeyInfoSerialized, derivedKey);
        const encryptedKeyObject: EncryptedSecretKey = {
            alg: "scrypt",
            prm: {
                N: prmN,
                r: prmR,
                p: prmP,
            },
            slt: base64.encode(salt),
            key: base64.encode(encryptedKey)
        }

        return base64.encode(new TextEncoder().encode(JSON.stringify(encryptedKeyObject)));
    }

    /** Generate new secret key */
    static generate(): SecretKey { return new SecretKey(p256.utils.randomSecretKey()); }
    
    /** Import secret key from password-protected base64 */
    static async fromBase64(encryptedKey: string, password?: string): Promise<SecretKey> {
        const encryptedKeyObject: EncryptedSecretKey = JSON.parse(new TextDecoder().decode(base64.decode(encryptedKey)));
        if(encryptedKeyObject.alg != "scrypt")
            throw new Error(`Can't decrypt key with algorithm "${encryptedKeyObject.alg}. Only "scrypt" supported`);

        const encryptedKeyBytes = base64.decode(encryptedKeyObject.key);
        const encryptedKeySalt = base64.decode(encryptedKeyObject.slt);

        let decryptedKeyBytes;
        if(password) {
            const derivedKey = await scryptAsync(password, encryptedKeySalt, {
                N: encryptedKeyObject.prm.N,
                p: encryptedKeyObject.prm.p,
                r: encryptedKeyObject.prm.r,
                dkLen: encryptedKeyBytes.length
            });
            decryptedKeyBytes = xor(encryptedKeyBytes, derivedKey);
        } 
        else decryptedKeyBytes = encryptedKeyBytes;

        const privateKeyInfo = AsnConvert.parse(decryptedKeyBytes, PrivateKeyInfo);
        if(privateKeyInfo.privateKeyAlgorithm.algorithm != id_ecPublicKey) throw new Error(`Invalid public key`);

        const ecPrivateKey = AsnConvert.parse(privateKeyInfo.privateKey, ECPrivateKey);
        
        return new SecretKey(
            new Uint8Array(ecPrivateKey.privateKey.buffer),
            ecPrivateKey.publicKey ? new Uint8Array(ecPrivateKey.publicKey) : undefined
        );
    }
}
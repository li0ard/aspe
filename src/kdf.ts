import { scryptAsync } from "@noble/hashes/scrypt.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { xor } from "./utils.js";
import type { EncryptedData } from "./types.js";

const N = 16384, r = 8, p = 1;

/** Scrypt PBKDF */
export class ScryptPBKDF {
    /** Encrypt data */
    static async encrypt(data: Uint8Array, passphrase: string, salt = randomBytes(16)): Promise<string> {
        const derivedKey = await scryptAsync(passphrase, salt, {
            N, p, r,
            dkLen: data.length
        });

        const encryptedData = xor(data, derivedKey);
        const encryptedDataObject: EncryptedData = {
            alg: "scrypt",
            prm: { N, r, p },
            slt: base64.encode(salt),
            key: base64.encode(encryptedData)
        }

        return base64.encode(new TextEncoder().encode(JSON.stringify(encryptedDataObject)));
    }

    /** Decrypt data */
    static async decrypt(data: string, passphrase: string): Promise<Uint8Array> {
        const encryptedDataObject: EncryptedData = JSON.parse(new TextDecoder().decode(base64.decode(data)));
        if(encryptedDataObject.alg != "scrypt")
            throw new Error(`Can't decrypt data with algorithm "${encryptedDataObject.alg}. Only "scrypt" supported`);

        const encryptedDataBytes = base64.decode(encryptedDataObject.key);
        const encryptedDataSalt = base64.decode(encryptedDataObject.slt);

        const derivedKey = await scryptAsync(passphrase, encryptedDataSalt, {
            N: encryptedDataObject.prm.N,
            p: encryptedDataObject.prm.p,
            r: encryptedDataObject.prm.r,
            dkLen: encryptedDataBytes.length
        });

        return xor(encryptedDataBytes, derivedKey);
    }
}
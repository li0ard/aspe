import { ES256Algorithm } from "./algorithm/es256.js";
import { EdDSAAlgorithm } from "./algorithm/eddsa.js";
import { KeyType, type KeyAlgorithm } from "./types.js";
import { computeJWKThumbprint } from "./utils.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { ECPrivateKey, id_ecPublicKey } from "@peculiar/asn1-ecc";
import { ScryptPBKDF } from "./kdf.js";

/** ASP Secret key */
export class SecretKey {
    /** Secret key algorithm */
    private algorithm: KeyAlgorithm;
    /** Public key */
    public publicKey: Uint8Array;

    /**
     * ASP Secret key
     * @param keyType Key type (ES256 or EdDSA)
     * @param privateKey Private key
     * @param publicKey Public key
     */
    constructor(public keyType: KeyType, public privateKey: Uint8Array, publicKey?: Uint8Array) {
        this.algorithm = keyType == KeyType.EDDSA ? EdDSAAlgorithm : ES256Algorithm;

        if(publicKey) this.algorithm.validatePublicKeyBlob(publicKey);
        this.publicKey ||= this.algorithm.getPublicKey(privateKey);
    }

    /** Public key (ASP profile) thumbprint */
    get thumbprint(): string {
        return computeJWKThumbprint(this.algorithm.generateJWKFromPubKey(this.publicKey));
    }

    /** Export secret key to password-protected base64 */
    async toBase64(password: string): Promise<string> {
        const privateKeyInfoSerialized = this.algorithm.serializePrivateKeyToDER(
            this.privateKey,
            this.publicKey
        );

        return await ScryptPBKDF.encrypt(privateKeyInfoSerialized, password);
    }

    /** Generate new secret key */
    static generate(keyType: KeyType): SecretKey {
        const algorithm = keyType == KeyType.EDDSA ? EdDSAAlgorithm : ES256Algorithm;
        return new SecretKey(keyType, algorithm.getRandomPrivateKey());
    }
    
    /** Import secret key from password-protected base64 */
    static async fromBase64(encryptedKey: string, password: string): Promise<SecretKey> {
        const decryptedKeyBytes = await ScryptPBKDF.decrypt(encryptedKey, password);

        let privateKeyInfo: PrivateKeyInfo;
        try {
            privateKeyInfo = AsnConvert.parse(decryptedKeyBytes, PrivateKeyInfo);
        } catch (e) { throw new Error("Invalid DER key format"); }

        const privateKeyAlgorithm = privateKeyInfo.privateKeyAlgorithm.algorithm;
        if(privateKeyAlgorithm == id_ecPublicKey) {
            const ecPrivateKey = AsnConvert.parse(privateKeyInfo.privateKey, ECPrivateKey);

            return new SecretKey(KeyType.ES256, new Uint8Array(ecPrivateKey.privateKey.buffer));
        }

        if(privateKeyAlgorithm == "1.3.101.112") { // id_ed25519PublicKey
            const privateKey = AsnConvert.parse(privateKeyInfo.privateKey.buffer, OctetString);
            return new SecretKey(KeyType.EDDSA, new Uint8Array(privateKey.buffer));
        }

        throw new Error(`Unsupported key algorithm "${privateKeyAlgorithm}"`);
    }
}
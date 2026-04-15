import { describe, test, expect } from "bun:test";
import { SecretKey } from "../src";

const password = "myverystrongpassword";
const thumbprint = "DL2CD4LN5JKHZYGWQQLH4R7H7Q";
const privateKey = Uint8Array.fromBase64("gU02EZAJiUyuFXSb7xCQeyeHEgndXcQ64KTKYNHVI2o=");
const encryptedPrivateKey = "eyJhbGciOiJzY3J5cHQiLCJwcm0iOnsiTiI6MTYzODQsInIiOjgsInAiOjF9LCJzbHQiOiJBc1BUZDluWDNLc1AyL1AwbXpNaUx3PT0iLCJrZXkiOiI4TThrRjRySkw2UVkwOHdqUmc1VW9MS05mL29vQzBCdXZpNnROOGZ5eW4vbkdJcnp2OVdEUDFjd3daWnpkbVN0Uk5uTFprZ2JMMnpzbkZUdy9tc0JXc3FqSzhtQkFsbS9aQ1ZPTU1Ea29HUlljc2ZpZ25GTE5ZcDVHTU5WNzVvUTRTVmVXeG84dG14Q3VGYjVEbE1qdWZNcGgyV0ZqVzM2UTBvYTBTZDB6VXRyYVhGaHBnb203dk42In0=";

describe("Secret key", async () => {
    const manuallyPrivKey = new SecretKey(privateKey);
    const importedPrivKey = await SecretKey.fromBase64(encryptedPrivateKey, password);

    test("Thumbprint", () => {
        expect(manuallyPrivKey.thumbprint).toBe(thumbprint);
        expect(importedPrivKey.thumbprint).toBe(thumbprint);
    });

    test("Export/Import to Base64", async () => {
        // Export -> Import -> Compare thumbprints
        expect((await SecretKey.fromBase64(await manuallyPrivKey.toBase64(password), password)).thumbprint).toBe(thumbprint);
        expect((await SecretKey.fromBase64(await importedPrivKey.toBase64(password), password)).thumbprint).toBe(thumbprint);
    });
});
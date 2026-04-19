import { describe, test, expect } from "bun:test";
import { ASPProfile } from "../src";

const checkHashedProof = true;

describe("[ES256] ASP Profile", () => {
    const thumbprint = "DL2CD4LN5JKHZYGWQQLH4R7H7Q";
    const publicKey = Uint8Array.fromBase64("BH6UaOXotayx7rPLZpaUnYB/uJ1kzgqSjbeczpZzzgd1HRh38oW5+Eb8AGbrcVsq+nAiQA4Kxwvnh2TAuq1icWQ=");
    const aspProfile = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkRMMkNENExONUpLSFpZR1dRUUxINFI3SDdRIiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiZnBSbzVlaTFyTEh1czh0bWxwU2RnSC00bldUT0NwS050NXpPbG5QT0IzVSIsInkiOiJIUmgzOG9XNS1FYjhBR2JyY1ZzcS1uQWlRQTRLeHd2bmgyVEF1cTFpY1dRIn19.eyJodHRwOi8vYXJpYWRuZS5pZC92ZXJzaW9uIjowLCJodHRwOi8vYXJpYWRuZS5pZC90eXBlIjoicHJvZmlsZSIsImh0dHA6Ly9hcmlhZG5lLmlkL25hbWUiOiJBbGljZSIsImh0dHA6Ly9hcmlhZG5lLmlkL2NsYWltcyI6WyJkbnM6ZG9tYWluLnRsZD90eXBlPXR4dCIsImh0dHBzOi8vZG9tYWluLnRsZC9AYWxpY2UiXSwiaHR0cDovL2FyaWFkbmUuaWQvZGVzY3JpcHRpb24iOiJIZWxsbywgQjBiIiwiaHR0cDovL2FyaWFkbmUuaWQvY29sb3IiOiIjNjg1NWMzIn0.TbkayNqxztFuefKt9bcB7xCsE3sVzZlLnAyUhyAcDCh2ddFp7W_spYjRZZ-lC3UDoJXEkNPFnLTsm0NNbBrylg";

    const profile = ASPProfile.fromBase64(aspProfile);

    test("Fields", () => {
        expect(profile.publicKey).toStrictEqual(publicKey);
        expect(profile.name).toBe("Alice");
        expect(profile.description).toBe("Hello, B0b");
        expect(profile.claims).toStrictEqual(["dns:domain.tld?type=txt", "https://domain.tld/@alice"]);
        expect(profile.color).toBe("#6855c3");
    });

    test("Thumbprint", () => expect(profile.thumbprint).toBe(thumbprint));

    test("ASPE URI (Direct proof)", () => expect(profile.getURI()).toBe(`aspe:keyoxide.org:${thumbprint}`));

    test.skipIf(!checkHashedProof)("Hashed proof", async () => {
        const proof = await profile.getHashedProof();

        expect(await Bun.password.verify(
            profile.getURI().toLowerCase(),
            proof,
            "argon2id"
        )).toBeTrue();
    }, 10000);
});

describe("[EdDSA] ASP Profile", () => {
    const thumbprint = "QPRGVPJNWDXH4ESK2RYDTZJLTE";
    const publicKey = Uint8Array.fromBase64("//poSQwNedopfLKP3ZgM6FXz9LIJszDZh5wKcoQF71U=");
    const aspProfile = "eyJ0eXAiOiJKV1QiLCJraWQiOiJRUFJHVlBKTldEWEg0RVNLMlJZRFRaSkxURSIsImp3ayI6eyJrdHkiOiJPS1AiLCJ1c2UiOiJzaWciLCJjcnYiOiJFZDI1NTE5IiwieCI6Il9fcG9TUXdOZWRvcGZMS1AzWmdNNkZYejlMSUpzekRaaDV3S2NvUUY3MVUifSwiYWxnIjoiRWREU0EifQ.eyJodHRwOi8vYXJpYWRuZS5pZC92ZXJzaW9uIjowLCJodHRwOi8vYXJpYWRuZS5pZC90eXBlIjoicHJvZmlsZSIsImh0dHA6Ly9hcmlhZG5lLmlkL25hbWUiOiJ0ZXN0IiwiaHR0cDovL2FyaWFkbmUuaWQvY2xhaW1zIjpbImh0dHBzOi8vZG9tYWluLnRsZC91c2VyL3Rlc3QiLCJodHRwczovL2Fub3RoZXIudGxkL3Rlc3QiXX0.yiBJbaB2oyprfRzYcmP-iz3C-5PGwV1Yc5iDSLW_2JFKVPKH3BKL2mUHE62VvyH1EiXDfWjpGae7jT1bM8PSAQ";

    const profile = ASPProfile.fromBase64(aspProfile);
    
    test("Fields", () => {
        expect(profile.publicKey).toStrictEqual(publicKey);
        expect(profile.name).toBe("test");
        expect(profile.description).toBe("");
        expect(profile.claims).toStrictEqual(["https://domain.tld/user/test", "https://another.tld/test"]);
        expect(profile.color).toBe("");
    });

    test("Thumbprint", () => expect(profile.thumbprint).toBe(thumbprint));

    test("ASPE URI (Direct proof)", () => expect(profile.getURI()).toBe(`aspe:keyoxide.org:${thumbprint}`));

    test.skipIf(!checkHashedProof)("Hashed proof", async () => {
        const proof = await profile.getHashedProof();

        expect(await Bun.password.verify(
            profile.getURI().toLowerCase(),
            proof,
            "argon2id"
        )).toBeTrue();
    }, 10000);
});
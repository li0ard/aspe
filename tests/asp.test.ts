import { describe, test, expect } from "bun:test";
import { ASPProfile } from "../src";

const thumbprint = "DL2CD4LN5JKHZYGWQQLH4R7H7Q";
const publicKey = Uint8Array.fromBase64("BH6UaOXotayx7rPLZpaUnYB/uJ1kzgqSjbeczpZzzgd1HRh38oW5+Eb8AGbrcVsq+nAiQA4Kxwvnh2TAuq1icWQ=");
const aspProfile = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkRMMkNENExONUpLSFpZR1dRUUxINFI3SDdRIiwiandrIjp7ImNydiI6IlAtMjU2Iiwia3R5IjoiRUMiLCJ4IjoiZnBSbzVlaTFyTEh1czh0bWxwU2RnSC00bldUT0NwS050NXpPbG5QT0IzVSIsInkiOiJIUmgzOG9XNS1FYjhBR2JyY1ZzcS1uQWlRQTRLeHd2bmgyVEF1cTFpY1dRIn19.eyJodHRwOi8vYXJpYWRuZS5pZC92ZXJzaW9uIjowLCJodHRwOi8vYXJpYWRuZS5pZC90eXBlIjoicHJvZmlsZSIsImh0dHA6Ly9hcmlhZG5lLmlkL25hbWUiOiJBbGljZSIsImh0dHA6Ly9hcmlhZG5lLmlkL2NsYWltcyI6WyJkbnM6ZG9tYWluLnRsZD90eXBlPXR4dCIsImh0dHBzOi8vZG9tYWluLnRsZC9AYWxpY2UiXSwiaHR0cDovL2FyaWFkbmUuaWQvZGVzY3JpcHRpb24iOiJIZWxsbywgQjBiIiwiaHR0cDovL2FyaWFkbmUuaWQvY29sb3IiOiIjNjg1NWMzIn0.TbkayNqxztFuefKt9bcB7xCsE3sVzZlLnAyUhyAcDCh2ddFp7W_spYjRZZ-lC3UDoJXEkNPFnLTsm0NNbBrylg";

describe("ASP Profile", () => {
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

    test("Hashed proof", async () => {
        const proof = await profile.getHashedProof();

        expect(await Bun.password.verify(
            profile.getURI().toLowerCase(),
            proof,
            "argon2id"
        )).toBeTrue();
    }, 10000);
})
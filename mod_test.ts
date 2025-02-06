import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { encode, verify } from "./mod.ts";

Deno.test("JWT encode and verify", async () => {
  const secretKey = "test-secret";
  const payload = {
    iss: "test-issuer",
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
  };

  const token = await encode(payload, secretKey);
  
  // Test token generation
  assertEquals(typeof token, "string");
  assertEquals(token.split(".").length, 3);

  // Test verification
  const isValid = await verify(token, secretKey);
  assertEquals(isValid, true);
});

Deno.test("JWT verification fails with wrong secret", async () => {
  const secretKey = "test-secret";
  const wrongSecret = "wrong-secret";
  const payload = {
    iss: "test-issuer",
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  const token = await encode(payload, secretKey);
  const isValid = await verify(token, wrongSecret);
  assertEquals(isValid, false);
});

Deno.test("JWT verification fails with malformed token", async () => {
  const secretKey = "test-secret";
  const malformedToken = "invalid.token.parts";
  
  const isValid = await verify(malformedToken, secretKey);
  assertEquals(isValid, false);
});
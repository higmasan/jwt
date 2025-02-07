import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { encode, verify } from "./mod.ts"; 

/**
 * JWT のエンコードと検証（デフォルトアルゴリズム）のテスト
 */
Deno.test("JWT sign and verify with default algorithm", async () => {
  const secretKey = "test-secret-key-with-sufficient-length";
  const payload = {
    sub: "1234567890",
    name: "John Doe",
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
  };

  const token = await encode(payload, secretKey);
  const verificationResult = await verify(token, secretKey);

  assertEquals(verificationResult, 'valid');
});

/**
 * 異なるアルゴリズムでの JWT 検証テスト
 */
Deno.test("JWT verification with different algorithms", async () => {
  const secretKey = "test-secret-key-with-sufficient-length";
  const algorithms: Array<'HS256' | 'HS384' | 'HS512'> = ['HS256', 'HS384', 'HS512'];

  for (const alg of algorithms) {
    const payload = {
      alg,
      exp: Math.floor(Date.now() / 1000) + 3600
    };

    const token = await encode(payload, secretKey, alg);
    const verificationResult = await verify(token, secretKey, alg);

    assertEquals(verificationResult, 'valid');
  }
});

/**
 * 期限切れトークンでの JWT 検証失敗テスト
 */
Deno.test("JWT verification fails with expired token", async () => {
  const secretKey = "test-secret-key-with-sufficient-length";
  const payload = {
    exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
  };

  const token = await encode(payload, secretKey);
  const verificationResult = await verify(token, secretKey);

  assertEquals(verificationResult, 'expired');
});

/**
 * 間違った秘密鍵での JWT 検証失敗テスト
 */
Deno.test("JWT verification fails with wrong secret", async () => {
  const secretKey = "test-secret-key-with-sufficient-length";
  const wrongSecret = "different-secret-key";
  const payload = {
    exp: Math.floor(Date.now() / 1000) + 3600
  };

  const token = await encode(payload, secretKey);
  const verificationResult = await verify(token, wrongSecret);

  assertEquals(verificationResult, 'invalid');
});
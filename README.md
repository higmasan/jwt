# JWT Library ✨🚀🎉

A lightweight JSON Web Token (JWT) library for Deno, supporting HMAC (HS256, HS384, HS512) algorithms. 🔐💡📦

## Features 🌟
- Encode and decode JWTs
- Supports `HS256`, `HS384`, and `HS512` algorithms
- Expiration and validity checks
- Leeway support for expiration time

## Installation 🔧📥💻
This module can be imported directly from Deno's ecosystem:

```typescript
import { encode, verify } from "jsr:@hig/jwt";
```

## Usage 🎯👨‍💻🎉

### Encode a JWT 🔑✍️
```typescript
import { encode } from "jsr:@hig/jwt";

const payload = {
  userId: "123",
  exp: Math.floor(Date.now() / 1000) + 60 * 60, // Expires in 1 hour
};
const secretKey = "your-secret-key";
const token = await encode(payload, secretKey);

console.log(token); // eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...
```

### Verify a JWT ✅🔎💥
```typescript
import { verify } from "jsr:@hig/jwt";

const token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...";
const secretKey = "your-secret-key";
const result = await verify(token, secretKey);

console.log(result); // 'valid' | 'invalid' | 'expired'
```

## API 💻🔒✨

### `encode(payload: Payload, secretKey: string, algorithm: Algorithm = 'HS256'): Promise<string>`
Generates a JWT.

**Parameters:**
- `payload`: The JWT payload (must include `exp` field for expiration)
- `secretKey`: Secret key used for signing the token
- `algorithm`: HMAC algorithm to use (`HS256`, `HS384`, `HS512`), default is `HS256`

**Returns:**
- A JWT string

### `verify(token: string, secretKey: string, algorithm: Algorithm = 'HS256', leeway: number = 0): Promise<'valid' | 'invalid' | 'expired'>`
Validates a JWT.

**Parameters:**
- `token`: The JWT string to verify
- `secretKey`: Secret key used for verification
- `algorithm`: HMAC algorithm to use (`HS256`, `HS384`, `HS512`), default is `HS256`
- `leeway`: Time in seconds to allow for expiration (default is `0`)

**Returns:**
- `'valid'` if the token is valid
- `'invalid'` if the token signature is incorrect or malformed
- `'expired'` if the token is expired

## License 📜✨🔓

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

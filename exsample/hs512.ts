import { encode, verify } from "../mod.ts";

const secretKey = "test-secret-key-with-sufficient-length";
const payload = {
  sub: "1234567890",
  name: "John Doe",
  exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
};

async function handleRequest(req: Request) {
  if (req.method === "GET") {
    return new Response(await encode(payload, secretKey, "HS512"))
  } else {
    try {
      const jwt = JSON.parse(await req.text())
      const payload = await verify(jwt, secretKey, "HS512")
      return Response.json(payload)
    } catch {
      return new Response("Invalid JWT\n", { status: 401 })
    }
  }
}

Deno.serve(handleRequest)

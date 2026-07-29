# `@ngriffin_uk/auth-cookie`

Strict cookie parsing and serialisation with secure session defaults.

```sh
pnpm add @ngriffin_uk/auth-cookie
```

```ts
import {
  parseCookies,
  serializeExpiredCookie,
  serializeSessionCookie,
} from "@ngriffin_uk/auth-cookie";

const cookies = parseCookies(request.headers.get("Cookie") ?? "");
const setCookie = serializeSessionCookie("__Host-session", sessionToken);
const clearCookie = serializeExpiredCookie("__Host-session");
```

Cookie transport remains the service's responsibility. Prefer `__Host-`
cookies with `HttpOnly`, `Secure`, a narrow path, and `SameSite=Lax` or
stricter.

# `@ngriffin_uk/auth-request`

Exact origin checks for CSRF protection on cookie-authenticated requests, plus
bounded outbound response and timeout helpers for provider integrations.

```sh
pnpm add @ngriffin_uk/auth-request
```

```ts
import { assertRequestCsrf } from "@ngriffin_uk/auth-request";

assertRequestCsrf(request, ["https://app.example.com"]);
```

Safe methods (`GET`, `HEAD`, and `OPTIONS`) pass without an Origin header.
State-changing requests require an exact allowed origin and reject
`Sec-Fetch-Site: cross-site`.

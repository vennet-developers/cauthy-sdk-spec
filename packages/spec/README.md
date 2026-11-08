# @cauthyhq/spec

TypeScript types of Cauthy's public API (`openapi/cauthy.yaml`) and of the auth-bff protocol
(`openapi/auth-bff.yaml`), generated from [cauthy-sdk-spec](https://github.com/vennet-developers/cauthy-sdk-spec).
Types only: there is no JavaScript in this package.

```ts
import type { CauthyData, CauthySchema, CauthyPaths } from '@cauthyhq/spec'

type Settings = CauthyData<CauthySchema<'WorkspaceAuthSettings'>>
type UserInfo = CauthyPaths['/v1/oauth/userinfo']['get']['responses'][200]['content']['application/json']
```

The version of this package is its own; `cauthy.protocol` in its `package.json` is the
auth-bff protocol version its types describe.

License: Apache-2.0.

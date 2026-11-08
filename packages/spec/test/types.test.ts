// Compile-time checks: tsc fails when a name these lines use leaves the documents.
import type { AuthBffPaths, CauthyData, CauthyList, CauthyPaths, CauthySchema, ProtocolVersion } from '../index.js'

const settings: CauthyData<CauthySchema<'WorkspaceAuthSettings'>> = { data: { allow_signup: true, verify_grace_days: 0 } }
const userinfo: CauthySchema<'OAuthUserInfo'> = { sub: 'u1', tid: 't1', roles: ['member'] }
type UserInfoAnswer = CauthyPaths['/v1/oauth/userinfo']['get']['responses'][200]['content']['application/json']
const answered: UserInfoAnswer = userinfo
const clients: CauthyList<CauthySchema<'OAuthClient'>> = { data: [{ client_id: 'acme-crm' }], total_count: 1 }
type Methods = AuthBffPaths['/methods']['get']
const version: ProtocolVersion = 1

export { answered, clients, settings, version }
export type { Methods }

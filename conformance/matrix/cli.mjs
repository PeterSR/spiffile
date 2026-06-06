// Parity CLI: mint or verify a token using the TypeScript implementation.
// Requires `npm run build` in ts/ first (imports from ts/dist).
//
// Usage:
//   node cli.mjs mint <root> <service> <aud-service>
//   node cli.mjs verify <root> <service> <token> <expected-sub-service>
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const here = dirname(fileURLToPath(import.meta.url))
const { provision } = await import(join(here, "..", "..", "ts", "dist", "src", "index.js"))

const TRUST_DOMAIN = "parity.test"
const [command, root, service, a, b] = process.argv.slice(2)

if (command === "mint") {
  const identity = provision.loadIdentity(root, service)
  process.stdout.write(identity.token(`spiffe://${TRUST_DOMAIN}/${a}`))
} else if (command === "verify") {
  const identity = provision.loadIdentity(root, service)
  const caller = identity.verify(a)
  if (caller.id.toString() !== `spiffe://${TRUST_DOMAIN}/${b}`) {
    throw new Error(`unexpected caller ${caller.id}`)
  }
  console.log(`node verified caller=${caller.id}`)
} else {
  throw new Error(`unknown command '${command}'`)
}

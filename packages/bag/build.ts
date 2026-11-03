// npm run build -w packages/bag (node packages/bag/build.ts): builds dist/ from this checkout (src/build.ts) and prints
// the version, the commit, the files and the bundled npm packages.
import { build } from './src/build.ts'

const built = await build()
console.log(`@usebag/bag ${built.version} ${built.commit}`)
for (const f of built.files) console.log(`  dist/${f}`)
console.log(`bundled npm packages: ${built.packages.map((d) => d.replace('node_modules/', '')).join(', ')}`)

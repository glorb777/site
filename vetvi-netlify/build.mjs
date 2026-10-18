import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist',{recursive:true});
await build({entryPoints:['src/main.tsx'],bundle:true,minify:true,outdir:'dist',entryNames:'app',jsx:'automatic',target:['es2022'],define:{'process.env.NODE_ENV':'"production"'},legalComments:'eof'});
await copyFile('public/index.html','dist/index.html');
await copyFile('public/favicon.svg','dist/favicon.svg');
console.log('Готово: dist/ и netlify/functions/');

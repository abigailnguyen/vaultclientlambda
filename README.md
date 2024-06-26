# vaultclientlambda

The request are signed before sending to AWS based on their signing documentation
https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html 


Steps to create files in this repo:
1. Run `npm init`
2. Run `npm install -D typescript ts-node`
3. Run `npx tsc --init`
4. Run `npx ts-node src/index`
5. Run `npm run build` to build locally
6. Run `npm run build:tsup` to build with tsup to a js bundle
7. Test package before publishing locally
   Run `npm link` at the root of the package
   Run `npm link npm-demo-ts` to create a demo package to import our `vaultclientlambda` package
   Create a file `main.ts` and add the following to test that you can see the type definition of function add
   ```javascript
        import { add } from "@abigailnguyen/vaultclientlambda"
        console.log(add(2, 6))
   ```
   
We use `tsup` to bundle js , other popular tools are tsup, babel, webpack, rollup 

Publish to registry
1. View that you have authorized locally with `vi ~/.npmrc` or following GitHub npm registry setup to before next step
2. Fix the version in `package.json` file
3. Run `npm publish`
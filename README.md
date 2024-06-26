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


We use `tsup` to bundle js , other popular tools are tsup, babel, webpack, rollup 
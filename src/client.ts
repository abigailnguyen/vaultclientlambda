import { defaultProvider } from "@aws-sdk/credential-provider-node";
import { createRequest } from "@aws-sdk/util-create-request";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { SignatureV4 } from "@smithy/signature-v4";
import { Sha256 } from "@aws-crypto/sha256-js";
import { HttpRequest } from "@smithy/types";
import { request } from "gaxios";

/**
  We sets the baseUrl and default X-Vault-Request to tell Vault that this is a request with a Vault token to access token
**/
const defaults = {
  baseURL: process.env.BASE_URL,
  headers: {
    "X-Vault-Request": true,
    "User-Agent": "VAULTCLIENT",
  },
};
/**
This is a built in util function from AWS to create a signed request based on their specs
https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
**/
async function getSignedRequest() {
  const credential = defaultProvider();
  const request = await createRequest(
    new STSClient({ region: "us-east-1" }),
    new GetCallerIdentityCommand({}),
  );
  const signer = new SignatureV4({
    applyChecksum: true,
    region: "us-east-1",
    service: "sts",
    sha256: Sha256,
    credentials: credential,
    uriEscapePath: true,
  });
  const signedRequest = await signer.sign(request);
  return signedRequest;
}

/**
The request body to send to Vault with AWS authentication
**/
function getVaultAuthRequestBody(stsRequest: HttpRequest) {
  const googleLikeHeaders = {};
  for (const e of Object.entries(stsRequest.headers)) {
    if (!e[1]) continue;
    googleLikeHeaders[e[0]] = [e[1]];
  }
  return {
    iam_http_request_method: stsRequest.method,
    iam_request_headers: Buffer.from(
      JSON.stringify(googleLikeHeaders),
    ).toString("base64"),
    iam_request_body: Buffer.from(stsRequest.body).toString("base64"),
    iam_request_url: Buffer.from(
      `https://${stsRequest.hostname}${stsRequest.path}`,
    ).toString("base64"),
    role: `aws_${process.env.ROLE_SET}`,
  };
}

/**
The request to send to Vault to retrieve GCP token based on Vault API
**/
async function getGcpToken(vaultToken: string) {
  const res = await request({
    ...defaults,
    method: "GET",
    url: `/gcp/token/${process.env.ROLE_SET}`,
    headers: {
      ...defaults.headers,
      "X-Vault-Token": vaultToken,
    },
  });
  return res.data["data"]["token"];
}
/**
This request sends to Vault to authenticate with AWS credential
**/
async function getVaultAuthToken(postData: string) {
  const res = await request({
    ...defaults,
    method: "POST",
    url: "/auth/aws/login",
    headers: {
      ...defaults.headers,
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(postData),
    },
    data: postData,
  });
  return res.data["auth"]["client_token"];
}

export async function generateGCPToken() {
  const request = await getSignedRequest();
  const vaultAuthReqBody = JSON.stringify(getVaultAuthRequestBody(request));
  const vaultToken = await getVaultAuthToken(vaultAuthReqBody);
  const gcpToken = await getGcpToken(vaultToken);
  return gcpToken;
}

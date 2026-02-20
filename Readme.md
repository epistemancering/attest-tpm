# `attest-tpm`
Hardware protected Code Signing without USB tokens. Run a CA/B compliant Code Signing certificate authority that requires Trusted Platform Module key attestation, or use your TPM to obtain a certificate from such an authority and sign `.exe` files. The only dependency is [Koffi](https://koffi.dev). Typescript is supported.

Basic TPM client using `austinhenrie.com`:
```javascript
import * as fs from "fs"
import * as attestTPM from "attest-tpm"
const exe = fs.readFileSync(".exe")

;(async () => {
    const tpmCreate = await attestTPM.tpmCreate()

    fs.writeFileSync(
        "signed.exe",
        await attestTPM.tpmSign(
            tpmCreate.keys,
            await attestTPM.tpmDecrypt(
                tpmCreate.keys,
                await (await fetch(
                    "https://tpm-authority.austinhenrie.com",
                    { method: "POST", body: tpmCreate.body }
                )).json()
            ),
            exe
        )
    )

    fs.writeFileSync(
        "root.cer",
        await (await fetch("https://tpm-authority.austinhenrie.com")).bytes()
    )

    // open `root.cer`, click Install Certificate, and place it in Trusted Root
    // Certification Authorities
})()
```
Basic authority server:
```javascript
import * as http from "http"
import * as attestTPM from "attest-tpm"

(async () => {
    const cerKeys = await crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 4096,
            publicExponent: Uint8Array.from([1, 0, 1]),
            hash: "SHA-256"
        },
        false,
        ["sign"]
    )

    const signCer = (/**@type {ArrayBuffer}*/ cer) => {
        return crypto.subtle.sign("rsassa-pkcs1-v1_5", cerKeys.privateKey, cer)
    }

    const authorityCers = await attestTPM.authorityCers(
        cerKeys.publicKey,
        cerKeys.publicKey,
        signCer
    )

    http.createServer(async (request, response) => {
        let responseContent

        if (request.method?.[3]) {
            for await (const content of request) {
                responseContent = (await attestTPM.authorityIssue(
                    authorityCers.Intermediate,
                    content,
                    signCer
                )).response
            }
        } else {
            responseContent = authorityCers["Trusted Root"]
        }

        response.end(responseContent)
    }).listen(80)
})()
```
## install
```bash
npm install attest-tpm
```
## use
### `attestTPM.authorityCers`
Creates Trusted Root and Intermediate certificates.
#### arguments
1. required: A `CryptoKey` to use as the Trusted Root certificate's Public key. Must have `algorithm: { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-256" }`.
1. required: A `CryptoKey` to use as the Intermediate certificate's Public key. Must have `algorithm: { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-256" }`.
1. required: A function to sign the certificates with the private key matching the Trusted Root certificate. Must accept an `ArrayBuffer` of the Details and return an `ArrayBuffer` of the signature.
1. optional: An object with certificate fields.
    - `Issued by`: A string to use as the Trusted Root certificate's Issued by and Issued to and the Intermediate certificate's Issued by.
    - `O`: A string to use as the O in the Trusted Root certificate's Issuer and Subject and in the Intermediate certificate's Issuer.
    - `C`: A string to use as the C in the Trusted Root certificate's Issuer and Subject and in the Intermediate certificate's Issuer. Must be two characters.
    - `Issued to`: A string to use as the Intermediate certificate's Issued to.
    - `On-line Certificate Status Protocol`: A string to use as the On-line Certificate Status Protocol URL in the Intermediate certificate's Authority Information Access.
    - `CRL Distribution Points`: A string to use as the Intermediate certificate's CRL Distribution Points URL.
#### returns
An object with certificates.
- `Trusted Root`: A `Uint8Array` of a `.cer` of a Trusted Root certificate.
- `Intermediate`: A `Uint8Array` of a `.cer` of an Intermediate certificate.
### `attestTPM.tpmCreate`
Creates TPM keys.
#### environment
Must run on a Windows computer with a TPM that supports 3072 bit keys.
#### returns
An object with a key pair and certificate request.
- `keys`: A `Uint8Array` of a key pair that can be provided to `attestTPM.tpmDecrypt` and `attestTPM.tpmSign`. The private key is encrypted by the TPM.
- `body`: A JSON string that can be provided to `attestTPM.authorityIssue`.
    - `cer`: The TPM certificate.
    - `Public key`: The public key from `keys`.
### `attestTPM.authorityIssue`
Verifies whether a certificate was issued by a TPM manufacturer and creates a Code Signing certificate if so.
#### arguments
1. required: A `Uint8Array` of a `.cer` of an Intermediate certificate.
1. required: A `Uint8Array` of a `body` from `attestTPM.tpmCreate`.
1. required: A function to sign the Code Signing certificate with the private key matching the Intermediate certificate's Public key. Must accept an `ArrayBuffer` of the Details and return an `ArrayBuffer` of the signature.
1. optional: An object with Code Signing certificate fields.
    - `Issued to`: A string to use as the Issued to.
    - `O`: A string to use as the Subject O.
    - `L`: A string to use as the Subject L.
    - `C`: A string to use as the Subject C. Must be two characters.
    - `On-line Certificate Status Protocol`: A string to use as the On-line Certificate Status Protocol URL in Authority Information Access.
    - `Certification Authority Issuer`: A string to use as the Certification Authority Issuer URL in Authority Information Access.
    - `CRL Distribution Points`: A string to use as the CRL Distribution Points URL.
#### returns
If `body` verifies, an object with TPM information and certificates.
- `TPMModel`: A string of the model.
- `TPMVersion`: A string of the firmware version.
- `response`: A JSON string that can be provided to `attestTPM.tpmDecrypt`.
    - `Intermediate`: The Intermediate certificate.
    - `key`: A key encrypted such that it can be decrypted by only that individual TPM and only if the private key is inextractable and 3072 bits.
    - `Code Signing`: A Code Signing certificate encrypted by `key`.
- `Serial number`: A string of `Code Signing`'s Serial number.

If `body` doesn't `verify`, an object with an error.
- `error`: A string of an error message.
### `attestTPM.tpmDecrypt`
Uses a TPM to decrypt a Code Signing certificate.
#### environment
Must run as administrator on a Windows computer with the TPM that created the keys.
#### arguments
1. required: A `Uint8Array` of `keys` from `attestTPM.tpmCreate`.
1. required: An object of the parsed `response` from `attestTPM.authorityIssue`.
#### returns
A `Uint8Array` of a `.p7b` of the Code Signing and Intermediate certificates.
### `attestTPM.tpmSign`
Uses a TPM to sign an `.exe`.
#### environment
Must run on a Windows computer with the TPM that created the keys.
#### arguments
1. required: A `Uint8Array` of `keys` from `attestTPM.tpmCreate`.
1. required: A `Uint8Array` of a `.p7b` of the Code Signing and Intermediate certificates.
1. required: A `Uint8Array` of an `.exe`.
#### returns
A `Uint8Array` of a signed and timestamped `.exe`.
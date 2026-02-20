import koffi from "koffi"
/**@import os from "os"*/

const authorityFields = {
    /**The Trusted Root certificate's Issued by and Issued to and the Intermediate certificate's Issued by.*/ "Issued by": "",
    /**O in the Trusted Root certificate's Issuer and Subject and in the Intermediate certificate's Issuer.*/ O: "",
    /**C in the Trusted Root certificate's Issuer and Subject and in the Intermediate certificate's Issuer. Must be two characters.*/ C: "",
    /**The Intermediate certificate's Issued to.*/ "Issued to": "",
    /**The On-line Certificate Status Protocol URL in the Intermediate certificate's Authority Information Access.*/ "On-line Certificate Status Protocol": "",
    /**The Intermediate certificate's CRL Distribution Points URL.*/ "CRL Distribution Points": ""
}

const C = (/**@type {string=}*/ C) => {
    const subjectC = [11, 48, 9, 6, 3, 85, 4, 6, 12, 2]

    if (C) {
        subjectC.push(...Array.from(
            C,
            (character) => {
                return character.charCodeAt(0)
            }
        ))
    } else {
        subjectC.push(85, 83)
    }

    return subjectC
}

const prependLength = (/**@type {number[]}*/ bytes) => {
    const prependedBytes = []

    if (bytes[255] === undefined) {
        if (bytes[127] !== undefined) {
            prependedBytes[0] = 129
        }

        prependedBytes[prependedBytes.length] = bytes.length
    } else {
        const bytesLength = Math.floor(bytes.length / 256)
        prependedBytes.push(130, bytesLength, bytes.length - 256 * bytesLength)
    }

    prependedBytes.push(...bytes)
    return prependedBytes
}

const O = (/**@type {string=}*/ O) => {
    const subjectO = []

    if (O) {
        subjectO.push(...Array.from(
            O,
            (character) => {
                return character.charCodeAt(0)
            }
        ))
    }

    return [49, 128, 48, 128, 6, 3, 85, 4, 10, 12, ...prependLength(subjectO), 0, 0, 0, 0, 49]
}

const Issued = (/**@type {string}*/ Issued) => {
    return [
        128,
        48,
        128,
        6,
        3,
        85,
        4,
        3,
        12,
        ...prependLength(Array.from(
            Issued,
            (character) => {
                return character.charCodeAt(0)
            }
        )),
        0,
        0,
        0,
        0
    ]
}

const createCer = async (/**@type {number[]}*/ Issuer, /**@type {number[]}*/ Valid, /**@type {number[]}*/ Subject, /**@type {string}*/ Publickey, /**@type {number[]}*/ Fields, /**@type {number}*/ KeyUsage, /**@type {(Details: ArrayBuffer) => Promise<ArrayBuffer>}*/ sign) => {
    const Serialnumber = [0, ...crypto.getRandomValues(new Uint8Array(8))]

    const Details = Uint8Array.from([
        48,
        ...prependLength([
            160,
            3,
            2,
            1,
            2,
            2,
            9,
            ...Serialnumber,
            48,
            11,
            6,
            9,
            42,
            134,
            72,
            134,
            247,
            13,
            1,
            1,
            11,
            48,
            ...prependLength([49, ...Issuer]),
            48,
            24,
            23,
            10,
            ...Valid,
            48,
            ...prependLength([49, ...Subject]),
            48,
            ...prependLength([
                48,
                11,
                6,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                1,
                1,
                3,
                ...prependLength([
                    0,
                    48,
                    128,
                    2,
                    ...prependLength(Array.from(
                        Publickey,
                        (character) => {
                            return character.charCodeAt(0)
                        }
                    )),
                    2,
                    3,
                    1,
                    0,
                    1,
                    0,
                    0
                ])
            ]),
            163,
            128,
            48,
            128,
            48,
            ...Fields,
            48,
            14,
            6,
            3,
            85,
            29,
            15,
            1,
            1,
            255,
            4,
            4,
            3,
            2,
            0,
            KeyUsage,
            0,
            0,
            0,
            0
        ])
    ])

    return { cer: Uint8Array.from([48, 128, ...Details, 48, 11, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 3, 130, 2, 1, 0, ...new Uint8Array(await sign(Details.buffer)), 0, 0]), "Serial number": Serialnumber }
}

const OnlineCertificateStatusProtocol = (/**@type {string}*/ URL) => {
    return [
        48,
        128,
        6,
        8,
        43,
        6,
        1,
        5,
        5,
        7,
        48,
        1,
        134,
        ...prependLength(Array.from(
            URL,
            (character) => {
                return character.charCodeAt(0)
            }
        )),
        0,
        0
    ]
}

const signingFields = (/**@type {number[]}*/ AuthorityInformationAccess, /**@type {{ "CRL Distribution Points"?: string }=}*/ Fields) => {
    let URL = Fields?.["CRL Distribution Points"]

    if (!URL) {
        URL = ""
    }

    return [
        128,
        6,
        8,
        43,
        6,
        1,
        5,
        5,
        7,
        1,
        1,
        4,
        ...prependLength([48, 128, ...AuthorityInformationAccess, 0, 0]),
        0,
        0,
        48,
        128,
        6,
        3,
        85,
        29,
        31,
        4,
        ...prependLength([
            48,
            128,
            48,
            128,
            160,
            128,
            160,
            128,
            134,
            ...prependLength(Array.from(
                URL,
                (character) => {
                    return character.charCodeAt(0)
                }
            )),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]),
        0,
        0,
        48,
        19,
        6,
        3,
        85,
        29,
        37,
        4,
        12,
        48,
        10,
        6,
        8,
        43,
        6,
        1,
        5,
        5,
        7,
        3,
        3,
        48,
        19,
        6,
        3,
        85,
        29,
        32,
        4,
        12,
        48,
        10,
        48,
        8,
        6,
        6,
        103,
        129,
        12,
        1,
        4,
        1,
        48,
        31,
        6,
        3,
        85,
        29,
        35,
        4,
        24,
        48,
        22,
        128,
        20,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    ]
}

export const /**Create Trusted Root and Intermediate certificates.*/ authorityCers = async (
    /**The Trusted Root certificate's Public key. Must have `algorithm: { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-256" }`. @type {CryptoKey}*/ TrustedRoot,
    /**The Intermediate certificate's Public key. Must have `algorithm: { name: "RSASSA-PKCS1-v1_5", modulusLength: 4096, publicExponent: Uint8Array.from([1, 0, 1]), hash: "SHA-256" }`. @type {CryptoKey}*/ Intermediate,
    /**A function to sign the certificates with the private key matching the Trusted Root certificate. @type {(Details: ArrayBuffer) => Promise<ArrayBuffer>}*/ sign,
    /**The certificate fields. @type {Partial<authorityFields>}*/ Fields = {}
) => {
    if (TrustedRoot.extractable) {
        if (TrustedRoot.algorithm.name === "RSASSA-PKCS1-v1_5") {
            if (Intermediate.extractable) {
                if (Intermediate.algorithm.name === "RSASSA-PKCS1-v1_5") {
                    let Issuedby = Fields["Issued by"]

                    if (!Issuedby) {
                        Issuedby = "\0"
                    }

                    let Issuedto = Fields["Issued to"]

                    if (!Issuedto) {
                        Issuedto = "\0"
                    }

                    if (Issuedby === Issuedto) {
                        Issuedby += "\0"
                    }

                    const Issuer = [...C(Fields.C), ...O(Fields.O), ...Issued(Issuedby)]
                    const Valid = [48, 48, 48, 49, 48, 49, 48, 48, 48, 48, 23, 10, 52, 57, 49, 50, 51, 49, 50, 51, 53, 57]
                    let URL = Fields["On-line Certificate Status Protocol"]

                    if (!URL) {
                        URL = ""
                    }

                    return {
                        /**A Trusted Root certificate.*/ "Trusted Root": (await createCer(Issuer, Valid, Issuer, atob(/**@type {string}*/((await crypto.subtle.exportKey("jwk", TrustedRoot)).n).replaceAll("_", "/").replaceAll("-", "+")), [15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255], 6, sign)).cer,
                        /**An Intermediate certificate.*/ Intermediate: (await createCer(Issuer, Valid, Issued(Issuedto), atob(/**@type {string}*/((await crypto.subtle.exportKey("jwk", Intermediate)).n).replaceAll("_", "/").replaceAll("-", "+")), [...signingFields(OnlineCertificateStatusProtocol(URL), Fields), 48, 15, 6, 3, 85, 29, 19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255], 6, sign)).cer
                    }
                }

                throw new Error("`Intermediate` key isn't `RSASSA-PKCS1-v1_5`")
            }

            throw new Error("`Intermediate` key isn't `extractable`")
        }

        throw new Error("`Trusted Root` key isn't `RSASSA-PKCS1-v1_5`")
    }

    throw new Error("`Trusted Root` key isn't `extractable`")
}

const Tbsi_Context_Create = () => {
    let tbs

    try {
        tbs = koffi.load("tbs").func
    } catch {
        throw new Error("`attestTPM.tpm` functions must run on Windows")
    }

    const Tbsip_Submit_Command = tbs("Tbsip_Submit_Command", "int", ["int", "void *", "void *", "uint8 *", "int", "uint8 *", "uint8 *"])
    const contextResponse = new ArrayBuffer(4)
    tbs("Tbsi_Context_Create", "void", ["uint8 *", "uint8 *"])([2, 0, 0, 0, 4, 0, 0, 0], contextResponse)
    const tbsContext = new DataView(contextResponse).getUint32(0, true)

    return (/**@type {number[]}*/ command) => {
        const commandResponse = new Uint8Array(1045)

        if (!(Tbsip_Submit_Command(tbsContext, undefined, undefined, command, command.length, commandResponse, [21, 4, 0, 0]) || new DataView(commandResponse.buffer).getUint32(6))) {
            return commandResponse
        }
    }
}

export const /**Create TPM keys.*/ tpmCreate = async () => {
    const Tbsip_Submit_Command = Tbsi_Context_Create()
    const signingKey = Tbsip_Submit_Command([128, 2, 0, 0, 0, 63, 0, 0, 1, 83, 129, 0, 0, 1, 0, 0, 0, 9, 64, 0, 0, 9, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 22, 0, 1, 0, 11, 0, 4, 0, 114, 0, 0, 0, 16, 0, 16, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

    if (signingKey) {
        const keys = signingKey.slice(14, new DataView(signingKey.buffer).getUint16(14) + 424)
        const savedCer = Tbsip_Submit_Command([128, 1, 0, 0, 0, 14, 0, 0, 1, 105, 1, 192, 0, 2])
        let cer

        if (savedCer) {
            let tpmCer = ""
            const cerLength = new DataView(savedCer.buffer).getUint16(24)

            while (tpmCer.length !== cerLength) {
                const cerCommand = [128, 2, 0, 0, 0, 35, 0, 0, 1, 78, 1, 192, 0, 2, 1, 192, 0, 2, 0, 0, 0, 9, 64, 0, 0, 9, 0, 0, 0, 0, 0]
                let /**@type {number}*/ responseLength = cerLength - tpmCer.length

                if (responseLength > 1023) {
                    cerCommand.push(4, 0)
                    responseLength = 1024
                } else {
                    const lengthBytes = new Uint8Array(2)
                    new DataView(lengthBytes.buffer).setUint16(0, responseLength)
                    cerCommand.push(...lengthBytes)
                }

                cerCommand.push(tpmCer.length / 256, 0)
                tpmCer += String.fromCharCode(.../**@type {Uint8Array}*/(Tbsip_Submit_Command(cerCommand)).slice(16, responseLength + 16))
            }

            cer = btoa(tpmCer)
        } else {
            const cerKey = /**@type {Uint8Array}*/(Tbsip_Submit_Command([128, 1, 0, 0, 0, 14, 0, 0, 1, 115, 129, 1, 0, 1])).slice(70, 326)

            if (String.fromCharCode(.../**@type {Uint8Array}*/(Tbsip_Submit_Command([128, 1, 0, 0, 0, 22, 0, 0, 1, 122, 0, 0, 0, 6, 0, 0, 1, 5, 0, 0, 0, 1])).slice(23, 27)) === "INTC") {
                cer = decodeURIComponent((await (await fetch(`https://ekop.intel.com/ekcertservice/${encodeURIComponent(btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest("sha-256", Uint8Array.from([...cerKey, 1, 0, 1]))))))}`)).json()).certificate).replaceAll("-", "+").replaceAll("_", "/")
            } else {
                cer = btoa(String.fromCharCode(...await (await fetch(`https://ftpm.amd.com/pki/aia/${Array.from(
                    new Uint8Array(await crypto.subtle.digest("sha-256", Uint8Array.from([0, 0, 34, 34, 0, 1, 0, 1, ...cerKey]))),
                    (byte) => {
                        return byte.toString(16).padStart(2, "0")
                    }
                ).join("")}`)).bytes()))
            }
        }

        return {
            /**A key pair that can be provided to `attestTPM.tpmDecrypt` and `attestTPM.tpmSign`. The private key is encrypted by the TPM.*/ keys,
            /**JSON that can be provided to `attestTPM.authorityIssue`.*/ body: JSON.stringify({ cer, "Public key": btoa(String.fromCharCode(...keys.slice(-384))) })
        }
    }

    throw new Error("computer's TPM doesn't support `modulusLength: 3072`")
}

const tpmFields = {
    /**The Issued to.*/ "Issued to": "",
    /**The Subject O.*/ O: "",
    /**The Subject L.*/ L: "",
    /**The Subject C. Must be two characters.*/ C: "",
    /**The On-line Certificate Status Protocol URL in Authority Information Access.*/ "On-line Certificate Status Protocol": "",
    /**The Certification Authority Issuer URL in Authority Information Access.*/ "Certification Authority Issuer": "",
    /**The CRL Distribution Points URL.*/ "CRL Distribution Points": ""
}

/**@typedef {{ asn: Uint8Array<ArrayBuffer>, content: Uint8Array, children: parsedASN }[]} parsedASN*/

const parseASN = (/**@type {Uint8Array}*/ asn) => {
    let asnByte = 0

    const parseASN = (/**@type {number}*/ end) => {
        const asnType = asnByte
        let contentLength = asn[asnType + 1]
        let contentStart = asnType + 2
        const indefiniteLength = contentLength === 128
        let contentEnd

        if (indefiniteLength) {
            contentEnd = end
        } else {
            if (contentLength === 129) {
                contentLength = asn[contentStart++]
            } else if (contentLength === 130) {
                contentLength = 256 * asn[contentStart++] + asn[contentStart++]
            }

            contentEnd = contentLength + contentStart
        }

        const /**@type {parsedASN}*/ children = []

        if (contentEnd <= end) {
            asnByte = contentStart

            while (asnByte !== contentEnd) {
                const parsedASN = children[children.length] = parseASN(contentEnd)

                if (indefiniteLength && !(parsedASN.asn[0] || parsedASN.asn[1])) {
                    break
                }
            }
        } else {
            asnByte = end
        }

        return { asn: asn.slice(asnType, asnByte), content: asn.slice(contentStart, asnByte), children }
    }

    return parseASN(asn.length)
}

const nuvotonKey = crypto.subtle.importKey("raw", Uint8Array.from([4, 218, 156, 220, 176, 62, 65, 63, 68, 128, 129, 103, 133, 99, 192, 44, 166, 44, 59, 108, 7, 181, 39, 191, 157, 142, 143, 65, 242, 18, 192, 31, 115, 191, 175, 140, 233, 118, 12, 255, 9, 110, 183, 40, 205, 141, 57, 179, 177, 133, 125, 10, 145, 222, 248, 111, 225, 151, 100, 36, 198, 165, 128, 234, 246]), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
const globalsignKey = crypto.subtle.importKey("jwk", { kty: "RSA", n: "68iNcEttUF8gLtIWNzPiGbpHQjK5EmknjmeljK2UAeahWiyhPeKyXnZPhQHhPWvVvzLtj69bcR3Sxk76b+ke1RzmH3TnTKcZ523S6+41nVxWdfaH9dNx0ohrCoQFVdFlDk4kyn9oOVTCxR4FP5KWEBqA2GbI3Da0LZpvl3uqvwVTTcOzqKjz3ZpIPbfPnXIsCLHXbW5Qcg+YcHJplGdopy1Nu7u6XAg2Wt1wH3ndnRZVCGKXnKNmzXjJ3jICcDdnVlb6as6Svx6FWxRu+tTHJ+EwicysRMjFHhH1flxMhWJrZJVO1+qtvpcwLX9PsrU8f3RBe2W3dYgsww0mEsPL6Q", e: "AQAB" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"])
const integrityBytes = Uint8Array.from([0, 0, 0, 1, 73, 78, 84, 69, 71, 82, 73, 84, 89, 0, 0, 0, 1, 0])
const aesCBC = { name: "aes-cbc", iv: new ArrayBuffer(16) }
const label = Uint8Array.from([73, 68, 69, 78, 84, 73, 84, 89, 0])

export const /**`verify` whether a certificate was issued by a TPM manufacturer and create a Code Signing certificate if so.*/ authorityIssue = async (
    /**A `.cer` of an Intermediate certificate. @type {Uint8Array}*/ Intermediate,
    /**A `body` from `attestTPM.tpmCreate`. @type {Uint8Array}*/ body,
    /**A function to sign the Code Signing certificate with the private key matching the Intermediate certificate's Public key. @type {(Details: ArrayBuffer) => Promise<ArrayBuffer>}*/ sign,
    /**The Code Signing certificate fields. @type {Partial<tpmFields>}*/ Fields = {}
) => {
    const Issuedby = parseASN(Intermediate).children[0]?.children[5]?.children

    if (Issuedby?.[0]) {
        const bodyJSON = String.fromCharCode(...body)
        let tpmBody

        try {
            tpmBody = JSON.parse(bodyJSON)
        } catch {
            return { error: "body isn't in `JSON.stringify` format" }
        }

        let tpmCer

        try {
            tpmCer = atob(tpmBody.cer)
        } catch {
            return { error: "`cer` isn't in `btoa` format" }
        }

        let Publickey

        try {
            Publickey = atob(tpmBody["Public key"])
        } catch {
            return { error: "`Public key` isn't in `btoa` format" }
        }

        const parsedCer = parseASN(Uint8Array.from(
            tpmCer,
            (character) => {
                return character.charCodeAt(0)
            }
        )).children

        if (parsedCer[2] && parsedCer[0].children[6]?.children[1]) {
            const /**@type {{ [key: string]: parsedASN }}*/ cerFields = {}

            for (const asn in parsedCer[0].children[7]?.children[0]?.children) {
                if (parsedCer[0].children[7].children[0].children[asn].children[0]) {
                    cerFields[String.fromCharCode(...parsedCer[0].children[7].children[0].children[asn].children[0].content)] = parsedCer[0].children[7].children[0].children[asn].children
                }
            }

            if (cerFields["+\x06\x01\x05\x05\x07\x01\x01"]?.[1].children[0]?.children[0]?.children[1]) {
                const URL = String.fromCharCode(...cerFields["+\x06\x01\x05\x05\x07\x01\x01"][1].children[0].children[0].children[1].content).replace("http://", "https://")
                let TPMModel, TPMVersion, urlDomain
                const signatureBytes = parsedCer[2].content.slice(1)
                let cerSignature

                if (URL === "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton TPM Root CA 2111.cer") {
                    TPMModel = cerFields["U\x1d\x11"]?.[2]?.children[0]?.children[0]?.children[0]?.children[0]?.children[1]?.children[1]
                    TPMVersion = cerFields["U\x1d\x11"]?.[2]?.children[0]?.children[0]?.children[0]?.children[0]?.children[2]?.children[1]
                    urlDomain = "nuvoton"
                } else {
                    TPMModel = cerFields["U\x1d\x11"]?.[2]?.children[0]?.children[0]?.children[0]?.children[1]?.children[0]?.children[1]
                    TPMVersion = cerFields["U\x1d\x11"]?.[2]?.children[0]?.children[0]?.children[0]?.children[2]?.children[0]?.children[1]

                    if (URL === "https://secure.globalsign.com/stmtpmekint06.crt") {
                        urlDomain = "globalsign"
                        cerSignature = signatureBytes
                    } else if (URL.startsWith("https://ftpm.amd.com/pki/aia/")) {
                        urlDomain = "amd"
                        cerSignature = signatureBytes
                    } else if (URL.startsWith("https://trustedservices.intel.com/content/CRL/ekcert/")) {
                        urlDomain = "intel"
                    }
                }

                if (TPMModel && TPMVersion && urlDomain) {
                    if (!cerSignature) {
                        const ecdsaSignature = parseASN(signatureBytes).children

                        if (ecdsaSignature[1]) {
                            cerSignature = Uint8Array.from([...ecdsaSignature[0].content, ...ecdsaSignature[1].content.slice(1)])
                        }
                    }

                    if (cerSignature) {
                        let verifyCer

                        if (urlDomain === "nuvoton") {
                            verifyCer = crypto.subtle.verify({ name: "ecdsa", hash: "sha-256" }, await nuvotonKey, cerSignature, parsedCer[0].asn)
                        } else if (urlDomain === "globalsign") {
                            verifyCer = crypto.subtle.verify("rsassa-pkcs1-v1_5", await globalsignKey, cerSignature, parsedCer[0].asn)
                        } else {
                            const Publickey = parseASN(await (await fetch(URL)).bytes()).children[0].children[6]?.children[1].content

                            if (Publickey) {
                                if (urlDomain === "amd") {
                                    verifyCer = crypto.subtle.verify("rsassa-pkcs1-v1_5", await crypto.subtle.importKey("jwk", { kty: "RSA", n: btoa(String.fromCharCode(...Publickey.slice(10, 266))), e: "AQAB" }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]), cerSignature, parsedCer[0].asn)
                                } else {
                                    verifyCer = crypto.subtle.verify({ name: "ecdsa", hash: "sha-256" }, await crypto.subtle.importKey("raw", Publickey.slice(1), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]), cerSignature, parsedCer[0].asn)
                                }
                            }
                        }

                        if (await verifyCer) {
                            const identityRandom = crypto.getRandomValues(new Uint8Array(32))
                            const integrityKey = await crypto.subtle.importKey("raw", identityRandom, { name: "HMAC", hash: "SHA-256" }, false, ["sign"])
                            const /**@type {number[]}*/ key = []

                            const storageDigest = [
                                0,
                                11,
                                ...new Uint8Array(await crypto.subtle.digest(
                                    "sha-256",
                                    Uint8Array.from([
                                        0,
                                        1,
                                        0,
                                        11,
                                        0,
                                        4,
                                        0,
                                        114,
                                        0,
                                        0,
                                        0,
                                        16,
                                        0,
                                        16,
                                        12,
                                        0,
                                        0,
                                        0,
                                        0,
                                        0,
                                        1,
                                        128,
                                        ...Array.from(
                                            Publickey,
                                            (character) => {
                                                return character.charCodeAt(0)
                                            }
                                        )
                                    ])
                                ))
                            ]

                            const storageKey = await crypto.subtle.importKey("raw", (await crypto.subtle.sign("hmac", integrityKey, Uint8Array.from([0, 0, 0, 1, 83, 84, 79, 82, 65, 71, 69, 0, ...storageDigest, 0, 0, 0, 128]))).slice(0, 16), "AES-CBC", false, ["encrypt"])
                            let keyBytes = new Uint8Array(16)
                            const prependedIdentity = [0, 32, ...identityRandom]

                            const encryptKey = async (/**@type {number}*/ bytes) => {
                                keyBytes = new Uint8Array((await crypto.subtle.encrypt(aesCBC, storageKey, keyBytes)).slice(0, bytes)).map((byte, index) => {
                                    return prependedIdentity[index + key.length] ^ byte
                                })

                                key.push(...keyBytes)
                            }

                            await encryptKey(16)
                            await encryptKey(16)
                            await encryptKey(2)
                            const Validfrom = new Date

                            const validMonth = Array.from(
                                Validfrom.toISOString().slice(5, 7),
                                (character) => {
                                    return character.charCodeAt(0)
                                }
                            )

                            const Valid = (/**@type {Date}*/ Valid) => {
                                return [
                                    ...Array.from(
                                        Valid.toISOString().slice(2, 4),
                                        (character) => {
                                            return character.charCodeAt(0)
                                        }
                                    ),
                                    ...validMonth,
                                    48,
                                    49,
                                    48,
                                    48,
                                    48,
                                    48
                                ]
                            }

                            const Validto = new Date(Validfrom)
                            Validto.setFullYear(Validto.getFullYear() + 1)
                            const Subject = C(Fields.C)
                            const L = []

                            if (Fields.L) {
                                L.push(...Array.from(
                                    Fields.L,
                                    (character) => {
                                        return character.charCodeAt(0)
                                    }
                                ))
                            }

                            let Issuedto = Fields["Issued to"]

                            if (!Issuedto) {
                                Issuedto = ""
                            }

                            Subject.push(49, 128, 48, 128, 6, 3, 85, 4, 7, 12, ...prependLength(L), 0, 0, 0, 0, ...O(Fields.O), ...Issued(Issuedto))
                            let URL = Fields["On-line Certificate Status Protocol"]

                            if (!URL) {
                                URL = ""
                            }

                            let CertificationAuthorityIssuer = Fields["Certification Authority Issuer"]

                            if (!CertificationAuthorityIssuer) {
                                CertificationAuthorityIssuer = ""
                            }

                            const CodeSigning = await createCer(
                                Array.from(Issuedby[Issuedby.length - 1].asn.slice(1)),
                                [...Valid(Validfrom), 23, 10, ...Valid(Validto)],
                                Subject,
                                Publickey,
                                signingFields(
                                    [
                                        ...OnlineCertificateStatusProtocol(URL),
                                        48,
                                        128,
                                        6,
                                        8,
                                        43,
                                        6,
                                        1,
                                        5,
                                        5,
                                        7,
                                        48,
                                        2,
                                        134,
                                        ...prependLength(Array.from(
                                            CertificationAuthorityIssuer,
                                            (character) => {
                                                return character.charCodeAt(0)
                                            }
                                        )),
                                        0,
                                        0
                                    ],
                                    Fields
                                ),
                                128,
                                sign
                            )

                            return {
                                /**The model.*/ TPMModel: String.fromCharCode(...TPMModel.content),
                                /**The firmware version.*/ TPMVersion: String.fromCharCode(...TPMVersion.content.slice(3)),
                                /**JSON that can be provided to `attestTPM.tpmDecrypt`.*/ response: JSON.stringify({
                                    Intermediate: btoa(String.fromCharCode(...Intermediate)),
                                    key: btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("hmac", await crypto.subtle.importKey("raw", await crypto.subtle.sign("hmac", integrityKey, integrityBytes), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]), Uint8Array.from([...key, ...storageDigest]))), ...key, 1, 0, ...new Uint8Array(await crypto.subtle.encrypt({ name: "rsa-oaep", label }, await crypto.subtle.importKey("jwk", { kty: "RSA", n: btoa(String.fromCharCode(...parsedCer[0].children[6].children[1].content.slice(10, 266))), e: "AQAB" }, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]), identityRandom)))),
                                    "Code Signing": btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.encrypt(aesCBC, await crypto.subtle.importKey("raw", identityRandom, "AES-CBC", false, ["encrypt"]), CodeSigning.cer))))
                                }),
                                /**`Code Signing`'s Serial number.*/ "Serial number": btoa(String.fromCharCode(...CodeSigning["Serial number"]))
                            }
                        }
                    }
                }
            }
        }

        return { error: "`cer` isn't a TPM certificate" }
    }

    throw new Error("`Intermediate` isn't a certificate")
}

const keyRequest = (/**@type {Uint8Array}*/ keys) => {
    const keyLength = new Uint8Array(2)
    new DataView(keyLength.buffer).setUint16(0, keys.length + 27)
    return [128, 2, 0, 0, ...keyLength, 0, 0, 1, 87, 129, 0, 0, 1, 0, 0, 0, 9, 64, 0, 0, 9, 0, 0, 0, 0, 0, ...keys]
}

export const /**Use the TPM to decrypt a Code Signing certificate.*/ tpmDecrypt = async (
    /**`keys` from `attestTPM.tpmCreate`. @type {Uint8Array}*/ keys,
    /**The parsed `response` from `attestTPM.authorityIssue`. @type {{ Intermediate: string, key: string, "Code Signing": string }}*/ response
) => {
    let Intermediate

    try {
        Intermediate = atob(response.Intermediate)
    } catch {
        throw new Error("`Intermediate` isn't in `btoa` format")
    }

    let responseKey

    try {
        responseKey = atob(response.key)
    } catch {
        throw new Error("`key` isn't in `btoa` format")
    }

    let CodeSigning

    try {
        CodeSigning = atob(response["Code Signing"])
    } catch {
        throw new Error("`Code Signing` isn't in `btoa` format")
    }

    const Tbsip_Submit_Command = Tbsi_Context_Create()

    if (Tbsip_Submit_Command(keyRequest(keys))) {
        if (process.env.sessionname) {
            throw new Error("`tpmDecrypt` must run as administrator")
        }

        Tbsip_Submit_Command([128, 1, 0, 0, 0, 43, 0, 0, 1, 118, 64, 0, 0, 7, 64, 0, 0, 7, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 16, 0, 11])
        Tbsip_Submit_Command([128, 2, 0, 0, 0, 41, 0, 0, 1, 81, 64, 0, 0, 11, 3, 0, 0, 0, 0, 0, 0, 9, 64, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

        const decryptedKey = Tbsip_Submit_Command([
            128,
            2,
            0,
            0,
            1,
            112,
            0,
            0,
            1,
            71,
            128,
            255,
            255,
            255,
            129,
            1,
            0,
            1,
            0,
            0,
            0,
            18,
            64,
            0,
            0,
            9,
            0,
            0,
            0,
            0,
            0,
            3,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            68,
            0,
            32,
            ...Array.from(
                responseKey,
                (character) => {
                    return character.charCodeAt(0)
                }
            )
        ])?.slice(16, 48)

        if (decryptedKey) {
            const decryptCer = crypto.subtle.decrypt(
                aesCBC,
                await crypto.subtle.importKey("raw", decryptedKey, "AES-CBC", false, ["decrypt"]),
                Uint8Array.from(
                    CodeSigning,
                    (character) => {
                        return character.charCodeAt(0)
                    }
                )
            )

            let decryptedCer

            try {
                decryptedCer = await decryptCer
            } catch {
                throw new Error("`key` doesn't match `Code Signing`")
            }

            return Uint8Array.from([
                48,
                128,
                6,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                7,
                2,
                160,
                128,
                48,
                128,
                2,
                1,
                0,
                49,
                0,
                48,
                11,
                6,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                7,
                1,
                160,
                128,
                ...new Uint8Array(decryptedCer),
                ...Array.from(
                    Intermediate,
                    (character) => {
                        return character.charCodeAt(0)
                    }
                ),
                0,
                0,
                49,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ])
        }

        throw new Error("TPM keys don't match `key`")
    }

    throw new Error("keys don't match TPM")
}

export const /**Use the TPM to sign an `.exe`.*/ tpmSign = async (
    /**`keys` from `attestTPM.tpmCreate`. @type {Uint8Array}*/ keys,
    /**A `.p7b` of the Code Signing and Intermediate certificates. @type {Uint8Array}*/ p7b,
    /**An `.exe`. @type {Uint8Array}*/ exe
) => {
    const p7bCers = parseASN(p7b).children[1]?.children[0]?.children[3]

    if (p7bCers?.children[0]?.children[0]?.children[3]) {
        if (exe[61] === undefined) {
            throw new Error("invalid `exe`")
        }

        const Tbsip_Submit_Command = Tbsi_Context_Create()

        if (Tbsip_Submit_Command(keyRequest(keys))) {
            const exeHeader = exe.slice(0, new DataView(exe.buffer).getUint16(60, true) + 168)
            const exeLength = 8 * Math.ceil(exe.length / 8)
            const exeContent = [...exe.slice(exeHeader.length + 8), ...Array(exeLength - exe.length)]

            const signatureDigest = Uint8Array.from([
                48,
                14,
                6,
                10,
                43,
                6,
                1,
                4,
                1,
                130,
                55,
                2,
                1,
                15,
                48,
                0,
                48,
                47,
                48,
                11,
                6,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                2,
                1,
                4,
                32,
                ...new Uint8Array(await crypto.subtle.digest("sha-256", Uint8Array.from([...exeHeader.slice(0, -80), ...exeHeader.slice(-76), ...exeContent])))
            ])

            const Authenticatedattributes = [49, 48, 47, 6, 9, 42, 134, 72, 134, 247, 13, 1, 9, 4, 49, 34, 4, 32, ...new Uint8Array(await crypto.subtle.digest("sha-256", signatureDigest))]

            const encryptedAttributes = /**@type {Uint8Array}*/(Tbsip_Submit_Command([
                128,
                2,
                0,
                0,
                0,
                73,
                0,
                0,
                1,
                93,
                128,
                255,
                255,
                255,
                0,
                0,
                0,
                9,
                64,
                0,
                0,
                9,
                0,
                0,
                0,
                0,
                0,
                0,
                32,
                ...new Uint8Array(await crypto.subtle.digest("sha-256", Uint8Array.from([49, ...Authenticatedattributes]))),
                0,
                20,
                0,
                11,
                128,
                36,
                64,
                0,
                0,
                7,
                0,
                0
            ])).slice(20, 404)

            const DigitalSignature = [
                48,
                128,
                6,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                7,
                2,
                160,
                128,
                48,
                128,
                2,
                1,
                0,
                49,
                13,
                48,
                11,
                6,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                2,
                1,
                48,
                81,
                6,
                10,
                43,
                6,
                1,
                4,
                1,
                130,
                55,
                2,
                1,
                4,
                160,
                67,
                48,
                65,
                ...signatureDigest,
                ...p7bCers.asn,
                49,
                128,
                48,
                128,
                2,
                1,
                0,
                48,
                128,
                ...p7bCers.children[0].children[0].children[3].asn,
                ...p7bCers.children[0].children[0].children[1].asn,
                0,
                0,
                48,
                11,
                6,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                2,
                1,
                160,
                ...Authenticatedattributes,
                48,
                11,
                6,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                1,
                1,
                4,
                130,
                1,
                128,
                ...encryptedAttributes,
                161,
                128,
                48,
                128,
                6,
                10,
                43,
                6,
                1,
                4,
                1,
                130,
                55,
                3,
                3,
                1,
                49,
                128,
                ...(await (await fetch("https://timestamp.acs.microsoft.com", { method: "POST", body: Uint8Array.from([48, 55, 2, 1, 0, 48, 47, 48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 4, 32, ...new Uint8Array(await crypto.subtle.digest("sha-256", encryptedAttributes)), 1, 1, 255]) })).bytes()).slice(9),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0
            ]

            const lengthBytes = new Uint8Array(4)
            new DataView(lengthBytes.buffer).setUint32(0, exeLength, true)
            const signaturesLength = new Uint8Array(2)
            const signatureLength = new Uint8Array(2)
            new DataView(signatureLength.buffer).setUint16(0, DigitalSignature.length + 8, true)
            const DigitalSignatures = [...signatureLength, 0, 0, 0, 0, 2, 0, ...DigitalSignature, ...Array(8 * Math.ceil(DigitalSignature.length / 8) - DigitalSignature.length)]
            new DataView(signaturesLength.buffer).setUint16(0, DigitalSignatures.length, true)
            return Uint8Array.from([...exeHeader, ...lengthBytes, ...signaturesLength, 0, 0, ...exeContent, ...DigitalSignatures])
        }

        throw new Error("keys don't match TPM")
    }

    throw new Error("invalid `p7b`")
}
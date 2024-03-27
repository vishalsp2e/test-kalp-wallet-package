
async function generateKeyPairUsingCryptoSubtles() {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );
    return keyPair;
  } catch (err) {
    console.error("Error generating key pair:", err);
    return null;
  }
}

async function exportPrivateKeyAsPem(cryptoKey) {
  // Export the key
  const exportedKey = await crypto.subtle.exportKey("pkcs8", cryptoKey);

  // Convert the exported key to PEM format
  const exportedAsString = String.fromCharCode.apply(
    null,
    new Uint8Array(exportedKey)
  );
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExportedKey = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----\n`;

  return pemExportedKey;
}

async function exportPublicKeyToPem(publicKey) {
  try {
    // Export the public key
    const exportedKey = await crypto.subtle.exportKey("spki", publicKey);

    // Convert ArrayBuffer to base64-encoded string
    const exportedAsString = Array.from(new Uint8Array(exportedKey))
      .map((byte) => String.fromCharCode(byte))
      .join("");
    const exportedAsBase64 = btoa(exportedAsString);

    // Format the PEM string
    const pemString = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

    return pemString;
  } catch (error) {
    console.error("Error exporting public key:", error);
  }
}

async function hashByteArray(uint8Array) {
  // Convert Uint8Array to ArrayBuffer
  const buffer = uint8Array.buffer.slice(
    uint8Array.byteOffset,
    uint8Array.byteOffset + uint8Array.byteLength
  );

  // Use SubtleCrypto to create a hash
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);

  // Convert the hash ArrayBuffer to Uint8Array
  const hashUint8Array = new Uint8Array(hashBuffer);

  return hashUint8Array;
}

function encodeToString(src) {
  const dst = new Uint8Array(src.length * 2); // Each byte will be represented by 2 characters in hexadecimal
  for (let i = 0; i < src.length; i++) {
    const byte = src[i];
    dst[i * 2] = (byte >> 4) & 0xf; // High nibble
    dst[i * 2 + 1] = byte & 0xf; // Low nibble
  }
  return Array.from(dst)
    .map((byte) => byte.toString(16))
    .join("");
}

export async function getKeyPair() {
  try {
    const keyPair = await generateKeyPairUsingCryptoSubtles();
    const publicKey = keyPair.publicKey;
    const privateKey = keyPair.privateKey;
    const pemPublicKey = await exportPublicKeyToPem(publicKey);
    const pemPrivateKey = await exportPrivateKeyAsPem(privateKey);
    return { pemPublicKey, pemPrivateKey };
  } catch (error) {
    return { error: "Failed to generate key pair", details: error.message };
  }
}

export async function getEnrollmentId(publicKey) {
  try {
    // var pemPublicKey = await exportPublicKeyToPem(publicKey);
    const encoder = new TextEncoder();
    const pemPublicKeyBytes = encoder.encode(publicKey);
    const hashedPemPublicKey = await hashByteArray(pemPublicKeyBytes);
    const initialEnrollmentId = encodeToString(hashedPemPublicKey);
    const enrollmentID = initialEnrollmentId.slice(-40);
    return enrollmentID;
  } catch (error) {
    return { error: "Failed to generate EnrollmentId", details: error.message };
  }
}

export function createCsr(enrollmentID, privateKeyPem, publicKeyPem) {
  try {
    const jsrsasign = require("jsrsasign");
    var csr = new jsrsasign.KJUR.asn1.csr.CertificationRequest({
      subject: {
        str: `/CN=${enrollmentID}/O=Your Organization/postalCode=Your Postal Code/L=Your Locality/ST=Your Province/C=IN`,
      },
      sbjpubkey: publicKeyPem,
      sigalg: "SHA256withECDSA",
      sbjprvkey: privateKeyPem,
    });
    var pem = csr.getPEM();
    return pem;
  } catch (error) {
    return { error: "Failed to generate EnrollmentId", details: error.message };
  }
}

// function name
export async function register(enrollmentID, csr) {
  try {
    class WordEncryptor {
      constructor(seed) {
        this.seed = seed;
      }

      // Improved pseudorandom number generator based on seed
      getRandom() {
        const x = Math.sin(this.seed++) * 10000;
        return x - Math.floor(x);
      }

      encryptWord(word) {
        const baseCharacterSet =
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?0123456789";
        const specialCharacters = "!@#$%^&*+-=";

        // Set seed as part of the input to ensure consistent output
        let encryptedString = `${word}${this.seed}`;

        // Function to get a random character from a given character set
        const getRandomChar = (charSet) => {
          const index = Math.floor(this.getRandom() * charSet.length);
          return charSet.charAt(index);
        };

        // Randomly generate characters to meet encryption criteria
        encryptedString += getRandomChar("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); // Uppercase
        encryptedString += getRandomChar("abcdefghijklmnopqrstuvwxyz"); // Lowercase
        encryptedString += getRandomChar(specialCharacters); // Special character
        encryptedString += getRandomChar("0123456789"); // Number

        const minLength = 8;
        const maxLength = 16;
        let remainingLength =
          Math.floor(this.getRandom() * (maxLength - minLength + 1)) +
          minLength;

        for (let i = 0; i < remainingLength; i++) {
          encryptedString += getRandomChar(baseCharacterSet);
        }

        // Shuffle the characters to create a random string
        encryptedString = encryptedString
          .split("")
          .sort(() => this.getRandom() - 0.5)
          .join("");

        // Trim to ensure the length is within the desired range
        encryptedString = encryptedString.slice(0, maxLength);

        return encryptedString;
      }
    }
    const encryptor = new WordEncryptor(90);
    const encryptedWord = encryptor.encryptWord(enrollmentID);
    console.log(encryptedWord);
    const endpoint = "https://dev-userreg-gov.p2eppl.com/v1/pki/register";
    const headers = {
      Authorization:
        "f5b1aca0717e01d0dbca408d281e9e5145250acb146ff9f0844d53e95aab30b5",
      "Content-Type": "application/json",
    };
    const body = {
      invokerid: "5239272AB9849607A2270191C1C549A6E40B8AB4",
      enrollmentid: enrollmentID,
      secret: encryptedWord,
      role: "client",
      affiliation: "p2epro.clients",
      maxenrollments: "-1",
    };
    const response = await fetch(endpoint, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(body),
    });
    if (response.ok || response.status == 500) {
      console.log(`response is ${response}`);
      const endpoint = "https://dev-userreg-gov.p2eppl.com/v1/pki/enrollCsr";
      const headers = {
        Authorization:
          "f5b1aca0717e01d0dbca408d281e9e5145250acb146ff9f0844d53e95aab30b5",
        "Content-Type": "application/json",
      };
      const body = {
        enrollmentid: enrollmentID,
        secret: encryptedWord,
        csr: csr,
      };
      try {
        const response = await fetch(endpoint, {
          method: "POST",
          headers: headers,
          body: JSON.stringify(body),
        });
        if (response.ok) {
          const responseData = await response.json();
          const res = JSON.stringify(responseData);
          console.log(`data is :${res}`);
          const cert = responseData.response.pubcert;
          console.log(`public certificate is ${responseData.response.pubcert}`);
          return cert;
        } else {
          console.log("Failed to generate pubcert");
        }
      } catch (error) {
        return {
          error: "Failed to generate EnrollmentId",
          details: error.message,
        };
      }
    } else {
      console.log("Failed to register");
    }
  } catch (error) {
    return { error: "Failed to generate EnrollmentId", details: error.message };
  }
}

export async function Transaction(
  cert,
  channelName,
  chainCodeName,
  transactionName,
  transactionParams,
  PrivateKey
) {
  const domainName = "http://localhost:4000/transaction";
  const proposalUrl = domainName + "/proposalbytes";
  const endorsementUrl = domainName + "/transactionbytes";
  const submitUrl = domainName + "/result";
  const commitSubmitUrl = domainName + "/commit";
  var sigr = "";
  var sigs = "";
  const privateKeyString = PrivateKey;
  const transaction = {
    cert: cert,
    channelName: channelName,
    chainCodeName: chainCodeName,
    transactionName: transactionName,
    transactionParams: transactionParams,
  };

  async function restCall(url, message) {
    try {
      console.log(`url ${url} message ${message}`);
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(message),
      });
      const responseData = await response.json();
      console.log("responseData", responseData);
      if (!response.ok) {
        return { error: "Error in step 1", details: responseData.error };
        //return [null, responseData.error];
      } else {
        return [responseData, null];
      }
    } catch (error) {
      console.error("Error fetching data:", error, error.stack);
    }
  }

  function GetNValueForEcdsa() {
    const elliptic = require("elliptic");
    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves["p256"];
    const nvalue = new EC(ecdsaCurve).curve.n.toString();
    console.log("N:", nvalue);
    return nvalue;
  }

  function decodeBase64String(base64String) {
    const base64Table =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    // Prepare a map for reverse lookup
    const decodeMap = {};
    for (let i = 0; i < base64Table.length; i++) {
      decodeMap[base64Table[i]] = i;
    }
    decodeMap["="] = 0;

    // Decode Base64 string
    const data = new Uint8Array(base64String.length);
    let j = 0;
    for (let i = 0; i < base64String.length; i += 4) {
      const b1 = decodeMap[base64String[i]];
      const b2 = decodeMap[base64String[i + 1]];
      const b3 = decodeMap[base64String[i + 2]];
      const b4 = decodeMap[base64String[i + 3]];
      data[j] = (b1 << 2) | (b2 >> 4);
      j++;
      if (base64String[i + 2] !== "=") {
        data[j] = (b2 << 4) | (b3 >> 2);
        j++;
      }
      if (base64String[i + 3] !== "=") {
        data[j] = (b3 << 6) | b4;
        j++;
      }
    }

    return data.slice(0, j);
  }
  async function exportPrivateKeyAsPem(cryptoKey) {
    // Export the key
    const exportedKey = await crypto.subtle.exportKey("pkcs8", cryptoKey);

    // Convert the exported key to PEM format
    const exportedAsString = String.fromCharCode.apply(
      null,
      new Uint8Array(exportedKey)
    );
    const exportedAsBase64 = btoa(exportedAsString);
    const pemExportedKey = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----\n`;

    return pemExportedKey;
  }
  async function importPrivateKey(pem) {
    try {
      // Convert the PEM string to ArrayBuffer
      const pemString = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "");
      const binaryString = atob(pemString);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const privateKeyData = bytes.buffer;

      // Import the private key
      const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyData,
        {
          name: "ECDSA",
          namedCurve: "P-256", // Assuming ECDSA with P-256 curve
        },
        true,
        ["sign"]
      );

      return privateKey;
    } catch (error) {
      console.error("Error importing private key:", error);
    }
  }
  async function SignUsingElliptic(privateKey, hashedBytesArray) {
    const elliptic = require("elliptic");
    const { KEYUTIL } = require("jsrsasign");
    const privateKeyPem = await exportPrivateKeyAsPem(privateKey);
    console.log(`gaurav experiment privateKeyPEM ${privateKeyPem}`);
    const { prvKeyHex } = KEYUTIL.getKey(privateKeyPem); // convert the pem encoded key to hex encoded private key
    console.log(`hexPrivateKey is :${prvKeyHex}`);

    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves["p256"];
    const Buffer = require("buffer").Buffer;
    const ecdsa = new EC(ecdsaCurve);

    const signKey = ecdsa.keyFromPrivate(prvKeyHex, "hex");
    const sig = ecdsa.sign(Buffer.from(hashedBytesArray), signKey);
    const signature = Buffer.from(sig.toDER());
    sigr = sig.r.toString();
    sigs = sig.s.toString();
    console.log(`(r=${sigr}, s=${sigs})`);
    return [sigr, sigs];
  }
  const privateKey = await importPrivateKey(privateKeyString).catch((error) => {
    console.error("Error:", error);
  });

  try {
    var [proposalData, err] = await restCall(proposalUrl, transaction).catch(
      (error) => {
        console.error("Error fetching data:", error, error.stack);
      }
    );
    if (err != null) {
      return err;
    }
    console.log(`proposalData `, proposalData.toString());
    var sigr = "";
    var sigs = "";
    var signatureHex = "";
    const nvalue = GetNValueForEcdsa();

    var proposal = JSON.stringify(proposalData);
    console.log(`proposal ${proposal}`);
    const proposalBytes = decodeBase64String(proposalData);
    console.log("proposalBytes", proposalBytes);

    [sigr, sigs] = await SignUsingElliptic(privateKey, proposalBytes);
    console.log(`sigr ${sigr} sigs ${sigs}`);
    const signedProposal = {
      nValue: nvalue,
      signedR: sigr,
      signedS: sigs,
      signatureHex: signatureHex,
      originalProposalBytes: proposalData,
    };
    console.log("signedProposal", signedProposal);
    var [endorseData, err] = await restCall(
      endorsementUrl,
      signedProposal
    ).catch((error) => {
      console.error("Error fetching data:", error, error.stack);
    });
    if (err != null) {
      return err;
    }
    if (endorseData == null) {
      return;
    }
    console.log(`endorseData ${endorseData}`);
    const endorsedProposalBytes = decodeBase64String(endorseData);
    console.log("endorsedProposalBytes", endorsedProposalBytes);
    [sigr, sigs] = await SignUsingElliptic(privateKey, endorsedProposalBytes);
    console.log(`sigr ${sigr} sigs ${sigs}`);

    const signedEndorsedProposal = {
      nValue: nvalue,
      signedR: sigr,
      signedS: sigs,
      signatureHex: signatureHex,
      originalTransactionBytes: endorseData,
    };
    console.log("signedEndorsedProposal", signedEndorsedProposal);
    var [commitData, err] = await restCall(
      submitUrl,
      signedEndorsedProposal
    ).catch((error) => {
      console.error("Error fetching data:", error, error.stack);
    });
    if (err != null) {
      return err;
    }
    console.log(`commitData ${commitData}`);

    const commitProposalBytes = decodeBase64String(commitData);
    console.log("commitProposalBytes", commitProposalBytes);
    [sigr, sigs] = await SignUsingElliptic(privateKey, commitProposalBytes);
    console.log(`signatureHex ${signatureHex}`);
    const signedCommitProposal = {
      nValue: nvalue,
      signedR: sigr,
      signedS: sigs,
      signatureHex: signatureHex,
      originalCommitBytes: commitData,
    };
    console.log("signedCommitProposal", signedCommitProposal);
    var [statusData, err] = await restCall(
      commitSubmitUrl,
      signedCommitProposal
    ).catch((error) => {
      console.error("Error fetching data:", error, error.stack);
    });
    if (err != null) {
      return err;
    }
    const formattedResponse =
      "Transaction committed successfully with asset id:";
    console.log(`formattedResponse is :${formattedResponse}`);
    return formattedResponse;
  } catch (error) {
    return {
      error: "Failed to generate EnrollmentId",
      details: error.message,
    };
  }
}

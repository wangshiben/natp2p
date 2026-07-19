import crypto from "node:crypto";
import fs from "node:fs";
import process from "node:process";

const keyPath = process.argv[2];
if (!keyPath) {
  process.stderr.write("usage: node-id-from-key.mjs PRIVATE_KEY_FILE\n");
  process.exit(2);
}

const privateKeyHex = fs.readFileSync(keyPath, "utf8").trim();
if (!/^[0-9a-fA-F]{64}$/.test(privateKeyHex)) {
  process.stderr.write("invalid P-256 private key file\n");
  process.exit(2);
}

const keyPair = crypto.createECDH("prime256v1");
keyPair.setPrivateKey(Buffer.from(privateKeyHex, "hex"));
const publicKeyHex = keyPair.getPublicKey("hex", "uncompressed");
const nodeId = crypto.createHash("sha256").update(publicKeyHex).digest("hex");
process.stdout.write(`${nodeId}\n`);

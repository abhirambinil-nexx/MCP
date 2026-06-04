import { OAuth2Client } from "google-auth-library";
import fs from "fs";
import path from "path";

const credentialPath = path.join(process.cwd(), "client_secret.json");
const credentials = JSON.parse(fs.readFileSync(credentialPath, "utf8"));

const { client_id } = credentials.web;

export const googleClient = new OAuth2Client(client_id);

export { client_id };

console.log("✅ Google Auth initialized successfully using client_secret.json");

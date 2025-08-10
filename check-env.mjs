import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';

// Get the directory name in ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from .env file
const envPath = path.resolve(__dirname, '.env');
const envResult = config({ path: envPath });

if (envResult.error) {
  console.error('❌ Error loading .env file:', envResult.error);
  process.exit(1);
}

// Log all environment variables (be careful with sensitive data)
console.log('Environment variables from .env:');
console.log('--------------------------------');

// Only log non-sensitive environment variables
const safeToLog = [
  'NODE_ENV',
  'PORT',
  'FIREBASE_API_KEY',
  'FIREBASE_AUTH_DOMAIN',
  'FIREBASE_PROJECT_ID',
  'FIREBASE_STORAGE_BUCKET',
  'FIREBASE_MESSAGING_SENDER_ID',
  'FIREBASE_APP_ID',
  'FIREBASE_MEASUREMENT_ID',
  'MONGODB_URI',
  'SESSION_SECRET',
  'FIREBASE_ADMIN_PROJECT_ID',
  'FIREBASE_ADMIN_CLIENT_EMAIL',
  // Don't log FIREBASE_ADMIN_PRIVATE_KEY for security
];

safeToLog.forEach(key => {
  if (process.env[key] !== undefined) {
    console.log(`${key}=${process.env[key]}`);
  } else {
    console.log(`${key}=❌ Not Set`);
  }
});

// Check for private key without logging it
console.log('\nFIREBASE_ADMIN_PRIVATE_KEY:', 
  process.env.FIREBASE_ADMIN_PRIVATE_KEY ? '✅ Set (not shown for security)' : '❌ Not Set');

console.log('\nEnvironment variables check completed.');

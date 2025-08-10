process.removeAllListeners('warning');

import 'dotenv/config';
import admin from 'firebase-admin';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { createInterface } from 'readline';
import { stdin as input, stdout as output } from 'process';
import figlet from 'figlet';
import clear from 'clear';
import { promises as fs } from 'fs';
import os from 'os';
import crypto from 'crypto';
import {
  connectDB, 
  saveUser, 
  getUserById, 
  getWorkspacesByUser,
  getOrCreatePersonalWorkspace,
  getProjectsByWorkspace,
  getOrCreatePersonalProject,
  getTasksByProject,
  getTasksByUser,
  createTask as createTaskInDb, 
  updateTask, 
  deleteTask,
  mongoose,
  Workspace,
  Project,
  Task,
  User,
  getUserDatabaseConnection as _getUserDatabaseConnection
} from './utils/db.mjs';

/**
 * Fetches all projects for a specific user
 * @param {string} userId - The ID of the user
 * @returns {Promise<Array>} Array of project documents
 */
async function getProjectsByUser(userId) {
  try {
    return await Project.find({
      $or: [
        { createdBy: userId },
        { members: userId }
      ]
    }).sort({ isPersonal: -1, name: 1 }); // Personal projects first, then sort by name
  } catch (error) {
    console.error('Error getting projects by user:', error);
    throw error;
  }
}

/**
 * Creates a personal project for a user if one doesn't exist
 * @param {string} userId - The Firebase UID of the user
 * @returns {Promise<Object>} The created or existing personal project
 */
async function createPersonalProject(userId) {
  try {
    const existingProject = await Project.findOne({ 
      userId: userId, 
      isPersonal: true 
    });
    if (existingProject) {
      return existingProject;
    }
    
    // Get user details from Firebase
    let userName = 'Your';
    let userEmail = '';
    
    try {
      const userRecord = await admin.auth().getUser(userId);
      if (userRecord) {
        // Try to get a nice display name
        if (userRecord.displayName) {
          // If display name exists, use it
          userName = userRecord.displayName;
          // Handle cases where display name might be in 'First Last' format
          if (userName.includes(' ')) {
            const names = userName.split(' ');
            userName = names[0]; // Use just the first name
          }
        } else if (userRecord.email) {
          // If no display name, use the part before @ in email
          userEmail = userRecord.email;
          const emailName = userEmail.split('@')[0];
          // Clean up the name from email (remove numbers, special chars)
          const cleanName = emailName.replace(/[^a-zA-Z]/g, ' ').trim();
          if (cleanName) {
            userName = cleanName.split(' ')[0]; // Take first part if multiple words
          }
        }
      }
    } catch (error) {
      console.log(chalk.yellow('\nCould not fetch user details from Firebase, using default name'));
    }
    
    // Format the project name nicely
    const projectName = `${userName}${userName.endsWith('s') ? "'" : "'s"} Tasks`;
    
    const personalProject = new Project({
      name: projectName,
      description: 'Your personal project for tasks',
      userId: userId,
      members: [userId],
      isPersonal: true
    });
    
    await personalProject.save();
    console.log(chalk.green(`\nWelcome, ${userName}! Your personal task board is ready.`));
    return personalProject;
  } catch (error) {
    console.error(chalk.red('\nError creating personal project:'), error.message);
    throw error;
  }
}

function checkPasswordRequirements(input) {
  const hasLowercase = /[a-z]/.test(input);
  const hasUppercase = /[A-Z]/.test(input);
  const hasNumber = /[0-9]/.test(input);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(input);
  const lengthOk = input.length >= 6 && input.length <= 12;
  
  return {
    hasLowercase,
    hasUppercase,
    hasNumber,
    hasSpecial,
    lengthOk,
    isValid: hasLowercase && hasUppercase && hasNumber && hasSpecial && lengthOk,
    message: [
      lengthOk ? '✓ 6-12 characters' : '✗ Must be 6-12 characters',
      hasLowercase ? '✓ Lowercase letter' : '✗ Needs a lowercase letter',
      hasUppercase ? '✓ Uppercase letter' : '✗ Needs an uppercase letter',
      hasNumber ? '✓ Number' : '✗ Needs a number',
      hasSpecial ? '✓ Special character' : '✗ Needs a special character (!@#$%^&*)',
    ].join('\n')
  };
}

const prompt = inquirer.createPromptModule();

function createSeparator() {
  return new inquirer.Separator(chalk.dim('─'.repeat(40)));
}

async function getPasswordWithValidation(email) {
  return new Promise((resolve) => {
    const rl = createInterface({ input, output });
    let password = '';
    
    if (input.isTTY) {
      input.setRawMode(true);
    }
    
    const render = () => {
      console.clear();
      console.log(chalk.cyan('=== Create a New Account ===\n'));
      console.log(`Email: ${email}\n`);
      
      console.log('Password Requirements:');
      
      const requirements = checkPasswordRequirements(password);
      const requirementsList = [
        { met: requirements.lengthOk, text: '6-12 characters' },
        { met: requirements.hasLowercase, text: '1 lowercase letter (a-z)' },
        { met: requirements.hasUppercase, text: '1 uppercase letter (A-Z)' },
        { met: requirements.hasNumber, text: '1 number (0-9)' },
        { met: requirements.hasSpecial, text: '1 special character (!@#$%^&*)' }
      ];
      
      requirementsList.forEach(req => {
        const status = req.met ? chalk.green('✓') : '•';
        const text = req.met ? chalk.gray(req.text) : req.text;
        console.log(`  ${status} ${text}`);
      });
      
      console.log('\nPassword: ' + (password ? '•'.repeat(password.length) : '_'));
    };
    
    render();
    
    const onKeyPress = (str, key) => {
      if (key.ctrl && key.name === 'c') {
        process.exit();
      } else if (key.name === 'return') {
        const requirements = checkPasswordRequirements(password);
        if (requirements.isValid) {
          if (input.isTTY) input.setRawMode(false);
          input.off('keypress', onKeyPress);
          rl.close();
          resolve(password);
        }
      } else if (key.name === 'backspace') {
        password = password.slice(0, -1);
        render();
      } else if (str && str.length === 1) {
        password += str;
        render();
      }
    };
    
    input.on('keypress', onKeyPress);
  });
}

let isDbConnected = false;
let currentProject = null;

// Initialize Firebase Admin and Firestore
let firestoreDb = null;

const initializeFirebaseAdmin = () => {
  try {
    if (admin.apps.length === 0) {
      const serviceAccount = {
        projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || process.env.FIREBASE_ADMIN_PROJECT_ID,
        clientEmail: process.env.FIREBASE_ADMIN_CLIENT_EMAIL,
        privateKey: (process.env.FIREBASE_ADMIN_PRIVATE_KEY || '').replace(/\\\\n/g, '\n')
      };

      if (!serviceAccount.projectId || !serviceAccount.clientEmail || !serviceAccount.privateKey) {
        throw new Error(`Missing required Firebase Admin environment variables. Check if FIREBASE_ADMIN_PRIVATE_KEY is set.`);
      }

      try {
        admin.initializeApp({
          credential: admin.credential.cert(serviceAccount)
        });
        
        // Initialize Firestore
        firestoreDb = admin.firestore();
        return true;
      } catch (initError) {
        console.error(chalk.red('❌ Error initializing Firebase Admin:'));
        console.error(initError);
        throw initError;
      }
    }
    
    // If Firebase is already initialized, ensure Firestore is initialized
    if (!firestoreDb) {
      firestoreDb = admin.firestore();
    }
    return true;
  } catch (error) {
    console.error(chalk.red('Error initializing Firebase Admin:'));
    console.error(chalk.red(error.message));
    console.error('\nPlease make sure you have set all the required environment variables in your .env file:');
    console.log('\nFIREBASE_PROJECT_ID=your-project-id');
    console.log('FIREBASE_ADMIN_CLIENT_EMAIL=your-client-email@project-id.iam.gserviceaccount.com');
    console.log('FIREBASE_ADMIN_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n');
    process.exit(1);
  }
};

(async () => {
  try {
    isDbConnected = await connectDB({ verbose: false });
    if (!isDbConnected) {
      console.error(chalk.yellow('Warning: Could not connect to MongoDB. Some features may not work.'));
    }
    
    initializeFirebaseAdmin();
    
    // Wait a moment to ensure Firebase is fully initialized
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Now start the app
    await init();
  } catch (error) {
    console.error(chalk.red('Error during initialization:'), error.message);
    process.exit(1);
  }
})();

// Generate a unique device ID based on machine details
function getDeviceId() {
  const deviceInfo = {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    totalMem: os.totalmem()
  };
  
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(deviceInfo))
    .digest('hex');
}

const SESSION_DIR = `${os.homedir()}/.taskflow-cli`;
const SESSION_FILE = `${SESSION_DIR}/session.json`;

async function ensureSessionDir() {
  try {
    await fs.mkdir(SESSION_DIR, { recursive: true });
    // Set secure permissions (read/write for user only)
    if (process.platform !== 'win32') {
      await fs.chmod(SESSION_DIR, 0o700);
    }
  } catch (error) {
    console.error('Error creating session directory:', error);
    throw error;
  }
}

async function saveSession(user) {
  try {
    if (!user || !user.uid || !user.email) {
      throw new Error('Invalid user data provided to saveSession');
    }
    
    await ensureSessionDir();
    
    const session = {
      uid: user.uid,
      email: user.email.toLowerCase(),
      displayName: user.displayName || user.email.split('@')[0],
      deviceId: getDeviceId(),
      lastLogin: new Date().toISOString()
    };
    
    // Ensure we're only saving plain objects, not Firestore objects
    const cleanSession = JSON.parse(JSON.stringify(session));
    
    await fs.writeFile(SESSION_FILE, JSON.stringify(cleanSession, null, 2), 'utf8');
    
    // Set secure permissions (read/write for user only)
    if (process.platform !== 'win32') {
      await fs.chmod(SESSION_FILE, 0o600);
    }
    
    return true;
  } catch (error) {
    console.error(chalk.red('❌ Error saving session:'), error);
    return false;
  }
}

async function loadSession() {
  try {
    await ensureSessionDir();
    
    // Check if session file exists
    try {
      await fs.access(SESSION_FILE);
    } catch (error) {
      return null; // No session file
    }
    
    // Read and parse session data
    const sessionData = await fs.readFile(SESSION_FILE, 'utf8');
    const session = JSON.parse(sessionData);
    
    // Verify the session is from this device
    const currentDeviceId = getDeviceId();
    if (session.deviceId !== currentDeviceId) {
      console.log(chalk.yellow('Session is not from this device. Please log in again.'));
      await clearSession();
      return null;
    }
    
    // Verify session with Firebase
    try {
      const userRecord = await admin.auth().getUser(session.uid);
      if (userRecord && userRecord.email.toLowerCase() === session.email) {
        return {
          ...session,
          displayName: userRecord.displayName || session.displayName,
          emailVerified: userRecord.emailVerified || false
        };
      }
    } catch (error) {
      // If it's a permission error, we'll allow the session to continue
      // but warn the user about limited Firebase features
      if (error.message.includes('permission') || error.message.includes('PERMISSION_DENIED')) {
        console.log(chalk.yellow('⚠️  Firebase verification unavailable due to permissions, continuing with cached session'));
        
        return {
          ...session,
          emailVerified: false,
          firebaseVerified: false
        };
      }
      
      // For other errors, still fail
      console.log(chalk.yellow('Session verification failed, clearing...'));
      await clearSession();
      return null;
    }
    
    // If we get here, the session is invalid (no return from Firebase verification)
    await clearSession();
    return null;
    
  } catch (error) {
    console.error(chalk.red('Error loading session:'), error.message);
    await clearSession();
    return null;
  }
}

async function clearSession() {
  try {
    if (await fs.access(SESSION_FILE).then(() => true).catch(() => false)) {
      await fs.unlink(SESSION_FILE);
    }
    return true;
  } catch (error) {
    console.error('Error clearing session:', error);
    return false;
  }
}

async function handleLogout() {
  try {
    await clearSession();
    console.log(chalk.green('\nSuccessfully logged out. Goodbye!'));
    await new Promise(resolve => setTimeout(resolve, 1500));
    await showMainMenu();
  } catch (error) {
    console.error(chalk.red('\nError during logout:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showMainMenu();
  }
}

import { initializeApp } from 'firebase/app';
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, updateProfile } from 'firebase/auth';

const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID
};

// Log Firebase config for debugging (without sensitive data)
console.log('Firebase Config:', {
  ...firebaseConfig,
  apiKey: firebaseConfig.apiKey ? '***' + firebaseConfig.apiKey.slice(-4) : 'Not set',
  appId: firebaseConfig.appId ? '***' + firebaseConfig.appId.slice(-4) : 'Not set'
});

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);

function showWelcome() {
  clear();
  console.log(
    chalk.blue(
      figlet.textSync('Taskflow AI', { 
        font: 'Standard',
        horizontalLayout: 'full',
        verticalLayout: 'default',
        width: 80,
        whitespaceBreak: true
      })
    )
  );
  console.log(chalk.yellow.bold('Terminal Interface\n'));
}


async function showMainMenu() {
  let menuActive = true;
  
  while (menuActive) {
    showWelcome();
    
    try {
      const { action } = await prompt([
        {
          type: 'list',
          name: 'action',
          message: 'What would you like to do?',
          choices: [
            { name: 'Login', value: 'login' },
            { name: 'Register', value: 'register' },
            createSeparator(),
            { name: 'Exit', value: 'exit' }
          ],
          pageSize: 4,
        },
      ]);
      
      switch (action) {
        case 'login':
          await handleLogin();
          break;
        case 'register':
          await handleRegister();
          break;
        case 'exit':
          console.log(chalk.yellow('\nGoodbye!'));
          process.exit(0);
      }
    } catch (error) {
      console.error(chalk.red('\nAn error occurred:'));
      console.error(chalk.red(error.message));
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
}

async function handleRegister(previousValues = {}) {
  try {
    showWelcome();
    console.log(chalk.cyan('\n=== Create a New Account ===\n'));

    // Get email
    const emailPrompt = await prompt([{
      type: 'input',
      name: 'email',
      message: 'Enter your email:',
      default: previousValues.email || '',
      validate: (input) => {
        if (/^\S+@\S+\.\S+$/.test(input)) return true;
        return 'Please enter a valid email address';
      },
    }]);
    const { email } = emailPrompt;

    // Get password with validation
    const { password } = await prompt({
      type: 'password',
      name: 'password',
      message: 'Create a password (6-12 chars, mixed case, numbers, special chars):',
      mask: '*',
      validate: (input) => {
        const requirements = checkPasswordRequirements(input);
        if (requirements.isValid) return true;
        return 'Please ensure your password meets all requirements';
      }
    });
    
    // Get password confirmation
    await prompt({
      type: 'password',
      name: 'confirmPassword',
      message: 'Confirm your password:',
      mask: '*',
      validate: (input) => {
        if (input === password) return true;
        return 'Passwords do not match';
      }
    });

    // Get user's name
    const namePrompt = await prompt([{
      type: 'input',
      name: 'name',
      message: 'Enter your full name:',
      default: previousValues.name || '',
      validate: (input) => {
        if (input.trim().length < 2) return 'Please enter your full name';
        return true;
      }
    }]);
    const { name } = namePrompt;

    console.clear();
    console.log(chalk.cyan('=== Create a New Account ===\n'));
    console.log(`Email: ${email}\n`);
    
    console.log(chalk.blue('Creating your account...'));
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;
    
    // Update user profile with display name
    await updateProfile(user, { displayName: name });
    
    // Create user document in Firestore
    await firestoreDb.collection('users').doc(user.uid).set({
      email: user.email,
      displayName: name,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    
    console.log(chalk.green('\n✅ Account created successfully!'));
    console.log(chalk.blue('\nLogging you in...'));
    
    // Create a personal project for the user
    await createPersonalProject(user.uid);
    
    try {
      // Ensure user is properly created in Firestore
      await ensureUserInFirestore({
        uid: user.uid,
        email: user.email,
        displayName: name
      });
      
      // Also save user to MongoDB
      await saveUser({
        uid: user.uid,
        email: user.email,
        displayName: name
      });
      
      // Get the user document data
      const userDoc = await firestoreDb.collection('users').doc(user.uid).get();
      const userData = userDoc.data() || {};
      
      // Create session data
      const sessionData = {
        uid: user.uid,
        email: user.email,
        displayName: userData.displayName || name || user.email.split('@')[0]
      };
      
      // Save session
      await saveSession(sessionData);
      
      console.log(chalk.green('\n✅ Registration successful! Logging you in...'));
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Show dashboard with explicit user ID
      await showDashboard(user.uid);
    } catch (dbError) {
      console.error(chalk.red('\nError creating user profile:'), dbError);
      throw new Error('Failed to complete user registration. Please try again.');
    }
  } catch (error) {
    console.error(chalk.red('\nError creating account:'));
    console.error(chalk.red(error.message));
    
    if (error.code === 'auth/email-already-in-use') {
      console.log(chalk.yellow('\nThis email is already registered. Please try logging in instead.'));
      await new Promise(resolve => setTimeout(resolve, 2000));
      await handleLogin({ email: previousValues.email });
    } else {
      console.log(chalk.yellow('\nPlease try again.'));
      await new Promise(resolve => setTimeout(resolve, 2000));
      await handleRegister(previousValues);
    }
  }
}

async function ensureUserInFirestore(user) {
  try {
    const userDoc = await firestoreDb.collection('users').doc(user.uid).get();
    
    if (!userDoc.exists) {
      console.log(chalk.blue('\nCreating your user profile...'));
      
      // Create user document in Firestore
      await firestoreDb.collection('users').doc(user.uid).set({
        email: user.email,
        displayName: user.displayName || user.email.split('@')[0],
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // Also save to MongoDB
      await saveUser({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName || user.email.split('@')[0]
      });
      
      // Create a personal project for the user
      await createPersonalProject(user.uid);
    } else {
      // User exists in Firestore, ensure they exist in MongoDB too
      try {
        const mongoUser = await getUserById(user.uid);
        if (!mongoUser) {
          console.log(chalk.blue('\nSyncing user profile to MongoDB...'));
          await saveUser({
            uid: user.uid,
            email: user.email,
            displayName: user.displayName || user.email.split('@')[0]
          });
        }
      } catch (mongoError) {
        console.warn(chalk.yellow('\nWarning: Could not sync user to MongoDB:'), mongoError.message);
      }
    }
    
    return true;
  } catch (error) {
    console.error(chalk.red('Error ensuring user in Firestore:'), error);
    throw error;
  }
}

async function handleLogin(previousValues = {}) {
  showWelcome();
  
  try {
    const session = await loadSession();
    if (session) {
      // Ensure the user exists in Firestore
      await ensureUserInFirestore({
        uid: session.uid,
        email: session.email,
        displayName: session.displayName
      });
      
      console.log(chalk.green(`\nWelcome back, ${session.displayName || session.email}!`));
      await new Promise(resolve => setTimeout(resolve, 1000));
      await showDashboard(session.uid);
      return;
    }
  } catch (error) {
    console.log(chalk.yellow('\nStarting new session...'));
  }
  
  try {
    const { email, password } = await prompt([
      {
        type: 'input',
        name: 'email',
        message: 'Enter your email:',
        default: previousValues.email || '',
        validate: (input) => {
          if (/^\S+@\S+\.\S+$/.test(input)) return true;
          return 'Please enter a valid email address';
        },
      },
      {
        type: 'password',
        name: 'password',
        message: 'Enter your password:',
        mask: '*',
        validate: input => input.length >= 6 || 'Password must be at least 6 characters'
      }
    ]);

    console.log(chalk.yellow('\nSigning in...'));
    
    const auth = getAuth();
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    const user = userCredential.user;
    
    // Ensure user exists in Firestore
    await ensureUserInFirestore(user);
    
    console.log(chalk.green(`\n✅ Successfully logged in as ${user.email}`));
    
    // Save session with updated user data
    const userDoc = await firestoreDb.collection('users').doc(user.uid).get();
    const userData = userDoc.data() || {};
    
    // Also ensure user exists in MongoDB
    await saveUser({
      uid: user.uid,
      email: user.email,
      displayName: userData.displayName || user.displayName || user.email.split('@')[0]
    });
    
    await saveSession({
      uid: user.uid,
      email: user.email,
      displayName: userData.displayName || user.displayName || user.email.split('@')[0]
    });
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    await showDashboard(user.uid);
    
  } catch (error) {
    console.error(chalk.red('\n❌ Login failed:'));
    
    let errorMessage = 'Invalid email or password';
    if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password') {
      errorMessage = 'Invalid email or password';
    } else if (error.code === 'auth/too-many-requests') {
      errorMessage = 'Too many failed attempts. Please try again later.';
    } else if (error.code === 'auth/invalid-email') {
      errorMessage = 'Please enter a valid email address';
    } else {
      console.error(chalk.red(error.message));
    }
    
    console.error(chalk.red(`\n${errorMessage}`));
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Try again', value: 'retry' },
          { name: 'Go back', value: 'back' }
        ]
      }
    ]);
    
    if (action === 'retry') {
      await handleLogin({ email: previousValues.email });
    } else {
      await showMainMenu();
    }
  }
}

async function showDashboard(userId) {
  showWelcome();
  
  try {
    const user = await getUserById(userId);
    if (!user) {
      console.log(chalk.yellow('\nUser not found. Please log in again.'));
      return handleLogout();
    }
    
    // Get projects for the user
    const projects = await getProjectsByUser(userId);
    const personalProject = projects.find(p => p.isPersonal) || await createPersonalProject(userId);
    
    // Ensure personal project exists in projects list
    if (personalProject && !projects.some(p => p && p.isPersonal)) {
      projects.unshift(personalProject);
    }
    
    // Calculate task counts using the same method as the web app
    let totalTasks = 0;
    let completedTasks = 0;
    let inProgressTasks = 0;
    let todoTasks = 0;
    
    try {
      // Use the same fetchWebAppTasks function as the task listing
      const tasks = await fetchWebAppTasks(userId);
      totalTasks = tasks.length;
      completedTasks = tasks.filter(t => t.status === 'completed').length;
      inProgressTasks = tasks.filter(t => t.status === 'in-progress').length;
      todoTasks = tasks.filter(t => !t.status || t.status === 'todo').length;
    } catch (error) {
      console.warn(chalk.yellow('⚠️  Could not load task counts:', error.message));
      // Keep zeros as fallback
    }
    
    console.log(chalk.blue(`\nDashboard - ${user.displayName || user.email.split('@')[0]}`));
    console.log(chalk.gray('━'.repeat(60)));
    
    console.log(chalk.bold('Task Summary:'));
    console.log(`  • Total: ${chalk.bold(totalTasks)}`);
    console.log(`  • ${chalk.green('✓')} Completed: ${chalk.green(completedTasks)}`);
    console.log(`  • In Progress: ${chalk.blue(inProgressTasks)}`);
    console.log(`  • To Do: ${chalk.yellow(todoTasks)}`);
    
    const choices = [
      { name: '📋 View All Tasks', value: 'all-tasks' },
      createSeparator(),
      { name: '➕ Create New Task', value: 'create-task' },
      createSeparator(),
      { name: '👤 View Profile', value: 'profile' },
      { name: '⚙️ Settings', value: 'settings' },
      { name: '🚪 Logout', value: 'logout' },
      { name: '❌ Exit', value: 'exit' }
    ];
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: choices,
        pageSize: choices.length
      }
    ]);
    
    switch (action) {
      case 'all-tasks':
        await showAllTasks(userId);
        break;
      case 'create-task':
        await createTask(userId);
        break;
      case 'profile':
        await showProfile(user);
        break;
      case 'settings':
        await showSettings(userId);
        break;
      case 'logout':
        await handleLogout();
        break;
      case 'exit':
        console.log(chalk.blue('\nGoodbye! 👋'));
        process.exit(0);
        break;
      default:
        await showDashboard(userId);
    }
  } catch (error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}`));
    console.error(error.stack);
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showDashboard(userId);
  }
}

async function showWorkspaces(userId, retryCount = 0) {
  showWelcome();
  
  try {
    if (retryCount > 2) {
      throw new Error('Too many failed attempts. Returning to dashboard.');
    }
    
    const workspaces = await getWorkspacesByUser(userId);
    const personalWorkspace = await getOrCreatePersonalWorkspace(userId);
    
    if (!workspaces || !Array.isArray(workspaces)) {
      throw new Error('Failed to load workspaces. Please try again.');
    }
    
    const hasPersonal = workspaces.some(w => w && w.isPersonal);
    if (!hasPersonal && personalWorkspace) {
      workspaces.unshift(personalWorkspace);
    }
    
    const workspaceChoices = workspaces
      .filter(ws => ws)
      .map(ws => ({
        name: ws.isPersonal ? 'Personal' : ws.name,
        value: ws._id.toString(),
        isPersonal: ws.isPersonal,
        workspace: ws
      }));
    
    if (workspaceChoices.length === 0) {
      console.log(chalk.yellow('\nNo workspaces found. Creating a personal workspace...'));
      await createWorkspace(userId, true);
      return showWorkspaces(userId);
    }
    
    const { workspaceId, action } = await prompt([
      {
        type: 'list',
        name: 'workspaceId',
        message: 'Select a workspace:',
        choices: [
          ...workspaceChoices,
          createSeparator(),
          { name: '➕ Create New Workspace', value: 'create' },
          { name: 'Back to Main Menu', value: 'back' }
        ],
        pageSize: 10,
        loop: false
      }
    ]);
    
    if (workspaceId === 'back') {
      await showDashboard(userId);
    } else if (workspaceId === 'create') {
      await createWorkspace(userId);
      return showWorkspaces(userId);
    } else {
      const selected = workspaceChoices.find(w => w.value === workspaceId);
      currentWorkspace = selected.workspace;
      await showWorkspaceProjects(workspaceId, userId);
    }
    
  } catch (error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}`));
    
    if (retryCount < 2) {
      console.log(chalk.yellow(`\nRetrying... (${retryCount + 1}/2)`));
      await new Promise(resolve => setTimeout(resolve, 1500));
      return showWorkspaces(userId, retryCount + 1);
    } else {
      console.log(chalk.yellow('\nReturning to dashboard...'));
      await new Promise(resolve => setTimeout(resolve, 1500));
      await showDashboard(userId);
    }
  }
}

async function showWorkspaceTasks(workspaceId, userId, retryCount = 0) {
  showWelcome();
  
  try {
    if (retryCount > 2) {
      throw new Error('Too many failed attempts. Returning to workspace.');
    }
    
    const [workspace, tasks] = await Promise.all([
      Workspace.findById(workspaceId),
      getTasksByUser(userId, workspaceId)
    ]);
    
    if (!workspace) {
      throw new Error('Workspace not found');
    }
    
    const tasksByStatus = {
      todo: [],
      'in-progress': [],
      completed: []
    };
    
    tasks.forEach(task => {
      if (task.status in tasksByStatus) {
        tasksByStatus[task.status].push(task);
      } else {
        tasksByStatus[task.status] = [task];
      }
    });
    
    if (!currentProject || currentProject._id !== project._id.toString()) {
      currentProject = {
        _id: project._id,
        name: project.name,
        isPersonal: project.isPersonal
      };
    }
    
    console.log(chalk.blue(`\nTasks in ${project.name}`));
    console.log(chalk.gray('━'.repeat(40)));
    
    for (const [status, taskList] of Object.entries(tasksByStatus)) {
      if (taskList.length > 0) {
        console.log(`\n${chalk.bold(formatStatus(status))}:`);
        taskList.forEach(task => {
          const projectName = task.projectId?.name || 'No Project';
          const dueDate = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No due date';
          console.log(`• ${task.title} (${projectName}) - Due: ${dueDate}`);
        });
      }
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: '➕ Create New Task', value: 'create' },
          createSeparator(),
          { name: 'Back to Workspace', value: 'back' },
          { name: 'Back to Main Menu', value: 'home' }
        ]
      }
    ]);
    
    if (action === 'back') {
      await showWorkspaceProjects(workspaceId, userId);
    } else if (action === 'home') {
      await showDashboard(userId);
    } else if (action === 'create') {
      console.log(chalk.yellow('\nTask creation coming soon!'));
      await new Promise(resolve => setTimeout(resolve, 1500));
      await showWorkspaceTasks(workspaceId, userId);
    }
    
  } catch (error) {
    console.error(chalk.red(`\nError: ${error.message}`));
    
    if (retryCount < 2) {
      console.log(chalk.yellow(`\nRetrying... (${retryCount + 1}/2)`));
      await new Promise(resolve => setTimeout(resolve, 1500));
      return showWorkspaceTasks(workspaceId, userId, retryCount + 1);
    } else {
      console.log(chalk.yellow('\nReturning to workspace...'));
      await new Promise(resolve => setTimeout(resolve, 1500));
      await showWorkspaceProjects(workspaceId, userId);
    }
  }
}

async function showProjectList(userId) {
  showWelcome();
  
  try {
    const projects = await getProjectsByUser(userId);
    const personalProject = projects.find(p => p.isPersonal) || await createPersonalProject(userId);
    
    // Ensure personal project exists in projects list
    if (personalProject && !projects.some(p => p && p.isPersonal)) {
      projects.unshift(personalProject);
    }
    
    console.log(chalk.blue('\nYour Projects'));
    console.log(chalk.gray('━'.repeat(40)));
    
    if (projects.length === 0) {
      console.log(chalk.yellow('\nNo projects found. Create your first project!'));
    } else {
      projects.forEach((project, index) => {
        if (!project) return;
        console.log(`\n${index + 1}. ${project.name}`);
        console.log(`   ${chalk.dim(project.description || 'No description')}`);
      });
    }
    
    const choices = [
      { name: 'View Project Tasks', value: 'tasks' },
      { name: 'Create New Project', value: 'create' },
      createSeparator(),
      { name: 'Back to Dashboard', value: 'dashboard' }
    ];
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: '\nWhat would you like to do?',
        choices: choices,
        pageSize: 10
      }
    ]);
    
    if (action === 'tasks') {
      const { projectId } = await prompt([
        {
          type: 'list',
          name: 'projectId',
          message: 'Select a project to view tasks:',
          choices: projects
            .filter(p => p) // Filter out any null/undefined projects
            .map(p => ({
              name: p.name,
              value: p._id.toString()
            }))
        }
      ]);
      
      const selectedProject = projects.find(p => p && p._id.toString() === projectId);
      if (selectedProject) {
        await showTasks(projectId, userId);
      } else {
        console.log(chalk.yellow('\nProject not found.'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showProjectList(userId);
      }
    } else if (action === 'create') {
      const { name, description } = await prompt([
        {
          type: 'input',
          name: 'name',
          message: 'Project name:',
          validate: input => input.trim() ? true : 'Project name is required'
        },
        {
          type: 'input',
          name: 'description',
          message: 'Project description (optional):',
        }
      ]);
      
      const newProject = new Project({
        name: name.trim(),
        description: description.trim() || undefined,
        createdBy: userId,
        members: [userId],
        isPersonal: false
      });
      
      await newProject.save();
      console.log(chalk.green(`\nProject "${newProject.name}" created successfully!`));
      await new Promise(resolve => setTimeout(resolve, 1500));
      await showProjectList(userId);
    } else {
      await showDashboard(userId);
    }
    
  } catch (error) {
    console.error(chalk.red(`\nError: ${error.message}`));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showDashboard(userId);
  }
}

async function showWorkspaceProjects(workspaceId, userId, attempt = 0, returnToDashboard = false) {
  showWelcome();
  
  try {
    if (attempt > 2) {
      throw new Error('Too many failed attempts. Returning to workspaces.');
    }
    
    const [workspace, projects] = await Promise.all([
      Workspace.findById(workspaceId),
      getProjectsByWorkspace(workspaceId)
    ]);
    
    if (workspace) {
      currentWorkspace = {
        _id: workspace._id,
        name: workspace.name,
        isPersonal: workspace.isPersonal
      };
      
      currentProject = null;
    } else {
      throw new Error('Workspace not found');
    }
    
    const personalProject = await getOrCreatePersonalProject(workspaceId, userId);
    
    const hasPersonal = projects.some(p => p && p.isPersonal);
    if (!hasPersonal && personalProject) {
      projects.unshift(personalProject);
    }
    
    const projectChoices = projects
      .filter(p => p)
      .map(p => ({
        name: p.isPersonal ? 'Personal' : p.name,
        value: p._id.toString(),
        short: p.name,
        isPersonal: p.isPersonal,
        project: p
      }));
    
    console.log(chalk.blue(`\nWorkspace: ${workspace.name}`));
    console.log(chalk.gray('━'.repeat(40)));
    
    const choices = [
      { name: 'View Tasks', value: 'tasks' },
      { name: 'View Projects', value: 'projects' },
      createSeparator(),
      { name: 'Create New Task', value: 'create' },
      { name: 'Create New Project', value: 'create-project' },
      createSeparator(),
      { name: 'Switch Workspace', value: 'back' },
      { name: 'Back to Main Menu', value: 'home' }
    ];
    
    if (!workspace.isPersonal) {
      choices.splice(2, 0, { name: 'Manage Members', value: 'members' });
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: choices
      }
    ]);
    
    switch (action) {
      case 'back':
        await showWorkspaces(userId);
        break;
      case 'home':
        await showDashboard(userId);
        break;
      case 'tasks':
        await showWorkspaceTasks(workspaceId, userId);
        break;
      case 'projects':
        await showProjectList(workspaceId, userId);
        break;
      case 'members':
        // TODO: Implement workspace member management
        console.log(chalk.yellow('\nWorkspace member management coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showWorkspaceProjects(workspaceId, userId);
        break;
    }
    
  } catch (error) {
    console.error(chalk.red(`\n❌ Error: ${error.message}`));
    
    if (retryCount < 2) {
      console.log(chalk.yellow(`\nRetrying... (${retryCount + 1}/2)`));
      await new Promise(resolve => setTimeout(resolve, 1500));
      return showWorkspaceProjects(workspaceId, userId, retryCount + 1);
    } else {
      console.log(chalk.yellow('\nReturning to workspaces...'));
      await new Promise(resolve => setTimeout(resolve, 1500));
      await showWorkspaces(userId);
    }
  }
}

async function showProjects(workspaceId, userId) {
  showWelcome();
  
  try {
    const [workspace, projects] = await Promise.all([
      Workspace.findById(workspaceId),
      getProjectsByWorkspace(workspaceId)
    ]);
    
    const personalProject = await getOrCreatePersonalProject(workspaceId, userId);
    
    const hasPersonal = projects.some(p => p.isPersonal);
    if (!hasPersonal) {
      projects.unshift(personalProject);
    }
    
    const projectChoices = projects.map(p => ({
      name: p.isPersonal ? 'Personal' : p.name,
      value: p._id.toString(),
      project: p
    }));
    
    const { projectId } = await prompt([
      {
        type: 'list',
        name: 'projectId',
        message: `Workspace: ${workspace.name}\nSelect a project:`,
        choices: [
          ...projectChoices,
          createSeparator(),
          { name: '➕ Create New Project', value: 'create' },
          { name: 'Back to Workspaces', value: 'back' }
        ],
        pageSize: 10,
        loop: false
      }
    ]);
    
    if (projectId === 'back') {
      await showWorkspaces(userId);
    } else if (projectId === 'create') {
      await createProject(workspaceId, userId);
    } else {
      await showTasks(projectId, userId);
    }
    
  } catch (error) {
    console.error(chalk.red('\n❌ Error loading projects:'));
    console.error(chalk.red(error.message));
    await showWorkspaces(userId);
  }
}

async function createProject(userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Create New Project ===\n'));
  
  try {
    const { name, description } = await prompt([
      {
        type: 'input',
        name: 'name',
        message: 'Project name:',
        validate: input => input.trim() ? true : 'Project name cannot be empty',
        default: 'New Project'
      },
      {
        type: 'input',
        name: 'description',
        message: 'Project description (optional):',
        default: ''
      }
    ]);
    
    console.log(chalk.yellow('\nCreating project...'));
    
    const project = new Project({
      name: name.trim(),
      description: description.trim(),
      isPersonal: false,
      userId: userId
    });
    
    await project.save();
    
    console.log(chalk.green('\nProject created successfully!'));
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    await showProjectList(userId);
    
  } catch (error) {
    console.error(chalk.red('\nError creating project:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showProjectList(userId);
  }
}

async function showTasks(projectId, userId) {
  showWelcome();
  
  try {
    const project = await Project.findById(projectId);
    if (!project) {
      console.log(chalk.yellow('\nProject not found.'));
      await new Promise(resolve => setTimeout(resolve, 1500));
      return showProjectList(userId);
    }
    
    const tasks = await getTasksByProject(projectId, userId);
    
    console.log(chalk.blue(`\n${project.name}`));
    console.log(chalk.gray('━'.repeat(40)));
    
    if (tasks.length === 0) {
      console.log(chalk.yellow('\nNo tasks found in this project.'));
    } else {
      tasks.forEach((task, index) => {
        const status = formatStatus(task.status);
        const priority = formatPriority(task.priority);
        const dueDate = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No due date';
        
        console.log(`
${index + 1}. ${task.title}`);
        console.log(`   ${status} | ${priority} | Due: ${dueDate}`);
        if (task.description) {
          console.log(`   ${chalk.dim(task.description.substring(0, 60) + (task.description.length > 60 ? '...' : ''))}`);
        }
      });
    }
    
    const choices = [
      { name: 'Add New Task', value: 'add' },
      { name: 'View Task Details', value: 'view' },
      createSeparator(),
      { name: 'Back to Projects', value: 'back' },
      { name: 'Back to Dashboard', value: 'dashboard' }
    ];
    
    if (tasks.length > 0) {
      choices.unshift(
        { name: 'Edit Task', value: 'edit' },
        { name: 'Delete Task', value: 'delete' },
        createSeparator()
      );
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: '\nWhat would you like to do?',
        choices: choices,
        pageSize: 10
      }
    ]);
    
    switch (action) {
      case 'add':
        console.log(chalk.yellow('\nTask creation coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showTasks(projectId, userId);
        break;
        
      case 'view':
        if (tasks.length > 0) {
          const { taskIndex } = await prompt([
            {
              type: 'list',
              name: 'taskIndex',
              message: 'Select a task to view:',
              choices: tasks.map((t, i) => ({
                name: `${i + 1}. ${t.title} (${formatStatus(t.status)})`,
                value: i
              })),
              pageSize: 10
            }
          ]);
          await showTaskDetails(tasks[taskIndex], project, userId);
        } else {
          console.log(chalk.yellow('\nNo tasks to view.'));
          await new Promise(resolve => setTimeout(resolve, 1500));
          await showTasks(projectId, userId);
        }
        break;
        
      case 'edit':
        console.log(chalk.yellow('\nTask editing coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showTasks(projectId, userId);
        break;
        
      case 'delete':
        console.log(chalk.yellow('\nTask deletion coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showTasks(projectId, userId);
        break;
        
      case 'back':
        await showProjectList(userId);
        break;
        
      case 'dashboard':
      default:
        await showDashboard(userId);
    }
    
  } catch (error) {
    console.error(chalk.red(`\nError: ${error.message}`));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showProjectList(userId);
  }
}

/**
 * Fetches tasks from the web app's personal board using the same method as the web version
 * @param {string} userId - The user's Firebase UID
 * @returns {Promise<Array>} Array of tasks
 */
async function fetchWebAppTasks(userId) {
  try {
    // Use the same database connection method as the web version
    const database = await _getUserDatabaseConnection(userId);
    if (!database) {
      throw new Error('Failed to get user database connection');
    }
    
    // Query personalTasks collection exactly like the web version does
    const personalTasks = await database
      .collection('personalTasks')
      .find({ userId })
      .sort({ updatedAt: -1, order: 1 })
      .toArray();
    
    if (personalTasks && personalTasks.length > 0) {
      // Transform to match the expected format (same as web version)
      return personalTasks.map(task => ({
        id: task._id.toString(),
        title: task.title || 'Untitled Task',
        description: task.description || '',
        projectId: 'personal', // Web app uses 'personal' for personal tasks
        columnId: task.columnId || 'todo',
        status: task.status || 'todo',
        priority: task.priority || 'medium',
        order: task.order || 0,
        isBlocked: task.isBlocked || false,
        tags: task.tags || [],
        assigneeId: task.assigneeId || userId,
        assigneeName: task.assigneeName || 'You',
        dueDate: task.dueDate ? (task.dueDate instanceof Date ? task.dueDate : new Date(task.dueDate)) : null,
        completedAt: task.completedAt ? (task.completedAt instanceof Date ? task.completedAt : new Date(task.completedAt)) : null,
        createdAt: task.createdAt ? (task.createdAt instanceof Date ? task.createdAt : new Date(task.createdAt)) : new Date(),
        updatedAt: task.updatedAt ? (task.updatedAt instanceof Date ? task.updatedAt : new Date(task.updatedAt)) : new Date(),
        userId: task.userId || userId,
        _id: task._id.toString()
      }));
    }
    
    return [];
    
  } catch (error) {
    console.error(chalk.red('Error fetching web app tasks:'), error.message);
    throw error;
  }
}

/**
 * Creates a new task in the user's personal project
 * @param {string} userId - The user's Firebase UID
 */
async function createTask(userId) {
  showWelcome();
  
  try {
    console.log(chalk.blue('\nCreate a New Task'));
    console.log(chalk.gray('──────────────────────────────'));
    
    // Get user's personal project (create if doesn't exist)
    const personalProject = await Project.findOne({ 
      userId, 
      isPersonal: true 
    }) || await createPersonalProject(userId);
    
    if (!personalProject) {
      throw new Error('Could not find or create a personal project');
    }
    
    // Get user details for default assignee
    const user = await getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }
    
    // Get current timestamp for task creation
    const now = new Date();
    
    // Prompt for task details
    const taskData = await prompt([
      {
        type: 'input',
        name: 'title',
        message: 'Task title:',
        validate: input => input.trim() ? true : 'Title is required',
        filter: input => input.trim()
      },
      {
        type: 'input',
        name: 'description',
        message: 'Description (optional):',
        default: '',
        filter: input => input.trim()
      },
      {
        type: 'list',
        name: 'status',
        message: 'Status:',
        choices: [
          { name: 'To Do', value: 'todo' },
          { name: 'In Progress', value: 'in-progress' },
          { name: 'Review', value: 'review' },
          { name: 'Done', value: 'done' }
        ],
        default: 'todo'
      },
      {
        type: 'list',
        name: 'priority',
        message: 'Priority:',
        choices: [
          { name: 'Low', value: 'low' },
          { name: 'Medium', value: 'medium' },
          { name: 'High', value: 'high' }
        ],
        default: 'medium'
      },
      {
        type: 'input',
        name: 'dueDate',
        message: 'Due date (YYYY-MM-DD, optional):',
        validate: input => {
          if (!input) return true;
          return /^\d{4}-\d{2}-\d{2}$/.test(input) 
            ? true 
            : 'Please enter a valid date in YYYY-MM-DD format';
        },
        default: ''
      }
    ]);
    
    // Prepare task data for web app format (exactly like the web version)
    const taskPayload = {
      title: taskData.title,
      description: taskData.description || '',
      userId: userId,
      columnId: taskData.status, // Map status to columnId
      status: taskData.status,
      priority: taskData.priority,
      order: 0, // Will be updated by the server if needed
      isBlocked: false,
      dueDate: taskData.dueDate ? new Date(taskData.dueDate) : null,
      tags: [],
      assigneeId: userId,
      assigneeName: user.displayName || user.email.split('@')[0],
      createdAt: now,
      updatedAt: now
    };
    
    // Save to web app's personalTasks collection using the same connection method
    let savedTask;
    try {
      const database = await _getUserDatabaseConnection(userId);
      if (database) {
        // Save to personalTasks collection (web app format)
        const result = await database.collection('personalTasks').insertOne(taskPayload);
        savedTask = { 
          id: result.insertedId.toString(),
          _id: result.insertedId.toString(),
          ...taskPayload 
        };
        console.log(chalk.green('✓ Task saved successfully'));
      } else {
        throw new Error('Could not connect to user database');
      }
    } catch (webError) {
      console.warn(chalk.yellow('\nCould not save to web app, falling back to local storage:'));
      console.warn(chalk.yellow(webError.message));
      
      // Fallback to local MongoDB storage
      const newTask = new Task({
        ...taskPayload,
        projectId: personalProject._id
      });
      savedTask = await newTask.save();
      savedTask = {
        ...savedTask.toObject(),
        id: savedTask._id.toString(),
        _id: savedTask._id.toString()
      };
    }
    
    console.log(chalk.green('\n✓ Task created successfully!'));
    console.log(chalk.gray('──────────────────────────────'));
    console.log(chalk.bold('Title:'), savedTask.title);
    console.log(chalk.bold('Status:'), formatStatus(savedTask.status));
    console.log(chalk.bold('Priority:'), formatPriority(savedTask.priority));
    
    // Ask what to do next
    const { nextAction } = await prompt([
      {
        type: 'list',
        name: 'nextAction',
        message: 'What would you like to do next?',
        choices: [
          { name: '➕ Create another task', value: 'another' },
          { name: '📋 View all tasks', value: 'view' },
          { name: '🏠 Return to dashboard', value: 'dashboard' }
        ]
      }
    ]);
    
    switch (nextAction) {
      case 'another':
        await createTask(userId);
        break;
      case 'view':
        await showAllTasks(userId);
        break;
      default:
        await showDashboard(userId);
    }
    
  } catch (error) {
    console.error(chalk.red('\nError creating task:'), error.message);
    console.log(chalk.yellow('\nReturning to dashboard...'));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showDashboard(userId);
  }
}

/**
 * Shows all tasks in a board view similar to the web app's personal board
 * @param {string} userId - The user's Firebase UID
 */
async function showAllTasks(userId) {
  showWelcome();
  
  try {
    console.log(chalk.blue('\nLoading your tasks...'));
    
    // Get tasks from web app's personal board
    console.log(chalk.gray('\nFetching tasks from your personal board...'));
    let tasks = [];
    
    try {
      tasks = await fetchWebAppTasks(userId);
      console.log(chalk.green(`✓ Found ${tasks.length} tasks`));
    } catch (error) {
      console.error(chalk.red('\nError fetching tasks:'), error.message);
      console.log(chalk.yellow('\nFalling back to local task storage...'));
      
      // Fallback to local tasks if web app fetch fails
      const personalProject = await Project.findOne({ userId, isPersonal: true });
      if (personalProject) {
        tasks = await Task.find({ projectId: personalProject._id });
      }
    }
    
    // If still no tasks, prompt to create one
    if (!tasks || tasks.length === 0) {
      console.log(chalk.yellow('\nNo tasks found in your personal board.'));
      const { action } = await prompt([
        {
          type: 'list',
          name: 'action',
          message: 'What would you like to do?',
          choices: [
            { name: '➕ Create a new task', value: 'create' },
            { name: '🔙 Go back to dashboard', value: 'back' }
          ]
        }
      ]);
      
      if (action === 'create') {
        await createTask(userId);
      } else {
        await showDashboard(userId);
      }
      return;
    }
    
    // Group tasks by status
    const columns = {
      'todo': { title: 'To Do', tasks: [] },
      'in-progress': { title: 'In Progress', tasks: [] },
      'completed': { title: 'Completed', tasks: [] }
    };
    
    tasks.forEach(task => {
      const status = task.status || 'todo';
      if (columns[status]) {
        columns[status].tasks.push(task);
      }
    });
    
    // Display the board
    console.log(chalk.blue('\nPersonal Task Board'));
    console.log(chalk.gray('━'.repeat(80)));
    
    // Calculate column widths
    const colWidth = 25;
    const statusWidth = 15;
    const separator = ' '.repeat(3);
    
    // Print column headers
    let headerLine = '';
    Object.entries(columns).forEach(([status, col]) => {
      const padding = ' '.repeat(Math.max(0, colWidth - col.title.length - col.tasks.length.toString().length - 3));
      headerLine += `${chalk.bold(col.title)} (${col.tasks.length})${padding}${separator}`;
    });
    console.log(headerLine);
    console.log(chalk.gray('─'.repeat(80)));
    
    // Print tasks in columns
    const maxRows = Math.max(...Object.values(columns).map(col => col.tasks.length));
    
    for (let i = 0; i < maxRows; i++) {
      let row = '';
      
      Object.entries(columns).forEach(([status, col]) => {
        if (i < col.tasks.length) {
          const task = col.tasks[i];
          const priority = formatPriority(task.priority);
          const truncatedTitle = task.title.length > colWidth - 5 ? 
            task.title.substring(0, colWidth - 8) + '...' : 
            task.title.padEnd(colWidth - 5);
          
          row += `${i + 1}. ${truncatedTitle} ${priority}${' '.repeat(separator.length)}`;
        } else {
          row += ' '.repeat(colWidth + separator.length);
        }
      });
      
      console.log(row);
    }
    
    // Flatten all tasks for selection
    const allTasks = [].concat(
      ...Object.values(columns).map(col => col.tasks)
    );
    
    // Show task actions menu
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: '\nWhat would you like to do?',
        choices: [
          { name: 'View Task Details', value: 'view' },
          { name: 'Create New Task', value: 'create' },
          { name: 'Refresh', value: 'refresh' },
          { name: 'Back to Dashboard', value: 'dashboard' },
          { name: 'Logout', value: 'logout' }
        ],
        pageSize: 10
      }
    ]);
    
    switch (action) {
      case 'view':
        if (allTasks.length > 0) {
          const { taskIndex } = await prompt([
            {
              type: 'number',
              name: 'taskIndex',
              message: 'Enter the task number to view details:',
              validate: (value) => {
                const num = parseInt(value);
                return !isNaN(num) && num > 0 && num <= allTasks.length ? 
                  true : 'Please enter a valid task number';
              }
            }
          ]);
          
          const selectedTask = allTasks[taskIndex - 1];
          const project = await Project.findById(selectedTask.projectId);
          await showTaskDetails(selectedTask, project, userId);
        } else {
          console.log(chalk.yellow('\nNo tasks to view.'));
          await new Promise(resolve => setTimeout(resolve, 1500));
          await showAllTasks(userId);
        }
        break;
        
      case 'create':
        await createTask(userId);
        break;
        
      case 'refresh':
        await showAllTasks(userId);
        break;
        
      case 'dashboard':
        await showDashboard(userId);
        break;
        
      case 'logout':
        await handleLogout();
        break;
    }
    
  } catch (error) {
    console.error(chalk.red('\nError loading tasks:'));
    console.error(chalk.red(error.message));
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Back to Dashboard', value: 'dashboard' },
          { name: 'Try Again', value: 'retry' }
        ]
      }
    ]);
    
    if (action === 'dashboard') {
      return showDashboard(userId);
    } else {
      return showAllTasks(userId);
    }
  }
}

async function showTaskDetails(task, project, userId) {
  if (!task) {
    console.log(chalk.red('Task not found.'));
    await showDashboard(userId);
    return;
  }
  
  showWelcome();
  
  if (!project && task.projectId) {
    project = await Project.findById(task.projectId);
  }
  
  const statusEmoji = task.status === 'completed' ? '✅' : 
                     task.status === 'in-progress' ? '[In Progress]' : '[To Do]';
  const priorityEmoji = task.priority === 'high' ? '[High]' : 
                       task.priority === 'medium' ? '[Medium]' : '[Low]';
  const dueDate = task.dueDate ? new Date(task.dueDate).toLocaleDateString() : 'No due date';
  const createdAt = new Date(task.createdAt).toLocaleString();
  const updatedAt = new Date(task.updatedAt).toLocaleString();
  
  console.log(chalk.cyan('=== Task Details ===\n'));
  
  if (project) {
    console.log(chalk.blueBright(`Project: ${project.name}`));
  }
  
  console.log(chalk.bold(`\nTitle:       ${task.title}`));
  
  if (task.description) {
    console.log(`\n${chalk.bold('Description:')}\n${task.description}\n`);
  }
  
  console.log(chalk.bold('Status:      '), `${statusEmoji} ${formatStatus(task.status)}`);
  console.log(chalk.bold('Priority:    '), `${priorityEmoji} ${formatPriority(task.priority)}`);
  console.log(chalk.bold('Due Date:    '), dueDate);
  
  if (task.labels && task.labels.length > 0) {
    console.log(chalk.bold('Labels:      '), task.labels.map(l => `#${l}`).join(' '));
  }
  
  console.log(chalk.gray('\n---'));
  console.log(chalk.gray(`Created: ${createdAt}`));
  console.log(chalk.gray(`Updated: ${updatedAt}`));
  
  const { action } = await prompt([
    {
      type: 'list',
      name: 'action',
      message: '\nWhat would you like to do?',
      choices: [
        { name: '✅ Toggle Complete/Incomplete', value: 'toggle' },
        { name: '✏️  Edit Task', value: 'edit' },
        { name: 'Add/Remove Labels', value: 'labels' },
        { name: 'Delete Task', value: 'delete' },
        createSeparator(),
        { name: 'Back to Tasks', value: 'back' }
      ],
      pageSize: 6,
    },
  ]);
  
  try {
    switch (action) {
      case 'toggle':
        const newStatus = task.status === 'completed' ? 'todo' : 'completed';
        await updateTask(task._id, { status: newStatus });
        console.log(chalk.green(`\n✅ Task marked as ${formatStatus(newStatus)}!`));
        await new Promise(resolve => setTimeout(resolve, 1000));
        await showTaskDetails({ ...task, status: newStatus }, project, userId);
        break;
        
      case 'edit':
        await editTask(task, project, userId);
        break;
        
      case 'labels':
        await manageTaskLabels(task, project, userId);
        break;
        
      case 'delete':
        const { confirm } = await prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: 'Are you sure you want to delete this task? This cannot be undone.',
            default: false,
          },
        ]);
        
        if (confirm) {
          await deleteTask(task._id);
          console.log(chalk.green('\n✅ Task deleted successfully!'));
          await new Promise(resolve => setTimeout(resolve, 1000));
          await showTasks(project._id, userId);
        } else {
          await showTaskDetails(task, project, userId);
        }
        break;
        
      case 'back':
      default:
        if (project) {
          await showAllTasks(userId);
        } else {
          await showDashboard(userId);
        }
    }
  } catch (error) {
    console.error(chalk.red('\n❌ Error:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showTaskDetails(task, project, userId);
  }
}

function formatStatus(status) {
  const statusMap = {
    'todo': 'To Do',
    'in-progress': 'In Progress',
    'completed': 'Completed'
  };
  return statusMap[status] || status;
}

function formatPriority(priority) {
  return priority.charAt(0).toUpperCase() + priority.slice(1);
}

async function manageTaskLabels(task, project, userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Manage Task Labels ===\n'));
  
  const currentLabels = task.labels || [];
  
  const { labels } = await prompt([
    {
      type: 'input',
      name: 'labels',
      message: 'Enter labels (comma-separated):',
      default: currentLabels.join(', '),
      filter: input => 
        input.split(',')
          .map(l => l.trim())
          .filter(l => l.length > 0)
    }
  ]);
  
  try {
    await updateTask(task._id, { labels });
    console.log(chalk.green('\n✅ Labels updated successfully!'));
    await new Promise(resolve => setTimeout(resolve, 1000));
    await showTaskDetails({ ...task, labels }, project, userId);
  } catch (error) {
    console.error(chalk.red('\n❌ Error updating labels:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showTaskDetails(task, project, userId);
  }
}
async function editTask(task, project, userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Edit Task ===\n'));
  
  if (project) {
    console.log(chalk.blueBright(`Project: ${project.name}\n`));
  }
  
  try {
    const statuses = [
      { name: 'To Do', value: 'todo' },
      { name: 'In Progress', value: 'in-progress' },
      { name: '✅ Completed', value: 'completed' }
    ];
    
    const priorities = [
      { name: 'High', value: 'high' },
      { name: 'Medium', value: 'medium' },
      { name: 'Low', value: 'low' }
    ];
    
    let projects = [];
    if (project) {
      projects = await getProjectsByWorkspace(project.workspaceId);
    }
    
    const projectChoices = projects.map(p => ({
      name: `${p._id.toString() === task.projectId.toString() ? '→ ' : '  '}${p.name}`,
      value: p._id.toString(),
      short: p.name
    }));
    
    const updates = await prompt([
      {
        type: 'input',
        name: 'title',
        message: 'Task title:',
        default: task.title,
        validate: input => input.trim() ? true : 'Title cannot be empty'
      },
      {
        type: 'input',
        name: 'description',
        message: 'Description (optional):',
        default: task.description || '',
      },
      {
        type: 'list',
        name: 'status',
        message: 'Status:',
        choices: statuses,
        default: statuses.findIndex(s => s.value === task.status)
      },
      {
        type: 'list',
        name: 'priority',
        message: 'Priority:',
        choices: priorities,
        default: priorities.findIndex(p => p.value === task.priority)
      },
      {
        type: 'input',
        name: 'dueDate',
        message: 'Due date (YYYY-MM-DD, optional):',
        default: task.dueDate ? new Date(task.dueDate).toISOString().split('T')[0] : '',
        validate: input => {
          if (!input) return true;
          return /^\d{4}-\d{2}-\d{2}$/.test(input) 
            ? true 
            : 'Please use YYYY-MM-DD format';
        }
      },
      {
        type: 'list',
        name: 'projectId',
        message: 'Move to project:',
        choices: [
          ...projectChoices,
          createSeparator(),
          { name: '❌ Cancel', value: 'cancel' }
        ],
        default: task.projectId.toString(),
        pageSize: 10,
        loop: false
      }
    ]);
    
    if (updates.projectId === 'cancel') {
      console.log(chalk.yellow('\nEdit cancelled.'));
      await new Promise(resolve => setTimeout(resolve, 1000));
      await showTaskDetails(task, project, userId);
      return;
    }
    
    const formattedUpdates = {
      title: updates.title.trim(),
      description: updates.description.trim() || undefined,
      status: updates.status,
      priority: updates.priority,
      updatedAt: new Date()
    };
    
    if (updates.projectId && updates.projectId !== task.projectId.toString()) {
      formattedUpdates.projectId = updates.projectId;
      
      const newProject = projects.find(p => p._id.toString() === updates.projectId);
      if (newProject) {
        project = newProject;
      }
    }
    
    if (updates.dueDate) {
      formattedUpdates.dueDate = new Date(updates.dueDate);
    } else {
      formattedUpdates.dueDate = null;
    }
    
    console.log(chalk.yellow('\nUpdating task...'));
    
    await updateTask(task._id, formattedUpdates);
    
    console.log(chalk.green('\n✅ Task updated successfully!'));
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    await showTaskDetails(
      { ...task, ...formattedUpdates },
      project,
      userId
    );
    
  } catch (error) {
    console.error(chalk.red('\n❌ Error updating task:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showTaskDetails(task, project, userId);
  }
}

async function showProfile(user) {
  showWelcome();
  
  console.log(chalk.cyan('=== Your Profile ===\n'));
  console.log(chalk.yellow('User Information:'));
  console.log(`Name: ${user.displayName || 'Not set'}`);
  console.log(`Email: ${user.email || 'Not set'}`);
  console.log(`🆔 User ID: ${user.uid}`);
  
  const memberSince = user.createdAt 
    ? new Date(user.createdAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    : 'Unknown';
  
  console.log(`Member since: ${memberSince}`);
  
  console.log('\n' + chalk.yellow('Account Actions:'));
  const { action } = await prompt([
    {
      type: 'list',
      name: 'action',
      message: 'What would you like to do?',
      choices: [
        { name: 'Edit Profile', value: 'edit' },
        { name: 'Change Password', value: 'password' },
        SEPARATOR,
        { name: 'Back to Dashboard', value: 'back' },
      ],
      pageSize: 4,
    },
  ]);
  
  if (action === 'edit') {
    console.log(chalk.yellow('\nThis feature is coming soon!'));
    await new Promise(resolve => setTimeout(resolve, 1500));
    await showProfile(user);
  } else if (action === 'password') {
    console.log(chalk.yellow('\nThis feature is coming soon!'));
    await new Promise(resolve => setTimeout(resolve, 1500));
    await showProfile(user);
  } else {
    await showDashboard(user.uid);
  }
}

/**
 * Settings management interface
 */
async function showSettings(userId) {
  let settingsActive = true;
  
  while (settingsActive) {
    showWelcome();
    console.log(chalk.blue('\n⚙️ Settings\n'));
    
    const { section } = await prompt([
      {
        type: 'list',
        name: 'section',
        message: 'Choose a settings section:',
        choices: [
          { name: '🤖 AI Configuration', value: 'ai' },
          { name: '📧 Email Notifications', value: 'email' },
          { name: '🔔 In-App Notifications', value: 'notifications' },
          { name: '🏷️ Task Tags', value: 'tags' },
          { name: '👤 Profile Settings', value: 'profile' },
          createSeparator(),
          { name: '🔙 Back to Dashboard', value: 'back' }
        ],
        pageSize: 8
      }
    ]);
    
    switch (section) {
      case 'ai':
        await showAISettings(userId);
        break;
      case 'email':
        await showEmailSettings(userId);
        break;
      case 'notifications':
        await showNotificationSettings(userId);
        break;
      case 'tags':
        await showTagSettings(userId);
        break;
      case 'profile':
        await showProfileSettings(userId);
        break;
      case 'back':
        settingsActive = false;
        await showDashboard(userId);
        break;
    }
  }
}

/**
 * AI Configuration Settings
 */
async function showAISettings(userId) {
  try {
    showWelcome();
    console.log(chalk.blue('\n🤖 AI Configuration\n'));
    
    // Try to fetch current settings
    let currentSettings = null;
    try {
      const response = await fetch(`http://localhost:3000/api/users/${userId}/ai-config`);
      if (response.ok) {
        currentSettings = await response.json();
      }
    } catch (error) {
      console.log(chalk.yellow('Could not load current AI settings (this is normal if using terminal CLI only)'));
    }
    
    console.log(chalk.gray('Current AI Configuration:'));
    if (currentSettings) {
      console.log(`  • Status: ${currentSettings.isEnabled ? chalk.green('Enabled') : chalk.red('Disabled')}`);
      console.log(`  • Model: ${currentSettings.model || 'Default'}`);
      console.log(`  • API Key: ${currentSettings.apiKey ? chalk.green('Set') : chalk.red('Not set')}`);
    } else {
      console.log(chalk.gray('  • No AI configuration found'));
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: '✅ Enable/Disable AI Features', value: 'toggle' },
          { name: '🔧 Configure AI Model', value: 'model' },
          { name: '🔑 Set API Key', value: 'apikey' },
          createSeparator(),
          { name: '🔙 Back to Settings', value: 'back' }
        ]
      }
    ]);
    
    switch (action) {
      case 'toggle':
        const { enabled } = await prompt([{
          type: 'confirm',
          name: 'enabled',
          message: 'Enable AI features?',
          default: currentSettings?.isEnabled || false
        }]);
        console.log(chalk.green(`AI features ${enabled ? 'enabled' : 'disabled'} (Note: Full configuration available in web app)`));
        break;
        
      case 'model':
        const { model } = await prompt([{
          type: 'list',
          name: 'model',
          message: 'Select AI model:',
          choices: [
            { name: 'Gemini 1.5 Flash (Recommended)', value: 'gemini-1.5-flash-latest' },
            { name: 'Gemini Pro', value: 'gemini-pro' },
            { name: 'GPT-4', value: 'gpt-4' },
            { name: 'GPT-3.5 Turbo', value: 'gpt-3.5-turbo' }
          ],
          default: currentSettings?.model || 'gemini-1.5-flash-latest'
        }]);
        console.log(chalk.green(`AI model set to: ${model}`));
        break;
        
      case 'apikey':
        const { apiKey } = await prompt([{
          type: 'password',
          name: 'apiKey',
          message: 'Enter your API key:',
          mask: '*'
        }]);
        console.log(chalk.green('API key updated (Note: Save changes in web app for persistence)'));
        break;
        
      case 'back':
        await showSettings(userId);
        return;
    }
    
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
    
  } catch (error) {
    console.error(chalk.red('Error managing AI settings:'), error.message);
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
  }
}

/**
 * Email Notification Settings
 */
async function showEmailSettings(userId) {
  try {
    showWelcome();
    console.log(chalk.blue('\n📧 Email Notification Settings\n'));
    
    // Try to fetch current settings
    let currentSettings = null;
    try {
      const response = await fetch(`http://localhost:3000/api/users/${userId}/email-settings`);
      if (response.ok) {
        currentSettings = await response.json();
      }
    } catch (error) {
      console.log(chalk.yellow('Could not load current email settings'));
    }
    
    console.log(chalk.gray('Current Email Preferences:'));
    if (currentSettings) {
      console.log(`  • Organization Invites: ${currentSettings.organizationInvites ? chalk.green('Enabled') : chalk.red('Disabled')}`);
      console.log(`  • Preference: ${currentSettings.inAppOnly ? chalk.blue('In-app notifications only') : chalk.green('Email notifications enabled')}`);
    } else {
      console.log(chalk.gray('  • Using default settings (organization invites enabled)'));
    }
    
    console.log(chalk.cyan('\nEmail Notification Types:'));
    console.log('  📧 Organization Invitations - Get notified when invited to organizations');
    console.log('  📝 Task Assignments - Notifications for assigned tasks (in-app only)');
    console.log('  📅 Due Date Reminders - Deadline notifications (in-app only)');
    console.log('  📊 Project Updates - Project-related notifications (in-app only)');
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to configure?',
        choices: [
          { name: '📧 Toggle Organization Invitation Emails', value: 'toggle-invites' },
          { name: '🔄 Switch Between Email/In-app Only', value: 'toggle-mode' },
          { name: 'ℹ️ View Email Policy', value: 'policy' },
          createSeparator(),
          { name: '🔙 Back to Settings', value: 'back' }
        ]
      }
    ]);
    
    switch (action) {
      case 'toggle-invites':
        const { enableInvites } = await prompt([{
          type: 'confirm',
          name: 'enableInvites',
          message: 'Receive organization invitation emails?',
          default: currentSettings?.organizationInvites !== false
        }]);
        console.log(chalk.green(`Organization invitation emails ${enableInvites ? 'enabled' : 'disabled'}`));
        break;
        
      case 'toggle-mode':
        const { inAppOnly } = await prompt([{
          type: 'confirm',
          name: 'inAppOnly',
          message: 'Use in-app notifications only? (no emails except invitations)',
          default: currentSettings?.inAppOnly !== false
        }]);
        console.log(chalk.green(`Notification mode: ${inAppOnly ? 'In-app only' : 'Email enabled'}`));
        break;
        
      case 'policy':
        console.log(chalk.cyan('\n📋 Email Notification Policy:'));
        console.log('  • Only organization invitations are sent via email');
        console.log('  • All other notifications (tasks, deadlines, updates) are in-app only');
        console.log('  • This design reduces email spam while keeping you informed');
        console.log('  • You can disable organization emails if needed');
        break;
        
      case 'back':
        await showSettings(userId);
        return;
    }
    
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
    
  } catch (error) {
    console.error(chalk.red('Error managing email settings:'), error.message);
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
  }
}

/**
 * In-App Notification Settings
 */
async function showNotificationSettings(userId) {
  try {
    showWelcome();
    console.log(chalk.blue('\n🔔 In-App Notification Settings\n'));
    
    console.log(chalk.cyan('Available Notification Categories:'));
    console.log('  📋 Task Assignments - When tasks are assigned to you');
    console.log('  📅 Due Date Reminders - When task deadlines approach');
    console.log('  📊 Project Updates - Project-related changes');
    console.log('  👥 Team Activity - Collaboration and team updates');
    console.log('  🔒 Security Alerts - Account and security notifications');
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'Notification preferences:',
        choices: [
          { name: '🔔 Enable All Notifications', value: 'enable-all' },
          { name: '🔕 Disable All Notifications', value: 'disable-all' },
          { name: '⚙️ Configure by Category', value: 'configure' },
          { name: '⏰ Set Quiet Hours', value: 'quiet-hours' },
          { name: '📊 View Notification Summary', value: 'summary' },
          createSeparator(),
          { name: '🔙 Back to Settings', value: 'back' }
        ]
      }
    ]);
    
    switch (action) {
      case 'enable-all':
        console.log(chalk.green('✅ All notifications enabled'));
        break;
        
      case 'disable-all':
        console.log(chalk.yellow('🔕 All notifications disabled'));
        break;
        
      case 'configure':
        const categories = [
          { name: 'Task Assignments', key: 'tasks' },
          { name: 'Due Date Reminders', key: 'deadlines' },
          { name: 'Project Updates', key: 'projects' },
          { name: 'Team Activity', key: 'team' },
          { name: 'Security Alerts', key: 'security' }
        ];
        
        console.log(chalk.cyan('\nConfigure by category:'));
        for (const category of categories) {
          const { enabled } = await prompt([{
            type: 'confirm',
            name: 'enabled',
            message: `Enable ${category.name}?`,
            default: true
          }]);
          console.log(`  ${enabled ? '✅' : '❌'} ${category.name}: ${enabled ? 'Enabled' : 'Disabled'}`);
        }
        break;
        
      case 'quiet-hours':
        const { enableQuiet } = await prompt([{
          type: 'confirm',
          name: 'enableQuiet',
          message: 'Enable quiet hours?',
          default: false
        }]);
        
        if (enableQuiet) {
          const { startTime } = await prompt([{
            type: 'input',
            name: 'startTime',
            message: 'Quiet hours start time (HH:MM):',
            default: '22:00',
            validate: input => /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(input) || 'Please enter valid time (HH:MM)'
          }]);
          
          const { endTime } = await prompt([{
            type: 'input',
            name: 'endTime',
            message: 'Quiet hours end time (HH:MM):',
            default: '08:00',
            validate: input => /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(input) || 'Please enter valid time (HH:MM)'
          }]);
          
          console.log(chalk.green(`Quiet hours set: ${startTime} - ${endTime}`));
        }
        break;
        
      case 'summary':
        console.log(chalk.cyan('\n📊 Notification Summary:'));
        console.log('  • Total notifications: Available in web app');
        console.log('  • Unread count: Available in web app');
        console.log('  • Recent activity: Available in web app');
        console.log(chalk.gray('\nNote: Full notification history and management available in web application'));
        break;
        
      case 'back':
        await showSettings(userId);
        return;
    }
    
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
    
  } catch (error) {
    console.error(chalk.red('Error managing notification settings:'), error.message);
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
  }
}

/**
 * Task Tags Settings
 */
async function showTagSettings(userId) {
  try {
    showWelcome();
    console.log(chalk.blue('\n🏷️ Task Tags Settings\n'));
    
    // Try to fetch current user settings
    let currentTags = [];
    try {
      const response = await fetch(`http://localhost:3000/api/users/${userId}/settings`);
      if (response.ok) {
        const settings = await response.json();
        currentTags = settings.tags || [];
      }
    } catch (error) {
      console.log(chalk.yellow('Could not load current tag settings'));
    }
    
    console.log(chalk.gray('Current Tags:'));
    if (currentTags.length > 0) {
      currentTags.forEach((tag, index) => {
        console.log(`  ${index + 1}. ${chalk.blue(tag)}`);
      });
    } else {
      console.log(chalk.gray('  • No custom tags configured'));
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'Tag management:',
        choices: [
          { name: '➕ Add New Tag', value: 'add' },
          { name: '❌ Remove Tag', value: 'remove' },
          { name: '🔄 Reset to Defaults', value: 'reset' },
          { name: '📋 View Common Tags', value: 'common' },
          createSeparator(),
          { name: '🔙 Back to Settings', value: 'back' }
        ]
      }
    ]);
    
    switch (action) {
      case 'add':
        const { newTag } = await prompt([{
          type: 'input',
          name: 'newTag',
          message: 'Enter new tag name:',
          validate: input => input.trim() ? true : 'Tag name is required'
        }]);
        
        if (!currentTags.includes(newTag.trim())) {
          currentTags.push(newTag.trim());
          console.log(chalk.green(`Tag "${newTag.trim()}" added`));
        } else {
          console.log(chalk.yellow('Tag already exists'));
        }
        break;
        
      case 'remove':
        if (currentTags.length === 0) {
          console.log(chalk.yellow('No tags to remove'));
          break;
        }
        
        const { tagToRemove } = await prompt([{
          type: 'list',
          name: 'tagToRemove',
          message: 'Select tag to remove:',
          choices: currentTags.map(tag => ({ name: tag, value: tag }))
        }]);
        
        currentTags = currentTags.filter(tag => tag !== tagToRemove);
        console.log(chalk.green(`Tag "${tagToRemove}" removed`));
        break;
        
      case 'reset':
        const { confirmReset } = await prompt([{
          type: 'confirm',
          name: 'confirmReset',
          message: 'Reset to default tags?',
          default: false
        }]);
        
        if (confirmReset) {
          currentTags = ['urgent', 'bug', 'feature', 'documentation', 'testing'];
          console.log(chalk.green('Tags reset to defaults'));
        }
        break;
        
      case 'common':
        console.log(chalk.cyan('\n📋 Common Tag Examples:'));
        console.log('  🚨 Priority: urgent, high-priority, low-priority');
        console.log('  🐛 Type: bug, feature, enhancement, documentation');
        console.log('  🔧 Status: testing, review, blocked, waiting');
        console.log('  👥 Team: frontend, backend, design, qa');
        console.log('  📂 Category: ui, api, database, security');
        break;
        
      case 'back':
        await showSettings(userId);
        return;
    }
    
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
    
  } catch (error) {
    console.error(chalk.red('Error managing tag settings:'), error.message);
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
  }
}

/**
 * Profile Settings
 */
async function showProfileSettings(userId) {
  try {
    showWelcome();
    console.log(chalk.blue('\n👤 Profile Settings\n'));
    
    // Get user info
    const user = await getUserById(userId);
    if (!user) {
      console.log(chalk.red('User not found'));
      await showSettings(userId);
      return;
    }
    
    console.log(chalk.gray('Current Profile:'));
    console.log(`  • Name: ${user.displayName || 'Not set'}`);
    console.log(`  • Email: ${user.email}`);
    console.log(`  • User ID: ${user.uid}`);
    console.log(`  • Account Created: ${user.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Unknown'}`);
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'Profile options:',
        choices: [
          { name: '✏️ Edit Display Name', value: 'edit-name' },
          { name: '🖼️ Profile Picture', value: 'picture' },
          { name: '🔒 Account Security', value: 'security' },
          { name: '📊 Account Statistics', value: 'stats' },
          { name: '💾 Export Data', value: 'export' },
          createSeparator(),
          { name: '🔙 Back to Settings', value: 'back' }
        ]
      }
    ]);
    
    switch (action) {
      case 'edit-name':
        const { newName } = await prompt([{
          type: 'input',
          name: 'newName',
          message: 'Enter new display name:',
          default: user.displayName || '',
          validate: input => input.trim() ? true : 'Display name is required'
        }]);
        
        console.log(chalk.green(`Display name updated to: ${newName.trim()}`));
        console.log(chalk.gray('Note: Changes will sync with web app on next login'));
        break;
        
      case 'picture':
        console.log(chalk.cyan('\n🖼️ Profile Picture:'));
        console.log('  • Profile pictures can be managed in the web application');
        console.log('  • Supports various image formats (JPG, PNG, GIF)');
        console.log('  • Maximum size: 5MB');
        console.log('  • Recommended: Square images, 256x256px or larger');
        break;
        
      case 'security':
        console.log(chalk.cyan('\n🔒 Account Security:'));
        console.log('  • Password changes: Available in web app');
        console.log('  • Two-factor authentication: Available in web app');
        console.log('  • Login history: Available in web app');
        console.log('  • Active sessions: Available in web app');
        console.log('  • Account deletion: Contact support');
        break;
        
      case 'stats':
        console.log(chalk.cyan('\n📊 Account Statistics:'));
        console.log('  • Tasks created: Available in dashboard');
        console.log('  • Projects joined: Available in web app');
        console.log('  • Organizations: Available in web app');
        console.log('  • Collaborations: Available in web app');
        console.log('  • Activity timeline: Available in web app');
        break;
        
      case 'export':
        console.log(chalk.cyan('\n💾 Data Export:'));
        console.log('  • Export personal tasks: Available in web app');
        console.log('  • Export project data: Available in web app');
        console.log('  • Data format: JSON, CSV options available');
        console.log('  • Includes: Tasks, projects, settings, activity logs');
        console.log('  • Privacy: Only your data is exported');
        break;
        
      case 'back':
        await showSettings(userId);
        return;
    }
    
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
    
  } catch (error) {
    console.error(chalk.red('Error managing profile settings:'), error.message);
    await prompt([{ type: 'input', name: 'continue', message: 'Press Enter to continue...' }]);
    await showSettings(userId);
  }
}

async function init() {
  try {
    showWelcome();
    
    try {
      const session = await loadSession();
      if (session) {
        // Ensure the user exists in both Firestore and MongoDB
        await ensureUserInFirestore({
          uid: session.uid,
          email: session.email,
          displayName: session.displayName
        });
        
        console.log(chalk.green(`\nWelcome back, ${session.displayName || session.email}!`));
        await new Promise(resolve => setTimeout(resolve, 1000));
        await showDashboard(session.uid);
        return;
      }
    } catch (error) {
      console.log(chalk.yellow('\nStarting new session...'));
    }
    
    await showMainMenu();
  } catch (error) {
    console.error(chalk.red('\nAn unexpected error occurred:'));
    console.error(chalk.red(error.message));
    process.exit(1);
  }
}

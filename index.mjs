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
  User 
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
    // Check if user already has a personal project
    const existingProject = await Project.findOne({ 
      createdBy: userId, 
      isPersonal: true 
    });

    if (existingProject) {
      return existingProject;
    }

    // Get user info from Firebase Auth
    let userName = 'My';
    try {
      const userRecord = await admin.auth().getUser(userId);
      if (userRecord) {
        userName = userRecord.displayName || userRecord.email?.split('@')[0] || 'My';
      }
    } catch (error) {
      console.log(chalk.yellow('\nCould not fetch user details from Firebase, using default name'));
    }

    // Create new personal project
    const personalProject = new Project({
      name: `${userName}'s Personal`,
      description: 'Your personal project for tasks',
      userId: userId, // Set the userId field
      members: [userId],
      isPersonal: true
    });

    await personalProject.save();
    console.log(chalk.green(`\nCreated personal project: ${personalProject.name}`));
    return personalProject;
  } catch (error) {
    console.error(chalk.red('\nError creating personal project:'), error.message);
    throw error;
  }
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
        return true;
      } catch (initError) {
        console.error(chalk.red('❌ Error initializing Firebase Admin:'));
        console.error(initError);
        throw initError;
      }
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
const SESSION_FILE = `${SESSION_DIR}/session-${getDeviceId()}.json`;

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
    await ensureSessionDir();
    
    const session = {
      uid: user.uid,
      email: user.email.toLowerCase(), // Store email in lowercase for consistency
      displayName: user.displayName,
      deviceId: getDeviceId(),
      lastLogin: new Date().toISOString(),
      // Don't store the token in the session file
      // Instead, we'll verify the session with Firebase on each load
    };
    
    // Encrypt sensitive data before saving
    const encryptedSession = JSON.stringify(session);
    await fs.writeFile(SESSION_FILE, encryptedSession, { mode: 0o600 }); // Read/write for user only
    
    return true;
  } catch (error) {
    console.error('Error saving session:', error);
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
    if (session.deviceId !== getDeviceId()) {
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
      console.error('Error verifying session with Firebase:', error);
    }
    
    // If we get here, the session is invalid
    await clearSession();
    return null;
    
  } catch (error) {
    console.error('Error loading session:', error);
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
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID
};

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
  showWelcome();
  console.log(chalk.cyan('\n=== Create a New Account ===\n'));

  const emailPrompt = await prompt([
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
  ]);
  const email = emailPrompt.email;

  const checkPasswordRequirements = (input) => {
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
      isValid: hasLowercase && hasUppercase && hasNumber && hasSpecial && lengthOk
    };
  };

  const password = await getPasswordWithValidation(email);
  
  console.clear();
  console.log(chalk.cyan('=== Create a New Account ===\n'));
  console.log(`Email: ${email}\n`);
  console.log('Password: •'.repeat(8) + '\n');
  
  const displayNamePrompt = await prompt([
    {
      type: 'input',
      name: 'displayName',
      message: 'Enter your full name:',
      default: previousValues.displayName || '',
      validate: (input) => {
        if (input.trim().length > 0) return true;
        return 'Please enter your name';
      },
    },
  ]);
  const displayName = displayNamePrompt.displayName;

  if (Object.keys(previousValues).length > 0) {
    const { usePrevious } = await prompt([{
      type: 'confirm',
      name: 'usePrevious',
      message: 'Use previously entered values?',
      default: true
    }]);
    
    if (!usePrevious) {
      return handleRegister();
    }
  }
  
  const answers = { email, password, displayName };
  
  try {
    const userCredential = await createUserWithEmailAndPassword(auth, answers.email, answers.password);
    const user = userCredential.user;
    
    await updateProfile(user, {
      displayName: answers.displayName
    });

    if (isDbConnected) {
      await saveUser({
        uid: user.uid,
        email: user.email,
        displayName: answers.displayName,
      });
    }

    console.log(chalk.green('\n✅ Account created successfully!'));
    console.log(chalk.blue(`\nWelcome to Taskflow AI, ${answers.displayName}!`));
    
    await showDashboard(user.uid);
  } catch (error) {
    console.error(chalk.red('\n❌ Error creating account:'));
    console.error(chalk.red(error.message));
    
    if (error.code === 'auth/email-already-in-use') {
      console.log(chalk.yellow('\nThis email is already registered. Would you like to log in instead?'));
      const { loginInstead } = await prompt([{
        type: 'confirm',
        name: 'loginInstead',
        message: 'Log in instead?',
        default: true
      }]);
      
      if (loginInstead) {
        return handleLogin({ email });
      }
    }
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Try again', value: 'retry' },
          createSeparator(),
          { name: 'Back to main menu', value: 'back' },
        ],
        pageSize: 3,
      },
    ]);

    if (action === 'retry') {
      await handleRegister(values);
    }
  }
}

async function handleLogin(previousValues = {}) {
  showWelcome();
  
  try {
    const session = await loadSession();
    if (session) {
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
    
    console.log(chalk.green(`\n✅ Successfully logged in as ${user.email}`));
    
    await saveSession(user);
    
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
    
    // Calculate task counts
    let totalTasks = 0;
    let completedTasks = 0;
    let inProgressTasks = 0;
    let todoTasks = 0;
    
    for (const project of projects) {
      if (!project) continue;
      const tasks = await getTasksByProject(project._id);
      totalTasks += tasks.length;
      completedTasks += tasks.filter(t => t.status === 'completed').length;
      inProgressTasks += tasks.filter(t => t.status === 'in-progress').length;
      todoTasks += tasks.filter(t => !t.status || t.status === 'todo').length;
    }
    
    console.log(chalk.blue(`\nDashboard - ${user.displayName || user.email.split('@')[0]}`));
    console.log(chalk.gray('━'.repeat(60)));
    
    console.log(chalk.bold('Task Summary:'));
    console.log(`  • Total: ${chalk.bold(totalTasks)}`);
    console.log(`  • ${chalk.green('✓')} Completed: ${chalk.green(completedTasks)}`);
    console.log(`  • In Progress: ${chalk.blue(inProgressTasks)}`);
    console.log(`  • To Do: ${chalk.yellow(todoTasks)}`);
    
    const choices = [
      { name: 'View All Tasks', value: 'all-tasks' },
      { name: 'View Projects', value: 'projects' },
      createSeparator(),
      { name: 'Create New Task', value: 'create-task' },
      { name: 'Create New Project', value: 'create-project' },
      createSeparator(),
      { name: 'View Profile', value: 'profile' },
      { name: 'Logout', value: 'logout' }
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
      case 'projects':
        await showProjectList(userId);
        break;
      case 'create-task':
        console.log(chalk.yellow('\nTask creation coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showDashboard(userId);
        break;
      case 'create-project':
        await createProject(userId);
        break;
      case 'profile':
        await showProfile(user);
        break;
      case 'logout':
        await handleLogout();
        break;
      default:
        console.log(chalk.yellow('\nThis feature is coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
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
 * Fetches tasks from the web app's personal board
 * @param {string} userId - The user's Firebase UID
 * @returns {Promise<Array>} Array of tasks
 */
async function fetchWebAppTasks(userId) {
  try {
    // Get user's personal project
    const personalProject = await Project.findOne({ 
      userId,
      isPersonal: true 
    });

    if (!personalProject) {
      console.log(chalk.yellow('\nNo personal project found. Creating one...'));
      await createPersonalProject(userId);
      return [];
    }

    // Get all tasks from the personal project
    const tasks = await Task.find({ 
      projectId: personalProject._id,
      userId
    }).sort({ 
      dueDate: 1, // Sort by due date (oldest first)
      priority: -1, // Then by priority (high to low)
      createdAt: 1 // Then by creation date
    });

    return tasks;
  } catch (error) {
    console.error('Error fetching web app tasks:', error);
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
    // Get or create personal project
    const personalProject = await Project.findOne({ userId, isPersonal: true }) || 
                           await createPersonalProject(userId);
    
    if (!personalProject) {
      throw new Error('Could not find or create a personal project');
    }
    
    console.log(chalk.blue('\nCreate New Task'));
    console.log(chalk.gray('━'.repeat(40)));
    
    // Get task details from user
    const taskDetails = await prompt([
      {
        type: 'input',
        name: 'title',
        message: 'Task title:',
        validate: input => input.trim() ? true : 'Title is required'
      },
      {
        type: 'input',
        name: 'description',
        message: 'Description (optional):',
        default: ''
      },
      {
        type: 'list',
        name: 'status',
        message: 'Status:',
        choices: [
          { name: 'To Do', value: 'todo' },
          { name: 'In Progress', value: 'in-progress' },
          { name: 'Completed', value: 'completed' }
        ],
        default: 'todo'
      },
      {
        type: 'list',
        name: 'priority',
        message: 'Priority:',
        choices: [
          { name: 'High', value: 'high' },
          { name: 'Medium', value: 'medium' },
          { name: 'Low', value: 'low' }
        ],
        default: 'medium'
      },
      {
        type: 'input',
        name: 'dueDate',
        message: 'Due date (YYYY-MM-DD, optional):',
        default: '',
        validate: (input) => {
          if (!input) return true;
          return /^\d{4}-\d{2}-\d{2}$/.test(input) || 'Please use YYYY-MM-DD format';
        }
      }
    ]);
    
    // Create the task
    const newTask = new Task({
      title: taskDetails.title.trim(),
      description: taskDetails.description.trim(),
      status: taskDetails.status,
      priority: taskDetails.priority,
      dueDate: taskDetails.dueDate || undefined,
      projectId: personalProject._id,
      userId: userId,
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    await newTask.save();
    
    console.log(chalk.green('\n✓ Task created successfully!'));
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Show the created task
    const project = await Project.findById(newTask.projectId);
    await showTaskDetails(newTask, project, userId);
    
  } catch (error) {
    console.error(chalk.red('\nError creating task:'), error.message);
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
    // Fetch tasks from the web app's personal board
    const tasks = await fetchWebAppTasks(userId);
    
    if (tasks.length === 0) {
      console.log(chalk.yellow('\nNo tasks found in your personal board. Create a task to get started!'));
      await new Promise(resolve => setTimeout(resolve, 2000));
      return showDashboard(userId);
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

async function init() {
  try {
    showWelcome();
    
    try {
      const session = await loadSession();
      if (session) {
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

init();

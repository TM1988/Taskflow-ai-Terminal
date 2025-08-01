process.removeAllListeners('warning');

import 'dotenv/config';
import admin from 'firebase-admin';
import inquirer from 'inquirer';
import chalk from 'chalk';
import { createInterface } from 'readline';
import { stdin as input, stdout as output } from 'process';
import figlet from 'figlet';
import clear from 'clear';
import { 
  connectDB, 
  saveUser, 
  getUserById, 
  getTasksByUserId, 
  createTask as createTaskInDb, 
  updateTask, 
  deleteTask 
} from './utils/db.mjs';

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
(async () => {
  isDbConnected = await connectDB({ verbose: false });
  if (!isDbConnected) {
    console.error(chalk.red('Warning: Could not connect to MongoDB. Some features may not work.'));
  }
})();

const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_ADMIN_PROJECT_ID,
  private_key: process.env.FIREBASE_ADMIN_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_ADMIN_CLIENT_EMAIL,
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_ADMIN_CLIENT_EMAIL)}`,
  universe_domain: 'googleapis.com'
};

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log(chalk.green('✓ Firebase Admin initialized successfully'));
} catch (error) {
  console.error(chalk.red('Error initializing Firebase Admin:'));
  console.error(error);
  process.exit(1);
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
          console.log(chalk.yellow('\nGoodbye! 👋'));
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
  console.log(chalk.cyan('\n=== Login to Your Account ===\n'));

  let questions = [
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
      default: previousValues.password || '',
    },
  ];

  let answers;
  
  if (Object.keys(previousValues).length > 0) {
    const { usePrevious } = await prompt([{
      type: 'confirm',
      name: 'usePrevious',
      message: 'Use previously entered values?',
      default: true
    }]);
    
    if (!usePrevious) {
      questions = questions.map(q => ({
        ...q,
        default: undefined
      }));
    }
  }
  
  answers = await prompt(questions);
  
  const values = { ...answers };
  delete values.usePrevious;

  try {
    const userCredential = await signInWithEmailAndPassword(auth, values.email, values.password);
    const user = userCredential.user;
    
    console.log(chalk.green('\n✅ Login successful!'));
    
    if (isDbConnected) {
      await saveUser({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName || 'User',
      });
    }
    
    await showDashboard(user.uid);
  } catch (error) {
    console.error(chalk.red('\n❌ Login failed:'));
    console.error(chalk.red(error.message.includes('auth/') ? 'Invalid email or password' : error.message));
    
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
      await handleLogin(values);
    }
  }
}

async function showDashboard(userId) {
  try {
    let user;
    
    if (isDbConnected) {
      user = await getUserById(userId);
    }
    
    if (!user) {
      const userRecord = await admin.auth().getUser(userId);
      user = {
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName || 'User',
        createdAt: userRecord.metadata.creationTime || new Date(),
        updatedAt: userRecord.metadata.lastSignInTime || new Date()
      };
      
      if (isDbConnected) {
        await saveUser(user);
      }
    }
    
    showWelcome();
    console.log(chalk.green(`\nWelcome back, ${user.displayName || 'User'}!\n`));
    
    const { action } = await prompt([
      {
        type: 'list',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'View Tasks', value: 'tasks' },
          { name: 'Create New Task', value: 'create' },
          { name: 'View Profile', value: 'profile' },
          createSeparator(),
          { name: 'Logout', value: 'logout' },
        ],
        pageSize: 5,
      },
    ]);
    
    switch (action) {
      case 'logout':
        console.log(chalk.yellow('\nLogging out...'));
        await new Promise(resolve => setTimeout(resolve, 1000));
        await showMainMenu();
        break;
      case 'profile':
        await showProfile(user);
        break;
      case 'tasks':
        await showTasks(userId);
        break;
      case 'create':
        await createTask(userId);
        break;
      default:
        console.log(chalk.yellow('\nThis feature is coming soon!'));
        await new Promise(resolve => setTimeout(resolve, 1500));
        await showDashboard(userId);
    }
  } catch (error) {
    console.error(chalk.red('\n❌ Error loading dashboard:'));
    console.error(chalk.red(error.message));
    await new Promise(resolve => setTimeout(resolve, 2000));
    await showMainMenu();
  }
}

async function showTasks(userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Your Tasks ===\n'));
  
  try {
    const tasks = await getTasksByUserId(userId);
    
    if (tasks.length === 0) {
      console.log(chalk.yellow('No tasks found. Create your first task!'));
      
      const { action } = await prompt([
        {
          type: 'list',
          name: 'action',
          message: 'What would you like to do?',
          choices: [
            { name: 'Create New Task', value: 'create' },
            createSeparator(),
            { name: 'Back to Dashboard', value: 'back' }
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
    
    const taskChoices = tasks.map((task, index) => ({
      name: `[${task.status === 'completed' ? '✓' : ' '}] ${index + 1}. ${task.title} ${task.dueDate ? `(Due: ${new Date(task.dueDate).toLocaleDateString()})` : ''}${task.priority !== 'medium' ? ` [${task.priority}]` : ''}`,
      value: task._id.toString(),
      short: task.title,
      task: task
    }));
    
    const { selectedTaskId } = await prompt([
      {
        type: 'list',
        name: 'selectedTaskId',
        message: 'Your Tasks:',
        choices: [
          ...taskChoices,
          createSeparator(),
          { name: 'Create New Task', value: 'create' },
          { name: 'Back to Dashboard', value: 'back' }
        ],
        pageSize: 15,
        loop: false
      }
    ]);
    
    if (selectedTaskId === 'create') {
      await createTask(userId);
    } else if (selectedTaskId === 'back') {
      await showDashboard(userId);
      return;
    } else {
      const selectedTask = tasks.find(task => task._id.toString() === selectedTaskId);
      await showTaskDetails(selectedTask, userId);
    }
    
    await showTasks(userId);
    await showTasks(userId);
    
  } catch (error) {
    console.error(chalk.red('\n❌ Error loading tasks:'));
    console.error(chalk.red(error.message));
    await showDashboard(userId);
  }
}

async function showTaskDetails(task, userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Task Details ===\n'));
  
  console.log(chalk.bold('Title:'), task.title);
  if (task.description) console.log(chalk.bold('Description:'), task.description);
  if (task.dueDate) console.log(chalk.bold('Due Date:'), new Date(task.dueDate).toLocaleDateString());
  console.log(chalk.bold('Priority:'), task.priority);
  console.log(chalk.bold('Status:'), task.status === 'completed' ? '✅ Completed' : '⏳ Pending');
  
  const { action } = await prompt([
    {
      type: 'list',
      name: 'action',
      message: '\nWhat would you like to do?',
      choices: [
        { name: task.status === 'completed' ? 'Mark as Not Complete' : 'Mark as Complete', value: 'toggleComplete' },
        { name: 'Edit Task', value: 'edit' },
        { name: 'Delete Task', value: 'delete' },
        createSeparator(),
        { name: 'Back to Tasks', value: 'back' }
      ]
    }
  ]);
  
  switch (action) {
    case 'toggleComplete':
      const newStatus = task.status === 'completed' ? 'todo' : 'completed';
      await updateTask(task._id, { status: newStatus });
      console.log(chalk.green(`\nTask marked as ${newStatus === 'completed' ? 'completed' : 'not complete'}!`));
      await showTaskDetails({ ...task, status: newStatus }, userId);
      break;
      
    case 'edit':
      await editTask(task, userId);
      break;
      
    case 'delete':
      const { confirm } = await prompt([
        {
          type: 'confirm',
          name: 'confirm',
          message: 'Are you sure you want to delete this task?',
          default: false
        }
      ]);
      
      if (confirm) {
        await deleteTask(task._id);
        console.log(chalk.green('\nTask deleted successfully!'));
        await showTasks(userId);
        return;
      } else {
        await showTaskDetails(task, userId);
      }
      break;
      
    case 'back':
      await showTasks(userId);
      break;
  }
}

async function editTask(task, userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Edit Task ===\n'));
  
  const { title, description, dueDate, priority } = await prompt([
    {
      type: 'input',
      name: 'title',
      message: 'Task title:',
      default: task.title,
      validate: input => input.trim() ? true : 'Title is required',
    },
    {
      type: 'input',
      name: 'description',
      message: 'Description (optional):',
      default: task.description || ''
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
          : 'Please enter a valid date in YYYY-MM-DD format';
      },
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
      default: task.priority || 'medium'
    }
  ]);
  
  const updates = {
    title,
    description: description || undefined,
    priority,
    updatedAt: new Date()
  };
  
  if (dueDate) {
    updates.dueDate = new Date(dueDate);
  } else {
    updates.dueDate = undefined;
  }
  
  await updateTask(task._id, updates);
  console.log(chalk.green('\nTask updated successfully!'));
  await showTaskDetails({ ...task, ...updates }, userId);
}

async function createTask(userId) {
  showWelcome();
  console.log(chalk.cyan('\n=== Create New Task ===\n'));
  
  const { title, description, dueDate, priority } = await prompt([
    {
      type: 'input',
      name: 'title',
      message: 'Task title:',
      validate: input => input.trim() ? true : 'Title is required',
    },
    {
      type: 'input',
      name: 'description',
      message: 'Description (optional):',
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
    }
  ]);
  
  const newTask = {
    userId,
    title,
    description: description || undefined,
    priority,
    status: 'todo',
    createdAt: new Date(),
    updatedAt: new Date()
  };
  
  if (dueDate) {
    newTask.dueDate = new Date(dueDate);
  }
  
  try {
    await createTaskInDb(newTask);
    console.log(chalk.green('\n✅ Task created successfully!'));
    
    const { another } = await prompt([{
      type: 'confirm',
      name: 'another',
      message: 'Create another task?',
      default: false,
    }]);
    
    if (another) {
      await createTask(userId);
    } else {
      await showTasks(userId);
    }
  } catch (error) {
    console.error(chalk.red('\n❌ Error creating task:'));
    console.error(chalk.red(error.message));
  }  
  await showTasks(userId);
}

async function showProfile(user) {
  showWelcome();
  
  console.log(chalk.cyan('=== Your Profile ===\n'));
  console.log(chalk.yellow('User Information:'));
  console.log(`👤 Name: ${user.displayName || 'Not set'}`);
  console.log(`📧 Email: ${user.email || 'Not set'}`);
  console.log(`🆔 User ID: ${user.uid}`);
  
  const memberSince = user.createdAt 
    ? new Date(user.createdAt).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    : 'Unknown';
  
  console.log(`📅 Member since: ${memberSince}`);
  
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
    await showMainMenu();
  } catch (error) {
    console.error(chalk.red('An unexpected error occurred:'));
    console.error(error);
    process.exit(1);
  }
}

init();

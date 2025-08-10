// Basic CLI Authentication Page
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function validateEmail(email) {
  // Simple email regex
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

function validatePassword(password) {
  // Minimum 6 characters
  return password.length >= 6;
}

console.log('=== Taskflow AI CLI Authentication ===');

rl.question('Email: ', (email) => {
  if (!validateEmail(email)) {
    console.log('Invalid email format.');
    rl.close();
    return;
  }
  rl.question('Password: ', (password) => {
    if (!validatePassword(password)) {
      console.log('Password must be at least 6 characters.');
      rl.close();
      return;
    }
    // Simulate authentication
    console.log('Authentication successful!');
    rl.close();
  });
});

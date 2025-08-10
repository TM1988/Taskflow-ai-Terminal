import React, { useState } from 'react';
import { render, Box, Text, useInput } from 'ink';
import { auth } from './firebase.js';
import { signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth';

const AuthPage = () => {
  const [mode, setMode] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [step, setStep] = useState('email');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  useInput((input, key) => {
    if (loading) return;
    if (key.return) {
      if (step === 'email') {
        setStep('password');
      } else if (step === 'password') {
        setLoading(true);
        if (mode === 'login') {
          signInWithEmailAndPassword(auth, email.trim(), password)
            .then(() => setMessage('Login successful!'))
            .catch(e => setMessage('Login failed: ' + e.message))
            .finally(() => setLoading(false));
        } else {
          createUserWithEmailAndPassword(auth, email.trim(), password)
            .then(() => setMessage('Registration successful!'))
            .catch(e => setMessage('Registration failed: ' + e.message))
            .finally(() => setLoading(false));
        }
      }
    } else if (input === 'r' && step === 'email') {
      setMode('register');
      setMessage('Switched to register mode.');
      setEmail('');
      setPassword('');
      setStep('email');
    } else if (input === 'l' && step === 'email') {
      setMode('login');
      setMessage('Switched to login mode.');
      setEmail('');
      setPassword('');
      setStep('email');
    } else {
      if (step === 'email') setEmail(email + input);
      if (step === 'password') setPassword(password + input);
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1 },
    React.createElement(Text, { color: 'cyan' }, '=== Taskflow AI Terminal Auth ==='),
    React.createElement(Text, null, `Mode: ${mode === 'login' ? 'Login' : 'Register'} (press 'r' for register, 'l' for login)`),
    React.createElement(Text, null, step === 'email' ? `Email: ${email}` : `Password: ${'*'.repeat(password.length)}`),
    loading
      ? React.createElement(Text, { color: 'yellow' }, 'Authenticating...')
      : React.createElement(Text, { color: 'yellow' }, message)
  );
};

render(React.createElement(AuthPage));

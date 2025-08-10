# Taskflow AI - Terminal Version

A command-line interface for Taskflow AI that syncs with your web app's personal task board.

## Features

- View all your tasks in a beautiful terminal interface
- Create new tasks directly from the command line
- Sync with your Taskflow AI web app account
- Works on macOS, Windows, and Linux

## Prerequisites

- Node.js 16 or higher
- npm or yarn
- A Taskflow AI account

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/taskflow-ai-terminal.git
   cd taskflow-ai-terminal
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy the example environment file and update with your credentials:
   ```bash
   cp .env.example .env
   ```

4. Edit the `.env` file and add your Firebase and MongoDB credentials.

## Configuration

You'll need to set up the following environment variables in your `.env` file:

- `FIREBASE_*` - Your Firebase configuration
- `FIREBASE_ADMIN_CONFIG_JSON` - Your Firebase Admin SDK service account key (as a JSON string)
- `MONGODB_URI` - Your MongoDB connection string

## Usage

1. Start the application:
   ```bash
   npm start
   ```

2. Log in with your Taskflow AI account email and password

3. Use the menu to view and manage your tasks

## Testing the Database Connection

To verify that your database connection is working correctly, you can run the test script:

```bash
# Set a test user ID (replace with an actual user ID from your Firebase Authentication)
export TEST_USER_ID="your-test-user-id"

# Run the test script
node test-db-connection.mjs
```

This will attempt to connect to the database and list the available collections.

## Available Commands

- `View All Tasks` - Show all your tasks in a Kanban-style board
- `Create New Task` - Add a new task to your personal board
- `View Profile` - View your profile information
- `Logout` - Sign out of your account
- `Exit` - Close the application

## Development

To run in development mode with file watching:

```bash
npm run dev
```

## Building for Production

To create a production build:

```bash
npm run build
```

## License

MIT

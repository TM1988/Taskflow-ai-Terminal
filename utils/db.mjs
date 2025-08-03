import mongoose from 'mongoose';

const connectDB = async (options = { verbose: false }) => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    
    if (options.verbose) {
      console.log('MongoDB connected successfully');
    }
    return true;
  } catch (error) {
    if (options.verbose) {
      console.error('MongoDB connection error:', error);
    }
    return false;
  }
};

const userSchema = new mongoose.Schema({
  uid: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  displayName: { type: String, required: true },
  photoURL: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const workspaceSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  name: { type: String, required: true },
  isPersonal: { type: Boolean, default: false },
  members: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const projectSchema = new mongoose.Schema({
  workspaceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Workspace', required: true },
  name: { type: String, required: true },
  description: { type: String },
  color: { type: String, default: '#3b82f6' },
  isPersonal: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const taskSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  workspaceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Workspace', required: true },
  projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
  title: { type: String, required: true },
  description: { type: String },
  dueDate: { type: Date },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['todo', 'in-progress', 'completed'],
    default: 'todo'
  },
  labels: [{ type: String }],
  assignee: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

taskSchema.index({ userId: 1, projectId: 1 });
projectSchema.index({ workspaceId: 1 });
workspaceSchema.index({ userId: 1 });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Workspace = mongoose.models.Workspace || mongoose.model('Workspace', workspaceSchema);
const Project = mongoose.models.Project || mongoose.model('Project', projectSchema);
const Task = mongoose.models.Task || mongoose.model('Task', taskSchema);

const saveUser = async (userData) => {
  try {
    const { uid, email, displayName, photoURL } = userData;
    
    const user = await User.findOneAndUpdate(
      { uid },
      {
        email,
        displayName,
        photoURL: photoURL || null,
        updatedAt: new Date(),
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    
    return user;
  } catch (error) {
    console.error('Error saving user to MongoDB:', error);
    throw error;
  }
};

const getUserById = async (uid) => {
  try {
    return await User.findOne({ uid });
  } catch (error) {
    console.error('Error getting user from MongoDB:', error);
    throw error;
  }
};

const getWorkspacesByUser = async (userId) => {
  try {
    return await Workspace.find({ 
      $or: [
        { userId },
        { members: userId }
      ]
    }).sort({ isPersonal: -1, name: 1 });
  } catch (error) {
    console.error('Error getting workspaces:', error);
    throw error;
  }
};

const getOrCreatePersonalWorkspace = async (userId) => {
  try {
    let workspace = await Workspace.findOne({ userId, isPersonal: true });
    
    if (!workspace) {
      workspace = new Workspace({
        userId,
        name: 'Personal',
        isPersonal: true,
        members: [userId]
      });
      await workspace.save();
    }
    
    return workspace;
  } catch (error) {
    console.error('Error getting personal workspace:', error);
    throw error;
  }
};

const getProjectsByWorkspace = async (workspaceId) => {
  try {
    return await Project.find({ workspaceId }).sort({ isPersonal: -1, name: 1 });
  } catch (error) {
    console.error('Error getting projects:', error);
    throw error;
  }
};

const getOrCreatePersonalProject = async (workspaceId, userId) => {
  try {
    let project = await Project.findOne({ workspaceId, isPersonal: true });
    
    if (!project) {
      project = new Project({
        workspaceId,
        name: 'Personal',
        isPersonal: true
      });
      await project.save();
    }
    
    return project;
  } catch (error) {
    console.error('Error getting personal project:', error);
    throw error;
  }
};

const getTasksByProject = async (projectId, userId) => {
  try {
    return await Task.find({ projectId, userId }).sort({ 
      status: 1, 
      dueDate: 1,
      priority: -1,
      createdAt: 1 
    });
  } catch (error) {
    console.error('Error getting tasks:', error);
    throw error;
  }
};

/**
 * Get tasks for a user, optionally filtered by workspace
 * @param {string} userId - The user's ID
 * @param {string} [workspaceId] - Optional workspace ID to filter tasks
 * @returns {Promise<Array>} Array of tasks
 */
const getTasksByUser = async (userId, workspaceId = null) => {
  try {
    const query = { userId };
    
    if (workspaceId) {
      query.workspaceId = workspaceId;
    }
    
    return await Task.find(query)
      .populate('projectId', 'name')
      .sort({ 
        status: 1,
        dueDate: 1,
        priority: -1,
        createdAt: 1 
      });
  } catch (error) {
    console.error('Error getting user tasks:', error);
    throw error;
  }
};

const getTasksByUserId = async (userId) => {
  try {
    return await Task.find({ userId }).sort({ createdAt: -1 });
  } catch (error) {
    console.error('Error getting tasks from MongoDB:', error);
    throw error;
  }
};

const createTaskInDb = async (taskData) => {
  try {
    const task = new Task(taskData);
    return await task.save();
  } catch (error) {
    console.error('Error creating task in MongoDB:', error);
    throw error;
  }
};

const updateTask = async (taskId, updates) => {
  try {
    return await Task.findByIdAndUpdate(
      taskId,
      { ...updates, updatedAt: new Date() },
      { new: true }
    );
  } catch (error) {
    console.error('Error updating task in MongoDB:', error);
    throw error;
  }
};

const deleteTask = async (taskId) => {
  try {
    return await Task.findByIdAndDelete(taskId);
  } catch (error) {
    console.error('Error deleting task from MongoDB:', error);
    throw error;
  }
};

export {
  connectDB,
  saveUser,
  getUserById,
  getWorkspacesByUser,
  getOrCreatePersonalWorkspace,
  getProjectsByWorkspace,
  getOrCreatePersonalProject,
  getTasksByProject,
  getTasksByUser,
  getTasksByUserId,
  createTaskInDb as createTask,
  updateTask,
  deleteTask,
  mongoose,
  User,
  Workspace,
  Project,
  Task
};

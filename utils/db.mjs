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

const taskSchema = new mongoose.Schema({
  userId: { type: String, required: true },
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
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
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
  getTasksByUserId,
  createTaskInDb as createTask,
  updateTask,
  deleteTask,
  mongoose
};

import { MongoClient } from 'mongodb';

async function checkTasks() {
  const client = new MongoClient('mongodb+srv://tanmarwah1337:HhYZlRrGIhfLb5rw@cluster0.yypzt.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0');
  
  try {
    await client.connect();
    console.log('✓ Connected to MongoDB');
    
    const db = client.db('myvercelappdb');
    const personalTasks = db.collection('personalTasks');
    
    // Find all tasks first to see structure
    console.log('\n--- All tasks in personalTasks collection ---');
    const allTasks = await personalTasks.find({}).toArray();
    console.log('Total tasks found:', allTasks.length);
    
    if (allTasks.length > 0) {
      console.log('Sample task structure:');
      console.log(JSON.stringify(allTasks[0], null, 2));
    }
    
    // Find tasks for your specific user ID
    console.log('\n--- Tasks for user uvFDwHpRKGRodszPahFdcwdZDYm2 ---');
    const userTasks = await personalTasks.find({ userId: 'uvFDwHpRKGRodszPahFdcwdZDYm2' }).toArray();
    console.log('User tasks found:', userTasks.length);
    
    if (userTasks.length > 0) {
      console.log('User tasks:');
      userTasks.forEach((task, i) => {
        console.log(`${i + 1}. ${task.title} (Status: ${task.status})`);
      });
    }
    
    // Also check different userId formats
    console.log('\n--- Checking different userId formats ---');
    const distinctUserIds = await personalTasks.distinct('userId');
    console.log('Distinct userId values in collection:');
    distinctUserIds.forEach(uid => console.log(`  - "${uid}"`));
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await client.close();
  }
}

checkTasks();

import { MongoClient } from 'mongodb';
import 'dotenv/config';

async function findYourTasks() {
  const mongoUri = process.env.MONGODB_URI;
  const client = new MongoClient(mongoUri);
  
  try {
    await client.connect();
    const db = client.db('myVercelAppDB');
    
    console.log('=== SEARCHING FOR YOUR TASKS ===');
    
    // Your user ID
    const yourUserId = 'uvFDwHpRKGRodszPahFdcwdZDYm2';
    console.log('Your user ID:', yourUserId);
    
    // Find tasks specifically for your user ID
    const yourTasks = await db.collection('personalTasks').find({ 
      userId: yourUserId 
    }).toArray();
    
    console.log('\n🔍 Tasks found for your user ID:', yourTasks.length);
    
    if (yourTasks.length > 0) {
      console.log('✅ YOUR TASKS:');
      yourTasks.forEach((task, i) => {
        console.log(`${i + 1}. "${task.title}"`);
        console.log(`   Status: ${task.status}`);
        console.log(`   Description: "${task.description}"`);
        console.log(`   Created: ${task.createdAt}`);
        console.log(`   Updated: ${task.updatedAt}`);
        console.log(`   Priority: ${task.priority}`);
        console.log(`   Column: ${task.columnId}`);
        console.log('');
      });
    } else {
      console.log('❌ No tasks found for your user ID');
      
      // Let's see all user IDs in the collection
      console.log('\n--- All user IDs in personalTasks collection ---');
      const allTasks = await db.collection('personalTasks').find({}).toArray();
      const userIds = [...new Set(allTasks.map(task => task.userId))];
      
      console.log('Distinct user IDs found:');
      userIds.forEach(uid => {
        console.log(`  - "${uid}"`);
        if (uid === yourUserId) {
          console.log('    ✅ This matches your user ID!');
        }
      });
      
      console.log('\nAll tasks:');
      allTasks.forEach((task, i) => {
        console.log(`${i + 1}. "${task.title}" (userId: "${task.userId}")`);
      });
    }
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await client.close();
  }
}

findYourTasks();

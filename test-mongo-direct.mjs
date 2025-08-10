import { MongoClient } from 'mongodb';
import 'dotenv/config';

async function testMongoDirectly() {
  const mongoUri = process.env.MONGODB_URI;
  console.log('MongoDB URI:', mongoUri ? 'Set (length: ' + mongoUri.length + ')' : 'Not set');
  
  if (!mongoUri) {
    console.error('MONGODB_URI not set!');
    return;
  }
  
  const client = new MongoClient(mongoUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  
  try {
    console.log('Connecting to MongoDB...');
    await client.connect();
    console.log('✓ Connected successfully');
    
    const db = client.db('myVercelAppDB'); // Match MongoDB Compass exactly
    console.log('✓ Connected to myVercelAppDB database');
    
    // Test database connection
    await db.command({ ping: 1 });
    console.log('✓ Database ping successful');
    
    // Check collections
    const collections = await db.listCollections().toArray();
    console.log('Available collections:');
    collections.forEach(col => console.log('  -', col.name));
    
    // If no personalTasks, let's check all collections for any task-like data
    if (collections.length === 0) {
      console.log('No collections found! This might be an empty database.');
    } else {
      console.log('\n--- Checking all collections for task data ---');
      for (const collection of collections) {
        console.log(`\nChecking collection: ${collection.name}`);
        const count = await db.collection(collection.name).countDocuments();
        console.log(`  Documents: ${count}`);
        
        if (count > 0) {
          const sample = await db.collection(collection.name).findOne();
          console.log('  Sample document:', JSON.stringify(sample, null, 2));
        }
      }
    }
    
    // Also try different database names that might contain tasks
    console.log('\n--- Trying other possible database names ---');
    const dbNames = ['Taskflow', 'taskflow', 'taskflow-ai', 'main', 'default'];
    
    for (const dbName of dbNames) {
      try {
        console.log(`\nTrying database: ${dbName}`);
        const testDb = client.db(dbName);
        const collections = await testDb.listCollections().toArray();
        if (collections.length > 0) {
          console.log(`  Found collections in ${dbName}:`, collections.map(c => c.name));
          
          // Check for personalTasks specifically
          if (collections.find(c => c.name === 'personalTasks')) {
            console.log(`  ✓ Found personalTasks in ${dbName}!`);
            const userTasks = await testDb.collection('personalTasks').find({ 
              userId: 'uvFDwHpRKGRodszPahFdcwdZDYm2' 
            }).toArray();
            console.log(`    Your tasks: ${userTasks.length}`);
            userTasks.forEach((task, i) => {
              console.log(`    ${i + 1}. "${task.title}" (status: ${task.status})`);
            });
          }
        } else {
          console.log(`  No collections in ${dbName}`);
        }
      } catch (error) {
        console.log(`  Error accessing ${dbName}: ${error.message}`);
      }
    }
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await client.close();
  }
}

testMongoDirectly();

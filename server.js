const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const app = express();
const admin = require('firebase-admin');
const axios = require('axios');
const pino = require('pino');

dotenv.config();
app.use(express.json());

const logger = pino({ level: process.env.NODE_ENV === 'production' ? 'error' : 'info' });


const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

try {
  console.log('Initializing Firebase');
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT.trim());
  console.log('Service account parsed:', Object.keys(serviceAccount));
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
  console.log('Firebase initialized successfully');
  logger.info('Firebase initialized');
} catch (error) {
  console.error('Firebase init error:', error.message, error.stack);
  logger.error({ event: 'firebase_init_failure', error: error.message, stack: error.stack });
  process.exit(1);
}

// Firebase Admin SDK
// const serviceAccount = require('./serviceAccountKey.json');
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount),
// });


// API 1: Register Employer (Creates Household)

app.get('/', (req, res) => {
  res.send('Welcome to HelperJet')
})

app.post('/api/register-employer', async (req, res) => {
  console.log('Handling POST /api/register-employer');
  logger.info("Calling Registration");
  const { phone_number, name } = req.body;

  if (!phone_number) return res.status(400).json({ error: 'Phone number required' });

  try {
    const existingUser = await pool.query(
      'SELECT phone_number FROM Employer WHERE phone_number = $1 ' +
      'UNION ' +
      'SELECT phone_number FROM Helper WHERE phone_number = $1',
      [phone_number]
    );
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Phone number already registered' });
    }

    await pool.query('BEGIN');
    const householdResult = await pool.query(
      'INSERT INTO Household (created_at) VALUES (NOW()) RETURNING household_id'
    );
    const household_id = householdResult.rows[0].household_id;

    const employerResult = await pool.query(
      'INSERT INTO Employer (household_id, phone_number, name, created_at) VALUES ($1, $2, $3, NOW()) RETURNING employer_id',
      [household_id, phone_number, name]
    );
    const employer_id = employerResult.rows[0].employer_id;

    const token = jwt.sign({ id: employer_id, type: 'employer', household_id }, JWT_SECRET, { expiresIn: '1h' });

    await pool.query('COMMIT');
    res.status(201).json({ employer_id, household_id, token });
  } catch (error) {
    await pool.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  }
});

// API 2: Add Employer (All Employers Are Admins)
app.post('/api/add-employer', authenticateToken, async (req, res) => {
  const { phone_number, name } = req.body;
  const { household_id, type } = req.user;

  if (type !== 'employer') return res.status(403).json({ error: 'Only employers can add employers' });
  if (!phone_number) return res.status(400).json({ error: 'Phone number required' });

  try {
    const existingUser = await pool.query(
      'SELECT * FROM Employer WHERE phone_number = $1 UNION SELECT * FROM Helper WHERE phone_number = $1',
      [phone_number]
    );
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Phone number already registered' });
    }

    const employerResult = await pool.query(
      'INSERT INTO Employer (household_id, phone_number, name, created_at) VALUES ($1, $2, $3, NOW()) RETURNING employer_id',
      [household_id, phone_number, name]
    );
    const employer_id = employerResult.rows[0].employer_id;

    res.status(201).json({ employer_id, household_id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/helpers', authenticateToken, async (req, res) => {
  const { household_id } = req.user;

  try {
    const result = await pool.query(
      'SELECT helper_id, name FROM Helper WHERE household_id = $1 ORDER BY helper_id',
      [household_id]
    );

    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// API 3: Add Helper (By Any Employer)
app.post('/api/add-helper', authenticateToken, async (req, res) => {
  const { phone_number, name } = req.body;
  const { household_id, type } = req.user;

  if (type !== 'employer') return res.status(403).json({ error: 'Only employers can add helpers' });
  if (!phone_number) return res.status(400).json({ error: 'Phone number required' });

  try {
    const existingUser = await pool.query(
      'SELECT phone_number FROM Employer WHERE phone_number = $1 UNION SELECT phone_number FROM Helper WHERE phone_number = $1',
      [phone_number]
    );
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'Phone number already registered' });
    }

    const helperResult = await pool.query(
      'INSERT INTO Helper (household_id, phone_number, name, created_at) VALUES ($1, $2, $3, NOW()) RETURNING helper_id',
      [household_id, phone_number, name]
    );
    const helper_id = helperResult.rows[0].helper_id;

    res.status(201).json({ helper_id, household_id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// API 4: Login (For Employer or Helper)
app.post('/api/login', async (req, res) => {
  const { phone_number } = req.body;

  if (!phone_number) return res.status(400).json({ error: 'Phone number required' });

  try {
    let userResult = await pool.query(
      'SELECT employer_id AS id, household_id, \'employer\' AS type FROM Employer WHERE phone_number = $1',
      [phone_number]
    );
    let user = userResult.rows[0];

    if (!user) {
      userResult = await pool.query(
        'SELECT helper_id AS id, household_id, \'helper\' AS type FROM Helper WHERE phone_number = $1',
        [phone_number]
      );
      user = userResult.rows[0];
    }

    if (!user) return res.status(401).json({ error: 'User not found' });

    const token = jwt.sign(
      { id: user.id, type: user.type, household_id: user.household_id },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ id: user.id, type: user.type, household_id: user.household_id, token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/helpers/device-token', authenticateToken, async (req, res) => {
  const { device_token } = req.body;
  const { id: helper_id } = req.user;
  try {
    await pool.query(
      'UPDATE Helper SET device_token = $1 WHERE helper_id = $2',
      [device_token, helper_id]
    );
    res.status(200).json({ message: 'Device token updated' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sops', authenticateToken, async (req, res) => {
  const { day_of_week, helper_id, tasks } = req.body;
  const { household_id, type } = req.user;

  // Validate employer role
  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can create SOPs' });
  }

  // Validate inputs
  if (!day_of_week || !tasks || !Array.isArray(tasks) || tasks.length === 0) {
    return res.status(400).json({ error: 'Day of week and at least one task required' });
  }

  // Validate day_of_week against enum
  const validDays = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  if (!validDays.includes(day_of_week)) {
    return res.status(400).json({ error: 'Invalid day of week' });
  }

  // Validate helper_id (if provided)
  if (helper_id) {
    const helperCheck = await pool.query(
      'SELECT helper_id FROM Helper WHERE helper_id = $1 AND household_id = $2',
      [helper_id, household_id]
    );
    if (helperCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid helper_id for this household' });
    }
  }

  try {
    const sopIds = [];
    const completionIds = [];

    for (const task of tasks) {
      const { task_title, task_description } = task;
      if (!task_title) {
        return res.status(400).json({ error: 'Task title required' });
      }

      // Insert into SOP
      const result = await pool.query(
        'INSERT INTO SOP (household_id, helper_id, task_title, task_description, day_of_week, created_at) ' +
        'VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING sop_id',
        [household_id, helper_id || null, task_title, task_description || null, day_of_week]
      );
      sopIds.push(result.rows[0].sop_id);

      // Insert into TaskCompletion
      const completionResult = await pool.query(
        'INSERT INTO TaskCompletion (household_id, sop_id, completion_date, status, created_at) ' +
        'VALUES ($1, $2, NOW()::date, $3, NOW()) RETURNING completion_id',
        [household_id, result.rows[0].sop_id, 'pending']
      );
      completionIds.push(completionResult.rows[0].completion_id);
    }

    res.status(201).json({ household_id, sop_ids: sopIds, completion_ids: completionIds });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/subscriptions', authenticateToken, async (req, res) => {
  const { platform, subscription_id: platform_subscription_id, receipt, household_id } = req.body;
  const { employer_id, type } = req.user;

  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can subscribe' });
  }

  if (!platform || !platform_subscription_id || !receipt || !household_id) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (!['ios', 'android'].includes(platform)) {
    return res.status(400).json({ error: 'Invalid platform' });
  }

  try {
    const householdCheck = await pool.query(
      'SELECT household_id FROM employer WHERE employer_id = $1 AND household_id = $2',
      [employer_id, household_id]
    );
    if (householdCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid household_id' });
    }

    let status, expiry_date;

    if (platform === 'ios') {
      const appleResponse = await axios.post(
        'https://buy.itunes.apple.com/verifyReceipt',
        { 'receipt-data': receipt, password: process.env.APPLE_SHARED_SECRET },
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (appleResponse.data.status !== 0) {
        return res.status(400).json({ error: 'Invalid Apple receipt' });
      }

      const latestReceipt = appleResponse.data.latest_receipt_info[0];
      if (latestReceipt.product_id !== 'helperjet_premium_household_monthly') {
        return res.status(400).json({ error: 'Invalid product ID' });
      }

      expiry_date = new Date(parseInt(latestReceipt.expires_date_ms));
      status = latestReceipt.is_in_intro_offer_period === 'true' ? 'trial' : 'active';
    } else if (platform === 'android') {
      const accessToken = await getGoogleAccessToken();
      const googleResponse = await axios.get(
        `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/com.helperjet/purchases/subscriptions/${platform_subscription_id}/tokens/${receipt}`,
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      if (!googleResponse.data.startTimeMillis) {
        return res.status(400).json({ error: 'Invalid Google receipt' });
      }

      expiry_date = new Date(parseInt(googleResponse.data.expiryTimeMillis));
      status = googleResponse.data.paymentState === 2 ? 'trial' : 'active';
    }

    const existingSub = await pool.query(
      'SELECT subscription_id FROM subscriptions WHERE household_id = $1 AND status IN ($2, $3)',
      [household_id, 'trial', 'active']
    );

    if (existingSub.rows.length > 0) {
      return res.status(400).json({ error: 'Household already has an active subscription' });
    }

    const result = await pool.query(
      'INSERT INTO subscriptions (household_id, employer_id, platform, platform_subscription_id, status, expiry_date, created_at, updated_at) ' +
      'VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) RETURNING *',
      [household_id, employer_id, platform, platform_subscription_id, status, expiry_date]
    );

    const helperResult = await pool.query(
      'SELECT device_token FROM employer WHERE employer_id = $1',
      [employer_id]
    );
    const deviceToken = helperResult.rows[0]?.device_token;

    if (deviceToken) {
      const message = {
        notification: {
          title: 'Subscription Started',
          body: `Your ${status === 'trial' ? '7-day trial' : 'subscription'} has started!`,
        },
        token: deviceToken,
      };
      try {
        await admin.messaging().send(message);
        console.log(`Notification sent to employer ${employer_id}`);
      } catch (fcmError) {
        console.error('FCM error:', fcmError);
      }
    }

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error processing subscription:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/subscriptions/status', authenticateToken, async (req, res) => {
  const { household_id } = req.user;

  try {
    const result = await pool.query(
      'SELECT status, expiry_date FROM subscriptions WHERE household_id = $1 AND status IN ($2, $3)',
      [household_id, 'trial', 'active']
    );

    if (result.rows.length === 0) {
      return res.json({ status: 'none' });
    }

    const { status, expiry_date } = result.rows[0];
    const now = new Date();

    if (expiry_date < now && status !== 'expired') {
      await pool.query(
        'UPDATE subscriptions SET status = $1, updated_at = NOW() WHERE household_id = $2',
        ['expired', household_id]
      );
      return res.json({ status: 'expired' });
    }

    res.json({ status, expiry_date });
  } catch (error) {
    console.error('Error checking subscription status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function getGoogleAccessToken() {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  const { private_key: privateKey, client_email: clientEmail } = serviceAccount;
  const jwtClient = new google.auth.JWT(
    clientEmail,
    null,
    privateKey,
    ['https://www.googleapis.com/auth/androidpublisher']
  );
  const tokens = await jwtClient.authorize();
  return tokens.access_token;
}



app.put('/api/sops/:id', authenticateToken, async (req, res) => {
  console.log("Updating SOPS");
  const { id } = req.params;
  const { task_title, task_description, day_of_week, helper_id } = req.body;
  const { household_id, type: userType } = req.user;

  // Validate employer role
  if (userType !== 'employer') {
    return res.status(403).json({ error: 'Only employers can edit SOPs' });
  }

  // Validate required fields
  if (!task_title) {
    return res.status(400).json({ error: 'SOP title required' });
  }

  // Validate day_of_week
  if (!['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].includes(day_of_week)) {
    return res.status(400).json({ error: 'Invalid day of week' });
  }

  try {
    const result = await pool.query(
      'UPDATE sop SET task_title = $1, task_description = $2, day_of_week = $3, helper_id= $6, updated_at = NOW() ' +
      'WHERE sop_id = $4 AND household_id = $5 RETURNING *',
      [task_title, task_description || null, day_of_week, id, household_id, helper_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'SOP not found or not yours' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating SOP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.delete('/api/sops/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const householdId = req.user.household_id;

  try {
    const result = await pool.query(
      'DELETE FROM sop WHERE sop_id = $1 AND household_id = $2 RETURNING *',
      [id, householdId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'SOP not found or unauthorized' });
    }

    res.status(200).json({ message: 'SOP deleted successfully' });
  } catch (err) {
    console.error('Error deleting SOP:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
  console.log("Calling insert task api");
  const { due_date, helper_id, priority, tasks } = req.body;
  const { household_id, type } = req.user;

  // Validate employer role
  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can create tasks' });
  }

  // Validate inputs
  if (!due_date || !tasks || !Array.isArray(tasks) || tasks.length === 0) {
    return res.status(400).json({ error: 'Due date and at least one task required' });
  }

  // Validate due_date (must be today or future)
  const dueDate = new Date(due_date);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  if (isNaN(dueDate) || dueDate < today) {
    return res.status(400).json({ error: 'Invalid or past due date' });
  }

  // Validate priority (if provided)
  const validPriorities = ['low', 'medium', 'high'];
  if (priority && !validPriorities.includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority' });
  }

  // Validate helper_id (if provided)
  if (helper_id) {
    const helperCheck = await pool.query(
      'SELECT helper_id FROM Helper WHERE helper_id = $1 AND household_id = $2',
      [helper_id, household_id]
    );
    if (helperCheck.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid helper_id for this household' });
    }
  }

  try {
    const taskIds = [];
    const completionIds = [];
    const taskSummaries = []; // Store task details for batch notification
  
    for (const task of tasks) {
      const { task_title, task_description } = task;
      if (!task_title) {
        return res.status(400).json({ error: 'Task title required' });
      }
  
      // Insert into Task
      const result = await pool.query(
        'INSERT INTO Task (household_id, helper_id, task_title, task_description, due_date, priority, created_at) ' +
        'VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING task_id',
        [household_id, helper_id || null, task_title, task_description || null, due_date, priority || 'medium']
      );
      taskIds.push(result.rows[0].task_id);
      taskSummaries.push({ task_id: result.rows[0].task_id, task_title });
  
      // Insert into TaskCompletion
      const completionResult = await pool.query(
        'INSERT INTO TaskCompletion (household_id, task_id, completion_date, status, created_at) ' +
        'VALUES ($1, $2, $3, $4, NOW()) RETURNING completion_id',
        [household_id, result.rows[0].task_id, due_date, 'pending']
      );
      completionIds.push(completionResult.rows[0].completion_id);
    }
  
    // Send FCM notification (batch or single)
    if (helper_id) {
      const helperResult = await pool.query(
        'SELECT device_token FROM Helper WHERE helper_id = $1',
        [helper_id]
      );
      const deviceToken = helperResult.rows[0]?.device_token;
  
      if (deviceToken) {
        let message;
        if (tasks.length > 1) {
          // Batch notification
          const taskTitles = taskSummaries.map(t => t.task_title).join(', ');
          message = {
            notification: {
              title: `${tasks.length} New Tasks Assigned`,
              body: `Tasks: ${taskTitles} (Due: ${due_date})`,
            },
            data: {
              task_ids: JSON.stringify(taskSummaries.map(t => t.task_id)),
              type: 'task_batch_assigned',
            },
            token: deviceToken,
          };
        } else {
          // Single notification
          message = {
            notification: {
              title: 'New Task Assigned',
              body: `Task: ${taskSummaries[0].task_title} (Due: ${due_date})`,
            },
            data: {
              task_id: taskSummaries[0].task_id.toString(),
              type: 'task_assigned',
            },
            token: deviceToken,
          };
        }
  
        try {
          await admin.messaging().send(message);
          logger.info({
            event: tasks.length > 1 ? 'fcm_batch_success' : 'fcm_success',
            task_ids: taskSummaries.map(t => t.task_id),
            helper_id
          });
          // Insert notifications for each task on success
          for (const { task_id, task_title } of taskSummaries) {
            await pool.query(
              'INSERT INTO notifications (helper_id, task_id, message, status, created_at) ' +
              'VALUES ($1, $2, $3, $4, NOW())',
              [helper_id, task_id, `New task: ${task_title} (Due: ${due_date})`, 'unread']
            );
          }
        } catch (fcmError) {
          logger.error({
            event: tasks.length > 1 ? 'fcm_batch_failure' : 'fcm_failure',
            task_ids: taskSummaries.map(t => t.task_id),
            helper_id,
            error_code: fcmError.code,
            error_message: fcmError.message
          });
          if (fcmError.code === 'messaging/invalid-registration-token' || 
              fcmError.code === 'messaging/registration-token-not-registered') {
            try {
              await pool.query(
                'UPDATE Helper SET device_token = NULL WHERE helper_id = $1',
                [helper_id]
              );
              logger.info({ event: 'token_cleanup_success', helper_id });
            } catch (dbError) {
              logger.error({
                event: 'token_cleanup_failure',
                helper_id,
                error_message: dbError.message
              });
            }
          }
        }
      }
    }
  
    res.status(201).json({ household_id, task_ids: taskIds, completion_ids: completionIds });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
})

// GET /api/tasks - Fetch tasks for a given date
app.get('/api/tasks', authenticateToken, async (req, res) => {

  const { date } = req.query; // e.g., '2025-05-07'
  const { household_id, helper_id: user_helper_id, type } = req.user;

  // Default to today if no date provided
  const queryDate = date || new Date().toISOString().split('T')[0];

  // Validate date
  const parsedDate = new Date(queryDate);
  if (isNaN(parsedDate)) {
    return res.status(400).json({ error: 'Invalid date format' });
  }

  try {
    // Fetch SOPs and ad-hoc tasks
    const result = await pool.query(
      `
SELECT * FROM (
  -- SOP records
  SELECT 
    'sop' AS type, 
    s.sop_id AS id, 
    s.task_title, 
    s.task_description, 
    s.day_of_week, 
    COALESCE(tc.status, 'pending') AS status, 
    tc.completion_id, 
    s.helper_id, 
    NULL AS priority,
    NULL AS due_date
  FROM sop s
  LEFT JOIN taskcompletion tc 
    ON s.sop_id = tc.sop_id 
       AND tc.completion_date = $2 ::date
  WHERE 
    s.household_id = $1
    AND s.day_of_week = TO_CHAR($2 ::date, 'FMDay')::day_of_week

  UNION

  -- Task records
  SELECT 
    'task' AS type, 
    t.task_id AS id, 
    t.task_title, 
    t.task_description, 
    TO_CHAR(t.due_date, 'FMDay')::day_of_week AS day_of_week,
    COALESCE(tc.status, 'pending') AS status, 
    tc.completion_id, 
    t.helper_id, 
    t.priority,
    NULL AS due_date
  FROM task t
  LEFT JOIN taskcompletion tc 
    ON t.task_id = tc.task_id 
       AND tc.completion_date = $2 ::date
  WHERE 
    t.household_id = $1 
    AND t.due_date = $2::date
) AS combined
ORDER BY 
  CASE priority
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 3
    ELSE 4
  END, 
  task_title;



      `,
      [household_id, queryDate]
    );

    // Filter by helper_id for helpers
    const tasks = type === 'helper' 
      ? result.rows.filter(task => !task.helper_id || task.helper_id === user_helper_id)
      : result.rows;

    res.status(200).json({ household_id, date: queryDate, tasks });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const householdId = req.user.household_id;

  try {
    const result = await pool.query(
      'DELETE FROM task WHERE task_id = $1 AND household_id = $2 RETURNING *',
      [id, householdId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Task not found or unauthorized' });
    }

    res.status(200).json({ message: 'Task deleted successfully' });
  } catch (err) {
    console.error('Error deleting task:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/helper-tasks', authenticateToken, async (req, res) => {
  const { date } = req.query;
  const { household_id, id: user_helper_id, type } = req.user;

  // Only helpers can access this endpoint
  if (type !== 'helper') {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const queryDate = date || new Date().toISOString().split('T')[0];
  const parsedDate = new Date(queryDate);
  console.log(parsedDate);
  if (isNaN(parsedDate)) {
    return res.status(400).json({ error: 'Invalid date format' });
  }

  try {
    const query = `
       SELECT 
        type, 
        id, 
        task_title, 
        task_description, 
        day_of_week, 
        status, 
        completion_id, 
        helper_id, 
        helper_name, 
        priority, 
        due_date 
      FROM (
        -- SOP records
        SELECT 
          'sop' AS type, 
          s.sop_id AS id, 
          s.task_title, 
          s.task_description, 
          s.day_of_week, 
          COALESCE(tc.status, 'pending') AS status, 
          tc.completion_id, 
          s.helper_id, 
          h.name AS helper_name,
          NULL AS priority,
          NULL::date AS due_date
        FROM sop s
        LEFT JOIN taskcompletion tc 
          ON s.sop_id = tc.sop_id
        LEFT JOIN Helper h 
          ON s.helper_id = h.helper_id
        WHERE 
          s.household_id = $1
          AND s.day_of_week = TO_CHAR($2::date, 'FMDay')::day_of_week
          AND (s.helper_id = $3 OR s.helper_id IS NULL)
        UNION
        -- Task records
        SELECT 
          'task' AS type, 
          t.task_id AS id, 
          t.task_title, 
          t.task_description, 
          TO_CHAR(t.due_date, 'FMDay')::day_of_week AS day_of_week,
          COALESCE(tc.status, 'pending') AS status, 
          tc.completion_id, 
          t.helper_id, 
          h.name AS helper_name,
          t.priority,
          t.due_date
        FROM task t
        LEFT JOIN taskcompletion tc 
          ON t.task_id = tc.task_id
        LEFT JOIN Helper h 
          ON t.helper_id = h.helper_id
        WHERE 
          t.household_id = $1 
          AND t.due_date = $2::date
          AND (t.helper_id = $3 OR t.helper_id IS NULL)
      ) AS combined 
      ORDER BY 
        CASE priority 
          WHEN 'high' THEN 1 
          WHEN 'medium' THEN 2 
          WHEN 'low' THEN 3 
          ELSE 4 
        END, 
        task_title
    `;

    const result = await pool.query(query, [household_id, queryDate, user_helper_id]);
    res.status(200).json({ household_id, date: queryDate, tasks: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PATCH /api/tasks/:completion_id/status - Update task status (Helper only)
app.patch('/api/tasks/:completion_id/status', authenticateToken, async (req, res) => {
  console.log("Calling checkbox");
  const { completion_id } = req.params;
  console.log('completion_id:',completion_id);
  const { status } = req.body;
  const { household_id, type, id: userId } = req.user;
  console.log('status:', status);
  console.log('userId:', userId);
  console.log('household_id:', household_id);

  if (type !== 'helper') return res.status(403).json({ error: 'Only helpers can update status' });
  if (!['pending', 'completed', 'incomplete'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const result = await pool.query(
      'UPDATE taskcompletion SET status = $1, completed_by = $2, updated_at = NOW() ' +
      'WHERE completion_id = $3 AND household_id = $4 RETURNING *',
      [status, userId, completion_id, household_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Completion record not found or not yours' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/tasks/:id - Edit task details (Employer only)
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { task_title, task_description, due_date, helper_id, priority } = req.body;
  const { household_id, type: userType } = req.user;

  // Validate employer role
  if (userType !== 'employer') {
    return res.status(403).json({ error: 'Only employers can edit tasks' });
  }

  // Validate required fields
  if (!task_title) {
    return res.status(400).json({ error: 'Task title is required' });
  }

  // Validate due_date format (YYYY-MM-DD)
  if (!due_date || !/^\d{4}-\d{2}-\d{2}$/.test(due_date)) {
    return res.status(400).json({ error: 'Invalid due date format (use YYYY-MM-DD)' });
  }

  // Validate priority
  if (!['low', 'medium', 'high'].includes(priority)) {
    return res.status(400).json({ error: 'Priority must be low, medium, or high' });
  }

  // Validate helper_id (if provided)
  if (helper_id != null) {
    try {
      const helperCheck = await pool.query(
        'SELECT 1 FROM Helper WHERE helper_id = $1 AND household_id = $2',
        [helper_id, household_id]
      );
      if (helperCheck.rows.length === 0) {
        return res.status(400).json({ error: 'Invalid helper ID or helper not in household' });
      }
    } catch (error) {
      console.error('Error validating helper_id:', error);
      return res.status(500).json({ error: 'Internal server error' });
    }
  }

  try {
    const result = await pool.query(
      'UPDATE Task SET task_title = $1, task_description = $2, due_date = $3, helper_id = $4, priority = $5, updated_at = NOW() ' +
      'WHERE task_id = $6 AND household_id = $7 RETURNING *',
      [task_title, task_description || null, due_date, helper_id || null, priority, id, household_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found or not yours' });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


app.put('/api/helper', authenticateToken, async (req, res) => {
  const { household_id, type } = req.user;
  const {
    ic_number,
    passport_number,
    contract_start_date,
    contract_end_date,
    off_days,
    salary,
  } = req.body;

  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can update helper details' });
  }

  try {
    // Check if helper exists
    const checkResult = await pool.query(
      'SELECT helper_id FROM Helper WHERE household_id = $1',
      [household_id]
    );
    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'No helper found for this household' });
    }

    // Update helper details
    const result = await pool.query(
      'UPDATE Helper SET ' +
      'ic_number = $1, passport_number = $2, contract_start_date = $3, ' +
      'contract_end_date = $4, off_days = $5, salary = $6, updated_at = NOW() ' +
      'WHERE household_id = $7 RETURNING *',
      [
        ic_number || null,
        passport_number || null,
        contract_start_date || null,
        contract_end_date || null,
        off_days || null,
        salary || null,
        household_id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(500).json({ error: 'Failed to update helper details' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/helper', authenticateToken, async (req, res) => {
  
  const { household_id, type } = req.user;

  // if (type !== 'employer') {
  //   return res.status(403).json({ error: 'Only employers can view helper details' });
  // }

  try {
    const result = await pool.query(
      'SELECT helper_id, name, ic_number, passport_number, contract_start_date, ' +
      'contract_end_date, off_days, salary ' +
      'FROM Helper WHERE household_id = $1',
      [household_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No helper found for this household' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/helper', authenticateToken, async (req, res) => {
  const { household_id, type } = req.user;

  console.log('DELETE /api/helper - User:', req.user);

  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can delete helper details' });
  }

  try {
    const result = await pool.query(
      'DELETE FROM Helper WHERE household_id = $1 RETURNING helper_id',
      [household_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No helper found for this household' });
    }
    res.status(200).json({ message: 'Helper deleted successfully' });
  } catch (error) {
    console.error('Error deleting helper:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

 // GET /api/household/address
 app.get('/api/household/address', authenticateToken, async (req, res) => {
  const { household_id, type } = req.user;

  // if (type !== 'employer') {
  //   return res.status(403).json({ error: 'Only employers can view address details' });
  // }

  try {
    const result = await pool.query(
      'SELECT block_number, street_name, level, unit_number, building_name, post_code ' +
      'FROM Household WHERE household_id = $1',
      [household_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Household not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching address:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/household/address
app.put('/api/household/address', authenticateToken, async (req, res) => {
  const { household_id, type } = req.user;
  const {
    block_number,
    street_name,
    level,
    unit_number,
    building_name,
    post_code,
  } = req.body;


  if (type !== 'employer') {
    return res.status(403).json({ error: 'Only employers can update address details' });
  }

  try {
    const result = await pool.query(
      'UPDATE Household SET ' +
      'block_number = $1, street_name = $2, level = $3, ' +
      'unit_number = $4, building_name = $5, post_code = $6 ' +
      'WHERE household_id = $7 RETURNING block_number, street_name, level, unit_number, building_name, post_code',
      [
        block_number || null,
        street_name || null,
        level || null,
        unit_number || null,
        building_name || null,
        post_code || null,
        household_id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Household not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error('Error updating address:', error.message);
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => console.log('Server ready on port 3000.'));
module.exports = app;
// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`Server on port ${PORT}`));
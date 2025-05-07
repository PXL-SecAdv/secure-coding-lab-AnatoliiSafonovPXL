const pg = require('pg');

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors')
const bcrypt = require('bcrypt')

const port=3000;

const pool = new pg.Pool({
    user: process.env.POSTGRES_USER,
    host: 'db',
    database: process.env.PG_DATABASE,
    password: process.env.POSTGRES_PASSWORD,
    port: 5432,
    connectionTimeoutMillis: 5000
})

console.log("Connecting...:")

app.use(cors());
app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

app.get('/authenticate/:username/:password', async (request, response) => {
    const { username, password } = request.params;

    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE user_name = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return response.status(401).json({ error: 'Invalid username or password' });
        }

        const user = result.rows[0];
        const storedPassword = user.password;

        // 🔍 Check if password is hashed
        const isHashed = storedPassword.startsWith('$2b$') || storedPassword.startsWith('$2a$');

        let isMatch = false;

        if (isHashed) {
            isMatch = await bcrypt.compare(password, storedPassword);
        } else {
            // Plaintext match
            isMatch = password === storedPassword;

            if (isMatch) {
                // 🛡️ Upgrade to hashed password
                const hashed = await bcrypt.hash(password, 10);
                await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashed, user.id]);
            }
        }

        if (isMatch) {
            response.status(200).json([user]); // Preserves original response format
        } else {
            response.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error('Error during authentication:', error);
        response.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
  console.log(`App running on port ${port}.`)
})


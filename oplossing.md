## RISK #2: Insecure Storage
To securely store sensetive information we're gonna hash it. To do it, we're going to implement `bcrypt` algorithm in backend logic.
First, we need to install bcrypt in our project: `npm install bcrypt`, then include it in required modules: `const bcrypt = require('bcrypt')`.
Then we just paste the whole auth block to ChatGPT with prompt "re-write this piece of code to make use of bcrypt hashing algorithm. dont change any app logic", and the output is:
```js
app.get('/authenticate/:username/:password', async (request, response) => {
  const username = request.params.username;
  const password = request.params.password;

  const query = `SELECT * FROM users WHERE user_name='${username}'`;
  console.log(query);

  pool.query(query, async (error, results) => {
    if (error) {
      throw error;
    }

    if (results.rows.length === 0) {
      return response.status(401).json({ error: 'Invalid username or password' });
    }

    const user = results.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (match) {
      response.status(200).json([user]); // mimic original structure (results.rows)
    } else {
      response.status(401).json({ error: 'Invalid username or password' });
    }
  });
});
```

But we still have an issue of existing users: their sensetive data is still being stored in plain text. So another ChatGPT prompt, now "Add a check to see if password is encrypted. If it was stored in plain text, update it with hashed version".
```js
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

        // Check if password is hashed
        const isHashed = storedPassword.startsWith('$2b$') || storedPassword.startsWith('$2a$');

        let isMatch = false;

        if (isHashed) {
            isMatch = await bcrypt.compare(password, storedPassword);
        } else {
            // Plaintext match
            isMatch = password === storedPassword;

            if (isMatch) {
                // Upgrade to hashed password
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
```

And after logging in with pre-existing username, we can see that his password was updated:
```
 id | user_name |                           password                           
----+-----------+--------------------------------------------------------------
  2 | george    | iwishihadbetteradmins
  1 | pxl-admin | $2b$10$WipCdhasYV7zT60iw39x/O8TT/9sTA.z3dsJnRoY4ailbCHUahoHi
(2 rows)
```

## RISK #4 Credentials in Version Control
One of the options: create a local `.env` file, in which we store our sensetive credentials. To not expose them in Version Control system, we're adding this file into .gitignore, to tell GitHub to ignore it. This option, however, is not the best for big projects. Instead it is recommended to use some kind of Secrets Vault (for example HashiCorp Vault, 1Password Secrets, native secret manager on AWS etc).
To deal with already exposed credentials, it is required to rotate all of the compromised credentials. In same cases it might be also useful to clear github history using tools like `BFG Repo-Cleaner`.


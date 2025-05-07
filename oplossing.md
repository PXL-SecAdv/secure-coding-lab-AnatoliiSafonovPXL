## RISK #2: Insecure Storage
Om gevoelige informatie veilig op te slaan, gaan we deze hashen. Hiervoor gaan we het `bcrypt`-algoritme implementeren in de backendlogica. Eerst moeten we bcrypt installeren in ons project: npm install bcrypt. Vervolgens voegen we het toe aan de vereiste modules: `const bcrypt = require('bcrypt')`. Daarna plakken we het hele authenticatieblok in ChatGPT met de prompt:
"__re-write this piece of code to make use of bcrypt hashing algorithm. dont change any app logic__"

De output is dan:
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

Maar we hebben nog steeds een probleem met bestaande gebruikers: hun gevoelige gegevens worden nog steeds in platte tekst opgeslagen. Dus gebruiken we een nieuwe ChatGPT-prompt:
"__Add a check to see if password is encrypted. If it was stored in plain text, update it with hashed version__".
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

En nadat we ingelogd zijn met een bestaande gebruikersnaam, kunnen we zien dat zijn wachtwoord werd bijgewerkt:
```
 id | user_name |                           password                           
----+-----------+--------------------------------------------------------------
  2 | george    | iwishihadbetteradmins
  1 | pxl-admin | $2b$10$WipCdhasYV7zT60iw39x/O8TT/9sTA.z3dsJnRoY4ailbCHUahoHi
(2 rows)
```

## RISK #4 Credentials in Version Control
Een van de opties is het aanmaken van een lokale .env-bestand, waarin we onze gevoelige inloggegevens opslaan. Om te voorkomen dat deze gegevens zichtbaar zijn in het versiebeheersysteem, voegen we dit bestand toe aan `.gitignore`, zodat GitHub het negeert.

Deze aanpak is echter niet ideaal voor grotere projecten. In plaats daarvan wordt aangeraden om gebruik te maken van een gespecialiseerde __Secrets Vault__, zoals **HashiCorp Vault**, **1Password Secrets** of de **native secret manager op AWS**.

Als er reeds gevoelige gegevens zijn blootgesteld, moeten alle gecompromitteerde inloggegevens geroteerd worden. In sommige gevallen kan het ook nuttig zijn om de GitHub-geschiedenis te wissen, bijvoorbeeld met behulp van tools zoals `BFG Repo-Cleaner`.

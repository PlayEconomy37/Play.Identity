# Play.Identity

Play Economy Identity microservice.

## Setup

- Generate RSA private and public keys

```bash
make cert
```

- To convert RSA private and public key files into environment variables that can be used by our application, we can use the following code:

```bash
bytes, err := os.ReadFile("<path to RSA key>")
if err != nil {
	logger.Fatal(err, nil)
}

s := base64.StdEncoding.EncodeToString(bytes)
print(s)
```

We read in the file and base64 encode it to convert it into a string.

Note: We store this base64 encoded string as a secret in Github to be used in Github Actions.

- Use **dev.json** inside the **config** folder to define the configuration values for our application.
  If there are any sensitive values, we can define them like this:

```bash
export DB__Dsn=mongodb://localhost:27017

go run ./cmd/api
```

Our configuration parser captures environment variables that follow this naming convention:

If we have a nested structure like this:

```bash
{
    "DB": {
        "Dsn": "mongodb://localhost:27017",
        ...
    }
}
```

We can rewrite it as an environment variable like this:

```bash
DB__Dsn
```

Notice the double underscore between each nested key and how the keys must have the same exact case.

- To run Makefile commands for database migrations, we need to create a .envrc file at the root directory and add the following environment variable:

```bash
DB_DSN=<postgres dns>
```

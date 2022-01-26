# Saferun

Saferun is designed for the (now niched) cases where a host might contain several sensitive environment variables for applications, not only leading to a possible lack if the host gets targeted, as well as leading to a possible lack if the application itself gets attacked.

Saferun tackles that by allowing the use of encrypted environment variables to the hosts env.

## Getting Started

We start by creating an environment variable encrypted with a public key

```
export SAFE_RUN_DATABASE_PASSWORD=$(saferun encrypt --public-key=test.pub "my-unencrypted-password")
```


Then, we run the process with saferun and the private key

```
saferun run --private-key=test.key --only-encrypted /bin/env
```

The results will be an environment available for the process with every successfully decrypted environment available. The option `--only-encrypted` allows to control if the rest of the environment will be shared as well, or only the decrypted context.

## Using Two keys

Any set of applications should have its own private key to control what is available for its safe run. In order to do so, we can simply create two environment variables with different keys
```
export SAFE_RUN_app1=$(saferun encrypt --public-key=test.pub "app1_key")
export SAFE_RUN_app2=$(saferun encrypt --public-key=second.pub "app2_key")
```

Now, if we run app 1 with app1 key:
```
saferun run --private-key=test.key /bin/env
```
only app1 environment variable is available unencrypted. app2 is still available but encrypted (hence not useful for app1)
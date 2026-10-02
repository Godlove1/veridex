# How to run and deploy Veridex

Two parts:

1. **Run it on your own computer** to test it.
2. **Deploy it** for a real app.

Commands are written for a bash terminal (Git Bash, macOS, Linux).
In PowerShell, write `$env:NAME = "value"` instead of `export NAME=value`.

---

## Part 1: Run it on your computer

### What you need

- Python 3.10 or newer
- Node.js 22 or newer
- A PostgreSQL database
- Anvil (a fake blockchain that runs on your computer). It comes with [Foundry](https://getfoundry.sh).

### Step 1: Start the database and the fake blockchain

If you have Docker:

```bash
docker compose up -d
```

If you do not have Docker, install PostgreSQL and Foundry yourself, start
PostgreSQL, then open a second terminal and run:

```bash
anvil
```

Leave it running.

### Step 2: Install Veridex

From the project folder:

```bash
python -m venv .venv
```

```bash
source .venv/Scripts/activate
```

(On macOS or Linux the second command is `source .venv/bin/activate`.)

```bash
pip install -e "./python[dev,evm]"
```

### Step 3: Tell Veridex where the database is

```bash
export DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/postgres
```

```bash
export VERIDEX_TEST_DATABASE_URL=$DATABASE_URL
```

Change the user name and password if yours are different.
Use `127.0.0.1`, not `localhost`. On some Windows computers `localhost` hangs.

### Step 4: Run the demo

```bash
python examples/demo.py
```

You should see this:

```
1. recorded, not yet anchored                  -> PENDING_ANCHOR
2. after checkpoint to external anchor         -> VERIFIED
3. legitimate update through the app           -> VERIFIED
4. attacker: UPDATE ... SET amount = 9999999   -> TAMPERED
5. attacker: DELETE FROM demo_payments         -> TAMPERED
```

To run the same demo with the fake blockchain:

```bash
ANVIL_RPC_URL=http://127.0.0.1:8545 python examples/demo.py
```

### Step 5: Run the tests

```bash
pytest python/tests
```

All tests should pass. If Anvil is not running, the blockchain tests are
skipped, not failed.

TypeScript tests:

```bash
cd typescript && npm install && npm test
```

### If something goes wrong

| What you see | What to do |
|---|---|
| Tests hang and never finish | Use `127.0.0.1` in the database address, not `localhost`. |
| Tests say "skipped: PostgreSQL not reachable" | The database is not running, or the address or password is wrong. |
| Blockchain tests are skipped | Anvil is not running. Start it with `anvil`. |
| `No module named veridex` | Run Step 2 again, with the virtual environment turned on. |

---

## Part 2: Deploy it for a real app

Read this first:

- Veridex is **not ready for production** yet.
- It has only been tested on the fake blockchain. Nobody has run it on Base yet.
- Start on **Base Sepolia**. That is the test network, and its money is free.
- On Base mainnet, every checkpoint costs a small amount of real money.

### The three secrets

| Secret | What it does | Who needs it |
|---|---|---|
| Signing key | Signs every change your app records | Only your app |
| Wallet key | Pays to save proofs on the blockchain | Only the checkpoint job |
| Database password | Opens the database | App, checkpoint job, checker |

Keep them in a secret manager. Never put them in code.
The person who **checks** records needs none of the first two.

### Step 1: Install

On the server, from the project folder:

```bash
pip install "./python[evm]"
```

### Step 2: Make a signing key

```bash
veridex keygen
```

It prints three things:

- `signing_key`: secret. Save it safely.
- `public_key`: not secret. You give this to anyone who checks records.
- `key_id`: a short name for the key.

### Step 3: Set up the database

```bash
export VERIDEX_DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DBNAME
```

```bash
export VERIDEX_SIGNING_KEY=the-signing-key-from-step-2
```

```bash
veridex init
```

This prints a `log_id`. Save it. It is not secret.

Now choose what to protect. This example protects five columns of the
`payments` table:

```bash
veridex protect payments id,amount,currency,recipient,status
```

Your own tables are not changed. Veridex keeps its data in a separate
`veridex` schema.

### Step 4: Put the contract on the blockchain

You need a wallet with a little ETH on the network you use.
For Base Sepolia you can get free test ETH from a faucet.

```bash
export VERIDEX_EVM_RPC_URL=https://sepolia.base.org
```

```bash
export VERIDEX_EVM_CHAIN_ID=84532
```

```bash
export VERIDEX_EVM_PRIVATE_KEY=your-wallet-key
```

```bash
veridex deploy-anchor
```

It prints two addresses. Save both. They are not secret.

- `contract`: where the proofs are stored.
- `publisher`: your wallet's address.

```bash
export VERIDEX_EVM_CONTRACT=the-contract-address
```

You do this step only once.

For Base mainnet, use `https://mainnet.base.org` and chain id `8453`.
The public addresses above are slow and limited. For real use, get your own
address from a provider.

### Step 5: Record changes in your app

Every time your app changes a protected row, tell Veridex in the same
transaction:

```python
import os
from veridex import Veridex, Signer
from veridex.adapters import PostgresAdapter

signer = Signer.from_seed_hex(os.environ["VERIDEX_SIGNING_KEY"])
vx = Veridex(
    database=PostgresAdapter(os.environ["VERIDEX_DATABASE_URL"]),
    signer=signer,
    trusted_keys=[signer.public_key_hex],
)

with conn.transaction():
    conn.execute("INSERT INTO payments (id, amount, currency, recipient, status) "
                 "VALUES (123, 500, 'XAF', 'alice', 'completed')")
    vx.record("payments", "CREATE", record={"id": 123}, conn=conn)
```

Use `"CREATE"` for a new row, `"UPDATE"` for a change, `"DELETE"` for a removal.
If your transaction is cancelled, the Veridex record is cancelled too.

### Step 6: Save proofs on the blockchain, on a timer

Run this every minute with cron or any scheduler. It needs all the settings
from steps 3 and 4.

```bash
veridex checkpoint --if-due
```

It does nothing until 5,000 changes are waiting or 5 minutes have passed.
Then it sends one small proof to the blockchain.

Run this job on a different machine from your app if you can. That way the
wallet key and the app are kept apart.

### Step 7: Check a record

The checker needs no secrets, only these public values:

```bash
export VERIDEX_DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DBNAME
```

```bash
export VERIDEX_TRUSTED_KEYS=the-public-key-from-step-2
```

```bash
export VERIDEX_LOG_ID=the-log-id-from-step-3
```

```bash
export VERIDEX_EVM_RPC_URL=https://sepolia.base.org
```

```bash
export VERIDEX_EVM_CHAIN_ID=84532
```

```bash
export VERIDEX_EVM_CONTRACT=the-contract-address
```

```bash
export VERIDEX_EVM_PUBLISHER=the-publisher-address
```

Then:

```bash
veridex verify payments 123
```

### What the answer means

| Answer | Meaning |
|---|---|
| `VERIFIED` | The row matches the proof on the blockchain. |
| `PENDING_ANCHOR` | The row looks right, but its proof is not on the blockchain yet. Wait, or run the checkpoint. |
| `TAMPERED` | Someone changed or removed the row outside your app. |
| `DELETED` | Your app deleted the row properly. |
| `INVALID_PROOF` | Someone changed Veridex's own records. |
| `UNVERIFIED` | Veridex has never seen this row. |
| `ANCHOR_FAILED` | Veridex could not reach the blockchain. Check the address, chain id and contract. |
| `CONFIGURATION_ERROR` | The list of protected columns was changed in a wrong way. |

On Base, a new proof takes about 15 to 20 minutes to become final.
Until then you will see `PENDING_ANCHOR`. That is normal.

### Other useful commands

```bash
veridex status
```

Shows how many changes are saved and how many are still waiting.

```bash
veridex history payments 123
```

Shows every recorded change of one row.

```bash
veridex audit
```

Checks all of Veridex's records at once.

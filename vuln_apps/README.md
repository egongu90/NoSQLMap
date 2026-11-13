# NoSQL Injection Vulnerable App

A small, intentionally-vulnerable web app for demonstrating and testing
**NoSQL injection**. It is a three-service Docker Compose stack (Apache + PHP +
MongoDB) with three endpoints, each vulnerable to a different NoSQL injection
technique. It is the target used by NoSQLMap's functional tests.

> ⚠️ **This app is deliberately insecure.** Do not expose it to untrusted
> networks. The MongoDB credentials (`root` / `prisma`) are hardcoded and the
> endpoints feed untrusted input directly into database queries.

## Stack

| Service | Build          | Purpose                                                        |
|---------|----------------|----------------------------------------------------------------|
| apache  | `./docker/apache` | Serves the app on **http://localhost:8080** (container :80)  |
| php     | `./docker/php`    | PHP-FPM backend that talks to MongoDB                          |
| mongo   | `./docker/mongo`  | MongoDB (`root`/`prisma`), exposed on **27017**               |

The app source lives in `src/` and is bind-mounted into both the apache and php
containers, so edits to `src/*.php` take effect on the next request (no rebuild
needed).

## Quick start

```bash
cd vuln_apps
docker compose up -d --build
```

Wait a few seconds for the services to come up, then open
<http://localhost:8080/index.html>.

### Seed data loads automatically

On first Mongo boot, the image runs the seed script
(`docker/mongo/mongo.nosql`, shipped as `/docker-entrypoint-initdb.d/mongo.js`)
and loads three collections:

| Database      | Collection    | Docs |
|---------------|---------------|------|
| `shop`        | `orders`      | 6    |
| `customers`   | `paymentinfo` | 6    |
| `appUserData` | `users`       | 6    |

The Mongo container has **no volume**, so the data is ephemeral: a fresh
`docker compose up` (after `docker compose down`) re-runs the seed automatically.
To re-seed an already-running stack without recreating the container:

```bash
python vuln_apps/load_seed_data.py
```

Useful lookup values for crafting requests: customer/order/payment ID `42`,
username `adrien`, order ID `42`.

## Endpoints & vulnerabilities

Base URL: `http://localhost:8080`

### 1. Account lookup — operator injection (`acct.php`)

Looks up a payment record by customer ID. The input is used directly as the
value of a Mongo filter field, with no type or shape validation:

```php
$filter = ['id' => $_GET['acctid']];
```

**Baseline** (one record):

```bash
curl -sG 'http://localhost:8080/acct.php' --data-urlencode 'acctid=42'
```

**Injection** (dump all cards) — supply a Mongo operator instead of a value:

```bash
curl -sG 'http://localhost:8080/acct.php' --data-urlencode 'acctid[$ne]='
```

This turns the filter into `{"id": {"$ne": ""}}`, which matches every document.

### 2. User lookup — `$where` injection (`userdata.php`)

Searches users by username using a `$where` clause. The input is interpolated
straight into the JavaScript:

```php
$js = "function () { var query = '". $search . "'; return this.username == query;}";
```

**Baseline**:

```bash
curl -sG 'http://localhost:8080/userdata.php' --data-urlencode 'usersearch=adrien'
```

**Injection** (dump all users) — break out of the string and force `true`:

```bash
curl -sG 'http://localhost:8080/userdata.php' --data-urlencode "usersearch=' ; return true; '"
```

### 3. Order lookup — `$where` injection (`orderdata.php`)

Same `$where` technique as the user lookup, but against `shop.orders` and the
`id` field.

**Baseline**:

```bash
curl -sG 'http://localhost:8080/orderdata.php' --data-urlencode 'ordersearch=42'
```

**Injection** (dump all orders):

```bash
curl -sG 'http://localhost:8080/orderdata.php' --data-urlencode "ordersearch=' ; return true; '"
```

> The `$where` payload (`' ; return true; '`) can also be pasted directly into a
> browser address bar; the browser URL-encodes it for you.

## Using NoSQLMap against this app

With the stack running (`docker compose up -d --build`), you can point the
NoSQLMap CLI at it. All three endpoints are `GET`, so the relevant mode is
**NoSQL Web App attacks** (`--attack 2`).

> Install first: `pip install -e .` (provides the `nosqlmap` console script), or
> run it as a module with `python -m nosqlmap`.

The `--uri` argument must include the query string (`?param=value`); NoSQLMap
parses the parameters from it. `--params` selects which parameter to inject by
**1-based index** into that list, so `1` targets the first (and here, only)
parameter.

### Account lookup (operator injection)

```bash
nosqlmap --attack 2 --victim localhost --webPort 8080 \
    --uri '/acct.php?acctid=42' --params 1 \
    --injectSize 8 --injectFormat 3 --verb ON
```

### User lookup (`$where` injection)

```bash
nosqlmap --attack 2 --victim localhost --webPort 8080 \
    --uri '/userdata.php?usersearch=adrien' --params 1 \
    --injectSize 8 --injectFormat 1 --verb ON
```

### Order lookup (`$where` injection)

```bash
nosqlmap --attack 2 --victim localhost --webPort 8080 \
    --uri '/orderdata.php?ordersearch=42' --params 1 \
    --injectSize 8 --injectFormat 3 --verb ON
```

Add `--savePath nosqlmap-report.txt` to any of the above to write the
vulnerable / possibly-vulnerable URLs to a file.

**Options reference (web-app mode):**

| Option           | Meaning                                                                                          |
|------------------|--------------------------------------------------------------------------------------------------|
| `--attack 2`     | NoSQL Web App attacks                                                                             |
| `--victim`       | Target host/IP (e.g. `localhost`)                                                                |
| `--webPort`      | Target web port (e.g. `8080`)                                                                    |
| `--uri`          | App path **including** the query string, e.g. `/acct.php?acctid=42`                             |
| `--params`       | 1-based index(es) of the query parameter(s) to inject, comma-separated (e.g. `1`)               |
| `--injectSize`   | Length of the random baseline string                                                             |
| `--injectFormat` | Baseline string format: `1`=alphanumeric, `2`=letters, `3`=numbers, `4`=email                   |
| `--httpMethod`   | `GET` (default) or `POST`                                                                        |
| `--verb`         | `ON` for verbose output                                                                          |
| `--savePath`     | File to write the results to                                                                     |

> Running `NoSQLMap` with no arguments opens an interactive menu; option **3**
> is "NoSQL Web App attacks" and walks you through the same options.

## Resetting the app

- **Full reset** (recreates containers and re-runs the seed):

  ```bash
  docker compose down && docker compose up -d --build
  ```

- **Re-seed only** (keeps containers running, drops and re-inserts the seed):

  ```bash
  python vuln_apps/load_seed_data.py
  ```

## Tests

Functional tests that exercise the live stack (they skip gracefully if the
stack is not running) live in `tests/test_vuln_app.py`:

```bash
python -m pytest tests/test_vuln_app.py -v
```

The base URL defaults to `http://localhost:8080` and can be overridden with the
`NOSQLMAP_APP_URL` environment variable.

## How to create a db migration script

This folder contains database migration scripts that are run via [db-migrate](https://db-migrate.readthedocs.io/en/latest/).

db-migrate uses the `database.json` file in the root project folder to determine what database to connect to, and how, depending on your environment.

1. Install db-migrate globally (**npm install -g db-migrate**).
1. Create migration script (**db-migrate create my-migration**).

Ref: <https://db-migrate.readthedocs.io/en/latest/search/>

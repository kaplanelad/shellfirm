<!-- GENERATED FILE, do not edit by hand.
     Regenerate from the repository root: make catalogue -->

# Built-in checks

496 checks in 23 groups, generated from [`shellfirm/checks/`](../../shellfirm/checks). List them locally with `shellfirm check --list -a` (add `-g <group>` to filter).

| Group | Checks | Enabled by default |
|---|---:|---|
| [aws](#aws) | 29 | yes |
| [azure](#azure) | 11 | yes |
| [base](#base) | 30 | yes |
| [database](#database) | 78 | yes |
| [docker](#docker) | 17 | yes |
| [exfil](#exfil) | 11 | yes |
| [flyio](#flyio) | 4 | yes |
| [fs](#fs) | 68 | yes |
| [gcp](#gcp) | 17 | yes |
| [git](#git) | 38 | yes |
| [github](#github) | 11 | yes |
| [heroku](#heroku) | 22 | yes |
| [kubernetes](#kubernetes) | 37 | yes |
| [mongodb](#mongodb) | 16 | yes |
| [mysql](#mysql) | 7 | yes |
| [netlify](#netlify) | 3 | yes |
| [network](#network) | 18 | yes |
| [npm](#npm) | 4 | yes |
| [psql](#psql) | 11 | yes |
| [redis](#redis) | 19 | yes |
| [shell](#shell) | 14 | yes |
| [terraform](#terraform) | 27 | yes |
| [vercel](#vercel) | 4 | yes |

## aws

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `aws:s3_remove_bucket` | HIGH | This deletes the S3 bucket and, with --force, all of its contents. | `aws s3 ls s3://<bucket>` |
| `aws:s3_recursive_delete` | HIGH | Recursively deleting all objects in an S3 bucket. |  |
| `aws:ec2_terminate` | HIGH | Terminating EC2 instances permanently destroys them and their local storage. | `aws ec2 stop-instances` |
| `aws:rds_delete` | HIGH | Deleting an RDS instance will permanently destroy the database. | `aws rds create-db-snapshot --db-instance-identifier <name> --db-snapshot-identifier <name>-final` |
| `aws:iam_delete` | HIGH | Deleting IAM resources can break access for services and users. |  |
| `aws:cfn_delete_stack` | HIGH | Deleting a CloudFormation stack will destroy all resources it manages. |  |
| `aws:route53_delete_zone` | HIGH | Deleting a Route53 hosted zone will remove all DNS records. |  |
| `aws:eks_delete_cluster` | HIGH | Deleting an EKS cluster will destroy the Kubernetes control plane. |  |
| `aws:lambda_delete` | HIGH | Deleting a Lambda function removes it permanently. |  |
| `aws:dynamodb_delete_table` | HIGH | Deleting a DynamoDB table permanently destroys all its data. |  |
| `aws:sqs_delete_queue` | HIGH | Deleting an SQS queue loses all queued messages. |  |
| `aws:sns_delete_topic` | HIGH | Deleting an SNS topic breaks all subscriptions. |  |
| `aws:ecr_delete_repository` | HIGH | Deleting an ECR repository removes all container images. |  |
| `aws:secretsmanager_delete` | HIGH | Deleting a secret can break applications depending on it. |  |
| `aws:elasticache_delete_cluster` | HIGH | Deleting an ElastiCache cluster destroys all cached data. |  |
| `aws:logs_delete_log_group` | HIGH | Deleting a CloudWatch log group permanently loses all log data. |  |
| `aws:ecs_delete` | HIGH | Deleting an ECS service or cluster stops all running containers. |  |
| `aws:rds_delete_cluster` | HIGH | Deleting an RDS cluster or snapshot permanently destroys the data. |  |
| `aws:s3_sync_delete` | HIGH | Syncing with --delete removes destination objects that are not in the source. | `aws s3 sync --dryrun --delete ...` |
| `aws:kms_schedule_key_deletion` | CRITICAL | Scheduling KMS key deletion makes all data encrypted with that key unrecoverable. | `aws kms disable-key --key-id <id>` |
| `aws:ecr_batch_delete_image` | MEDIUM | This deletes container images from an ECR repository. |  |
| `aws:redshift_delete_cluster` | HIGH | This deletes a Redshift cluster and its data. |  |
| `aws:elasticache_delete_replication_group` | HIGH | This deletes an ElastiCache replication group and its data. |  |
| `aws:docdb_delete` | HIGH | This deletes a DocumentDB / Neptune database cluster or instance. |  |
| `aws:rds_disable_backups` | HIGH | Setting the backup retention period to 0 disables automated backups and deletes the existing ones. |  |
| `aws:scale_to_zero` | HIGH | This scales the Auto Scaling group or ECS service to zero: every instance or task of it stops. | `aws ecs describe-services --cluster <cluster> --services <service>` |
| `aws:s3api_delete_bucket` | HIGH | This deletes the S3 bucket or deletes objects from it in bulk. |  |
| `aws:cdk_destroy` | HIGH | This destroys the CDK stacks and every AWS resource they created. |  |
| `aws:iac_destroy` | HIGH | This tears down the deployed stack and every resource it created (Serverless, SAM, Amplify or SST). |  |

## azure

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `azure:delete_resource_group` | HIGH | Deleting a resource group will destroy all resources within it. |  |
| `azure:delete_vm` | HIGH | Deleting a virtual machine permanently destroys it. | `az vm deallocate --name <vm>` |
| `azure:delete_sql_server` | HIGH | Deleting an Azure SQL server will destroy all its databases. |  |
| `azure:delete_aks_cluster` | HIGH | Deleting an AKS cluster will destroy all workloads running on it. |  |
| `azure:delete_storage` | HIGH | Deleting Azure storage resources can result in permanent data loss. |  |
| `azure:delete_keyvault` | HIGH | Deleting a Key Vault removes all secrets, keys, and certificates. |  |
| `azure:delete_ad_app` | HIGH | Deleting an Azure AD application or service principal can break authentication. |  |
| `azure:delete_functionapp` | HIGH | Deleting an Azure Function App removes it permanently. |  |
| `azure:delete_webapp` | HIGH | Deleting a web app removes it and all deployed code. |  |
| `azure:delete_cosmosdb` | HIGH | Deleting a Cosmos DB account destroys all databases and data. |  |
| `azure:delete_database` | HIGH | Deleting an Azure database or database server permanently destroys its data. |  |

## base

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `base:bash_fork_bomb` | CRITICAL | This short line defines a shell function that creates new copies of itself. The process continually replicates itself, and its copies continually replicate themselves, quickly taking up all your CPU time and memory. This can cause your computer to freeze. It's basically a denial-of-service attack. |  |
| `base:delete_all_cron_tasks` | HIGH | This removes all of your cron jobs. |  |
| `base:crontab_replace` | MEDIUM | This replaces your whole crontab with this input: every existing cron job not in it is removed, and the new ones run on a schedule from now on. | `crontab -l > crontab.backup` |
| `base:execute_all_history_commands` | CRITICAL | This re-runs every command in your shell history. |  |
| `base:reboot_machine` | HIGH | This reboots the machine. |  |
| `base:shutdown_machine` | HIGH | This shuts down the machine. |  |
| `process:kill_init_or_all` | CRITICAL | This signals PID 1 (init, or a container's main process) or every process you own (-1): it can halt the machine or end your whole session. |  |
| `base:clear_history` | MEDIUM | This erases your shell history, including the record of what was run. |  |
| `process:kill_9` | LOW | SIGKILL gives no chance for graceful shutdown or cleanup. | `kill <pid>` |
| `process:killall` | MEDIUM | This kills every process with that name. |  |
| `process:pkill` | MEDIUM | This kills every process matching the pattern, which can include unintended ones. |  |
| `systemd:disable_service` | MEDIUM | Disabling or masking a service prevents it from starting on boot. |  |
| `systemd:stop_critical_service` | HIGH | Stopping a critical system service can cause outages. |  |
| `base:poweroff_machine` | HIGH | This powers off the machine immediately. |  |
| `base:init_shutdown_reboot` | HIGH | This shuts down (init 0) or reboots (init 6) the machine. |  |
| `ssh:delete_all_identities` | MEDIUM | This removes all identities from the SSH agent. |  |
| `ssh:remove_known_host` | LOW | Removes a host from known_hosts — could enable MITM attacks. |  |
| `base:userdel_remove_home` | HIGH | This deletes the user together with their home directory and mail spool. |  |
| `base:passwd_delete` | HIGH | This removes the account's password: it can then log in without one. |  |
| `base:sysrq_trigger` | CRITICAL | This runs a kernel SysRq action immediately (b reboots, o powers off, c crashes the kernel), without a clean shutdown. |  |
| `base:systemctl_enable` | LOW | This makes a service start automatically at every boot or login. |  |
| `systemd:isolate_rescue` | HIGH | This switches the machine to single-user / emergency mode (or halts it): every other service stops, including the network and SSH. |  |
| `base:lock_root_account` | HIGH | This locks the root account's password: without another administrator login you can lock yourself out. |  |
| `base:remount_root_readonly` | HIGH | This remounts the root filesystem read-only: services that write to disk start failing. |  |
| `base:journal_vacuum` | MEDIUM | This permanently deletes archived system journal logs. |  |
| `base:delete_shadow_copies` | CRITICAL | This deletes the Windows shadow copies or backups (System Restore, previous versions of files) or turns off Windows recovery: nothing is left to restore from. |  |
| `base:delete_backups_macos` | CRITICAL | This deletes Time Machine backups or local APFS snapshots: there is nothing left to restore the files from. |  |
| `base:clear_event_logs` | HIGH | This clears the Windows event logs, erasing the record of what happened on the machine. |  |
| `base:disable_antivirus` | HIGH | This turns off Windows Defender protection, excludes a path from scanning, removes its definitions, or stops its service. |  |
| `base:disable_macos_security` | HIGH | This disables a core macOS protection — System Integrity Protection (csrutil) or Gatekeeper (spctl) — letting unsigned or tampered code run. |  |

## database

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `database:drop_database` | CRITICAL | Dropping a database permanently deletes all of its data. |  |
| `database:drop_table` | CRITICAL | Dropping a table permanently deletes all of its data. |  |
| `database:drop_tablespace` | HIGH | Dropping a tablespace removes the storage location for its tables. |  |
| `database:truncate_table` | CRITICAL | Truncating a table permanently deletes all of its rows. |  |
| `database:delete_all_rows` | CRITICAL | DELETE without a WHERE clause deletes every row in the table. | `DELETE FROM <table> WHERE <condition>` |
| `database:update_all_rows` | HIGH | UPDATE without a WHERE clause modifies every row in the table. |  |
| `database:drop_schema_role_user` | HIGH | Dropping a schema, role, user or owned objects is destructive and often irreversible. |  |
| `database:alter_drop_column` | HIGH | Dropping a column permanently removes its data from every row. |  |
| `database:drop_index` | MEDIUM | Dropping an index on a production table can severely degrade performance. |  |
| `database:drop_view` | MEDIUM | Dropping a view breaks every query, report and application that reads from it. |  |
| `database:drop_object` | MEDIUM | Dropping a function, trigger, extension, sequence or type can break the application that depends on it. |  |
| `database:drop_cascade` | HIGH | DROP ... CASCADE also drops every object that depends on it (views, foreign keys, columns of that type). |  |
| `database:drop_schema_cascade` | CRITICAL | DROP SCHEMA ... CASCADE drops every table, view and function in the schema. |  |
| `database:revoke_all` | HIGH | REVOKE ALL can lock users and applications out of the database. |  |
| `database:alter_system` | MEDIUM | ALTER SYSTEM changes the server configuration for every database on the server. |  |
| `database:copy_program` | HIGH | COPY ... PROGRAM runs a shell command on the database server. |  |
| `database:explain_analyze_write` | MEDIUM | EXPLAIN ANALYZE really executes the statement it explains. | `BEGIN; EXPLAIN ANALYZE ...; ROLLBACK;` |
| `database:prepare_write` | MEDIUM | This prepares a DELETE/UPDATE/TRUNCATE/DROP that runs on every EXECUTE. |  |
| `database:terminate_backend` | MEDIUM | pg_terminate_backend kills client connections; their open transactions are rolled back. |  |
| `database:drop_keyspace` | CRITICAL | Dropping a Cassandra keyspace permanently deletes every table in it. |  |
| `database:cqlsh_drop` | CRITICAL | This runs a DROP KEYSPACE/TABLE or TRUNCATE statement through cqlsh (Cassandra). |  |
| `database:clickhouse_drop` | CRITICAL | This runs a DROP DATABASE/TABLE or TRUNCATE statement through clickhouse-client. |  |
| `database:alter_drop_index` | MEDIUM | Dropping an index on a production table can severely degrade performance. |  |
| `database:alter_drop_key` | HIGH | Dropping a primary or foreign key removes the integrity guarantees (duplicates and orphan rows can appear) and can slow every query that used it. |  |
| `database:merge_delete` | MEDIUM | MERGE ... WHEN MATCHED THEN DELETE deletes every row the join condition matches. |  |
| `database:alter_delete_all` | CRITICAL | ALTER TABLE ... DELETE WHERE <always true> (ClickHouse) deletes every row in the table. | `ALTER TABLE <table> DELETE WHERE <condition>` |
| `database:cockroach_drop` | CRITICAL | This runs a DROP DATABASE/TABLE/SCHEMA or TRUNCATE statement through cockroach sql. |  |
| `database:sqlcmd_drop` | CRITICAL | This runs a DROP DATABASE/TABLE/SCHEMA or TRUNCATE statement through sqlcmd (SQL Server). |  |
| `database:lo_unlink_all` | HIGH | lo_unlink over pg_largeobject deletes every large object in the database (the files and blobs stored in it). |  |
| `database:innodb_flush_log_off` | MEDIUM | innodb_flush_log_at_trx_commit = 0 stops flushing the redo log on every commit: committed transactions can be lost in a crash. |  |
| `database:delete_limit_without_where` | HIGH | DELETE ... LIMIT without a WHERE clause deletes that many arbitrary rows of the table. | `DELETE FROM <table> WHERE <condition> LIMIT <n>` |
| `database:prisma_migrate_reset` | CRITICAL | prisma migrate reset drops the database (or every table in it), re-applies all migrations and runs the seed: all data is lost. | `prisma migrate status` |
| `database:prisma_db_push_force_reset` | CRITICAL | prisma db push --force-reset drops and recreates the whole database schema: all data is lost. | `prisma migrate dev --create-only` |
| `database:prisma_db_push_data_loss` | HIGH | prisma db push --accept-data-loss applies schema changes that drop columns or tables without asking. | `prisma migrate dev --create-only` |
| `database:rails_db_drop` | CRITICAL | This Rails task drops or wipes the database (db:drop / db:reset / db:purge / db:migrate:reset / db:truncate_all): all data is lost. | `rails db:migrate:status` |
| `database:rails_schema_load` | HIGH | db:schema:load / db:structure:load / db:setup recreate every table from the schema file: the data in the existing tables is lost. | `rails db:migrate:status` |
| `database:flyway_clean` | CRITICAL | flyway clean drops every object (tables, views, functions) in the configured schemas. | `flyway info` |
| `database:flyway_clean_build_tool` | CRITICAL | The Maven / Gradle flyway clean goal drops every object (tables, views, functions) in the configured schemas. | `mvn flyway:info` |
| `database:liquibase_drop_all` | CRITICAL | liquibase dropAll drops every database object in the configured schemas. | `liquibase status --verbose` |
| `database:django_flush` | CRITICAL | flush / reset_db deletes all data from every table of the Django database (reset_db drops and recreates it). | `python manage.py dumpdata --output backup.json` |
| `database:django_migrate_zero` | HIGH | migrate <app> zero un-applies every migration of the app: its tables are dropped. | `python manage.py migrate <app> zero --plan` |
| `database:dbmate_drop` | CRITICAL | dbmate drop drops the database. | `dbmate status` |
| `database:alembic_downgrade_base` | HIGH | alembic / flask db downgrade base runs every down migration: the tables they created are dropped. | `alembic downgrade base --sql` |
| `database:knex_rollback_all` | HIGH | knex migrate:rollback --all rolls back every migration batch: the tables they created are dropped. | `knex migrate:rollback` |
| `database:sqitch_revert` | HIGH | sqitch revert -y reverts deployed changes without asking (their tables and data are dropped). | `sqitch status` |
| `database:sequelize_db_drop` | CRITICAL | sequelize db:drop drops the database. | `sequelize db:migrate:status` |
| `database:sequelize_undo_all` | HIGH | sequelize db:migrate:undo:all reverts every migration: the tables they created are dropped. | `sequelize db:migrate:undo` |
| `database:typeorm_schema_drop` | CRITICAL | typeorm schema:drop drops every table of the database. | `typeorm schema:log` |
| `database:drizzle_push_force` | HIGH | drizzle-kit push --force applies schema changes that drop columns or tables without asking. | `drizzle-kit generate` |
| `database:drizzle_kit_drop` | MEDIUM | drizzle-kit drop deletes a generated migration (its SQL file and journal entry). |  |
| `database:ecto_drop` | CRITICAL | mix ecto.drop / ecto.reset drops the database. | `mix ecto.migrations` |
| `database:artisan_wipe` | CRITICAL | artisan migrate:fresh / db:wipe drops every table of the database. | `php artisan migrate:status` |
| `database:artisan_migrate_reset` | HIGH | artisan migrate:reset / migrate:refresh rolls back every migration: the tables they created are dropped. | `php artisan migrate:rollback --pretend` |
| `database:doctrine_drop` | CRITICAL | doctrine:database:drop / doctrine:schema:drop --force drops the database or every table in it. | `bin/console doctrine:schema:drop --dump-sql` |
| `database:golang_migrate_drop` | CRITICAL | migrate drop (golang-migrate) drops everything in the database. | `migrate -path <dir> -database <url> version` |
| `database:goose_reset` | HIGH | goose reset / down-to 0 rolls back every migration: the tables they created are dropped. | `goose status` |
| `database:cli_database_drop` | CRITICAL | diesel / sqlx database drop\|reset drops the database (reset recreates it empty). | `diesel migration list` |
| `database:atlas_schema_clean` | CRITICAL | atlas schema clean drops every object in the target database or schema. | `atlas schema inspect -u <url>` |
| `database:dotnet_ef_database_drop` | CRITICAL | dotnet ef database drop drops the Entity Framework Core database: all data is lost. | `dotnet ef database drop --dry-run` |
| `database:dotnet_ef_update_zero` | HIGH | dotnet ef database update 0 reverts every Entity Framework Core migration: the tables they created are dropped. | `dotnet ef migrations script <current> <target>` |
| `database:ecto_rollback_all` | HIGH | mix ecto.rollback --all rolls back every migration: the tables they created are dropped. | `mix ecto.rollback --step 1` |
| `database:golang_migrate_down_all` | HIGH | migrate down -all (golang-migrate) applies every down migration without asking: the tables they created are dropped. | `migrate -path <dir> -database <url> down 1` |
| `database:supabase_db_reset_remote` | CRITICAL | supabase db reset --linked resets the database of the linked remote project (often production): every table is dropped and the migrations and seed re-run. | `supabase db dump --linked -f backup.sql` |
| `database:supabase_db_reset` | MEDIUM | supabase db reset drops the local database and re-runs the migrations and seed: local data is lost. | `supabase migration list` |
| `database:supabase_projects_delete` | CRITICAL | supabase projects delete deletes the Supabase project with its database, storage and auth users. | `supabase projects list` |
| `database:firebase_firestore_delete_all` | CRITICAL | firebase firestore:delete --all-collections deletes every document of every collection in the Firestore database. | `gcloud firestore export gs://<bucket>/backup` |
| `database:firebase_firestore_delete` | HIGH | firebase firestore:delete deletes Firestore documents (with -r, every document under the path). | `gcloud firestore export gs://<bucket>/backup` |
| `database:firebase_database_remove_root` | CRITICAL | firebase database:remove / deletes the whole Realtime Database. | `firebase database:get / -o backup.json` |
| `database:firebase_database_remove` | HIGH | firebase database:remove deletes the data at the given path of the Realtime Database, with everything under it. | `firebase database:get <path> -o backup.json` |
| `database:sql_from_file` | MEDIUM | SQL from a file is not checked here: shellfirm cannot see the statements this file runs (prefix the same client command with `shellfirm wrap`, e.g. `shellfirm wrap <client> …`, to have the file scanned). |  |
| `database:wrangler_d1_delete` | CRITICAL | wrangler d1 delete deletes the Cloudflare D1 database with all of its data. | `wrangler d1 export <database> --remote --output backup.sql` |
| `database:wrangler_kv_namespace_delete` | CRITICAL | wrangler kv namespace delete deletes the Workers KV namespace and every key in it. | `wrangler kv namespace list` |
| `database:wrangler_r2_bucket_delete` | HIGH | wrangler r2 bucket delete deletes the Cloudflare R2 bucket. | `wrangler r2 bucket list` |
| `database:neon_project_delete` | CRITICAL | neonctl projects delete deletes the Neon project with all of its branches and databases. | `neonctl projects list` |
| `database:neon_branch_delete` | HIGH | neonctl branches delete deletes the Neon branch and the data written on it. | `neonctl branches list` |
| `database:pscale_database_delete` | CRITICAL | pscale database delete deletes the PlanetScale database with all of its branches and data. | `pscale database list` |
| `database:pscale_branch_delete` | HIGH | pscale branch delete deletes the PlanetScale branch and its data. | `pscale branch list <database>` |
| `database:turso_db_destroy` | CRITICAL | turso db destroy deletes the Turso database (group destroy: every database in the group). | `turso db shell <database> .dump > backup.sql` |

## docker

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `docker:system_prune_all` | HIGH | This removes all unused Docker data: stopped containers, networks, unused images and build cache. | `docker system prune` |
| `docker:force_remove_all_containers` | HIGH | This force-removes all containers. |  |
| `docker:force_remove_images` | HIGH | Force-removing images can break containers that depend on them. |  |
| `docker:remove_volume` | HIGH | Removing Docker volumes permanently deletes the data they contain. |  |
| `docker:volume_prune` | HIGH | This removes unused volumes and their data (every one, unless --filter keeps some). |  |
| `docker:remove_network` | MEDIUM | Removing a Docker network can disconnect containers using it. |  |
| `docker:compose_down_volumes` | HIGH | This stops the containers and deletes their volumes and data. | `docker-compose down` |
| `docker:stop_all_containers` | MEDIUM | This stops all running containers. |  |
| `docker:image_prune_all` | HIGH | This removes all unused images, not just dangling ones. | `docker image prune` |
| `docker:container_prune` | MEDIUM | This removes stopped containers (every one, unless --filter keeps some). |  |
| `docker:buildx_prune_all` | HIGH | This clears the entire build cache. |  |
| `docker:run_privileged` | HIGH | Running a container with --privileged gives it full access to the host system. |  |
| `docker:network_prune` | MEDIUM | This removes all unused Docker networks. |  |
| `docker:kill_all_containers` | MEDIUM | This kills all running containers. |  |
| `docker:run_mount_host_root` | HIGH | This mounts the host's root filesystem into the container: anything in it can read or change every host file. |  |
| `docker:run_mount_host_sensitive` | HIGH | This mounts the container engine socket or a host system directory into the container: it can take over the host. |  |
| `docker:podman_system_reset` | HIGH | This deletes every Podman container, pod, image, volume and network on the machine. |  |

## exfil

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `exfil:secret_file_to_network` | HIGH | This sends a credentials file to the network. |  |
| `exfil:env_to_network` | HIGH | This sends your environment variables (which often hold API keys and tokens) to the network. |  |
| `exfil:upload_secret_file` | HIGH | This uploads a credentials or secrets file to a remote server. |  |
| `exfil:ssh_authorized_keys` | HIGH | This changes the SSH keys allowed to log in to this account, which can grant someone persistent access. |  |
| `exfil:copy_secret_to_remote` | HIGH | This copies your SSH keys or cloud credentials to another machine. |  |
| `exfil:archive_secret_dir` | MEDIUM | This packs your SSH keys or cloud credentials into an archive, which is easy to copy or upload somewhere else. |  |
| `exfil:secret_to_socket` | HIGH | This sends a private key or credentials file over the network. |  |
| `exfil:archive_secret_and_send` | HIGH | This packs your SSH keys or cloud credentials and sends the archive to another machine. |  |
| `exfil:read_secret_file` | MEDIUM | This reads a private key or a credentials file. Shown on screen it can leak (screen sharing, terminal logs); run by an AI agent, the secret goes into the conversation and on to the model provider. | `read only what you need, not the secret itself` |
| `exfil:print_token` | MEDIUM | This prints a live access token or a secret. Shown on screen it can leak; run by an AI agent, it goes into the conversation and on to the model provider. | `check that you are authenticated without printing the secret` |
| `exfil:search_secret_files` | MEDIUM | This searches your home directory or the whole machine for private keys, credentials or wallet files. | `find . -name '<pattern>'` |

## flyio

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `flyio:apps_destroy` | CRITICAL | Destroying a Fly.io app permanently removes it and all its resources. |  |
| `flyio:secrets_unset` | HIGH | Removing secrets can break running applications that depend on them. |  |
| `flyio:volumes_destroy` | HIGH | Destroying a volume permanently deletes all data stored on it. |  |
| `flyio:postgres_destroy` | CRITICAL | Destroying a Fly Postgres cluster permanently deletes the database and all its data. |  |

## fs

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `fs:recursively_delete` | CRITICAL | This deletes a critical location: the filesystem root, your home directory, a system directory, the repository, or everything in the current directory. | `trash <path>` |
| `fs:delete_credentials` | CRITICAL | This deletes SSH keys, GPG keys or cloud / cluster credentials from your home directory. | `trash <path>` |
| `fs:diskutil_erase` | CRITICAL | This erases a disk or volume with diskutil: all data on it is lost. |  |
| `fs:write_to_block_device` | CRITICAL | This writes straight onto a disk device, overwriting the partition table and file systems on it. |  |
| `fs:nvme_format` | CRITICAL | This erases or sanitizes an NVMe device at the controller level: all data on it is lost. |  |
| `fs:windows_recursive_delete` | CRITICAL | This deletes a whole Windows drive, the user profiles or the Windows directory, with every file and folder in it. |  |
| `fs:windows_remove_item_recursive` | CRITICAL | This deletes a whole Windows drive, your user profile or the Windows directory, with every file and folder in it. |  |
| `fs:windows_pipeline_delete` | CRITICAL | This lists a whole Windows drive or your user profile and pipes every item into a delete. |  |
| `fs:windows_format_drive` | CRITICAL | This formats a Windows drive or wipes a disk, erasing all data on it. |  |
| `fs:recursively_delete_outside` | HIGH | This recursively deletes a top-level folder of your home directory (for example `~/projects` or `~/data`), or a directory outside the current one reached with `../`. | `trash <path>` |
| `fs:delete_repository` | HIGH | This recursively deletes a whole git repository, including any work that was never pushed. | `trash <path>` |
| `fs:delete_git_dir` | CRITICAL | This deletes the .git directory of a repository: its whole history, branches, stashes and every commit that was never pushed. | `trash <path>` |
| `fs:move_work_away` | HIGH | This moves a folder with work git does not have to a scratch folder that is cleared on its own. | `git stash push --include-untracked -- <path>` |
| `fs:sensitive_path` | HIGH | This deletes or overwrites a path you marked as sensitive (context.sensitive_paths). |  |
| `fs:move_to_dev_null` | CRITICAL | Moving files to /dev/null destroys them. |  |
| `fs:flush_file_content` | MEDIUM | This redirection overwrites the existing file and erases its contents. |  |
| `fs:recursively_chmod` | CRITICAL | Recursively changing permissions on the root, home or current directory can break the system and SSH keys. |  |
| `fs:chmod_credentials` | HIGH | This changes the permissions of your SSH or GnuPG keys so that other users can read them (ssh then refuses the keys), or so that nobody can. | `chmod -R go-rwx ~/.ssh` |
| `fs:delete_find_files` | CRITICAL | find -delete without a name, time or size filter deletes everything under the path: here the filesystem root, your home directory, a system directory, the repository or the current directory. | `find <path> -name '<pattern>' -print` |
| `fs:delete_find_files_dir` | MEDIUM | find -delete without a name, time or size filter deletes every file under the given directory. | `find <path> -name '<pattern>' -print` |
| `fs:delete_find_files_critical_root` | CRITICAL | find -delete under the filesystem root, your home directory or a system directory deletes every matching file there. | `find <path> -name '<pattern>' -print` |
| `fs:delete_find_files_filtered` | MEDIUM | find -delete permanently deletes every file matching the filter. | `find <path> -name '<pattern>' -print` |
| `fs:dd_block_device` | CRITICAL | Writing directly to a block device can overwrite the whole disk. |  |
| `fs:mkfs_format` | CRITICAL | Formatting a device erases all data on it. |  |
| `fs:parted_disk_modify` | CRITICAL | Modifying disk partitions can erase all data on the disk. |  |
| `fs:fdisk_disk_modify` | CRITICAL | Modifying disk partitions can erase all data on the disk. |  |
| `fs:sfdisk_disk_modify` | CRITICAL | Modifying disk partitions can erase all data on the disk. |  |
| `fs:dd_advanced_disk_write` | CRITICAL | Writing to a specific disk sector can corrupt data. |  |
| `fs:gdisk_disk_modify` | CRITICAL | Modifying GPT disk partitions can erase all data on the disk. |  |
| `fs:sgdisk_zap` | CRITICAL | This destroys the partition table of the disk (with --zap-all also the MBR); every partition on it becomes unreachable. | `sgdisk --print <device>` |
| `fs:blkdiscard` | CRITICAL | This discards every block of the device (TRIM): the data on it is gone at once and cannot be recovered. | `lsblk -f <device>` |
| `fs:mdadm_zero_superblock` | CRITICAL | This erases the RAID superblock of the device: the array it belongs to can no longer be assembled from it. | `mdadm --examine <device>` |
| `fs:partprobe_disk_update` | HIGH | Re-reading the partition table can affect mounted partitions. |  |
| `fs:blockdev_disk_modify` | HIGH | Changing block device parameters can affect disk operations. |  |
| `fs:mount_operations` | HIGH | Mounting a raw block device can affect system stability. |  |
| `fs:lvm_operations` | CRITICAL | Removing a logical volume, physical volume or volume group deletes all of its data. |  |
| `fs:filesystem_backup` | HIGH | Dumping or restoring a raw filesystem device can affect system stability. |  |
| `fs:encryption_operations` | CRITICAL | Encrypting or reformatting a device with cryptsetup can make its data inaccessible. |  |
| `fs-strict:change_permissions` | LOW | This changes file permissions. |  |
| `fs-strict:any_deletion` | LOW | This permanently deletes the given files. |  |
| `fs-strict:recursive_deletion` | MEDIUM | This recursively deletes the given files or directories, with everything inside them. | `trash <path>` |
| `fs-strict:folder_deletion` | MEDIUM | This deletes the given directory. |  |
| `fs:rsync_delete` | HIGH | Syncs with deletion — removes files at destination not present in source. | `rsync --dry-run --delete ...` |
| `fs:recursively_chown` | CRITICAL | Recursively changing the owner of the root, home or current directory, a system directory or your SSH keys can break the system and lock you out. |  |
| `fs:shred` | HIGH | Shred overwrites file data at the block level, making recovery impossible unlike rm. | `rm <file>` |
| `fs:truncate_zero` | HIGH | This truncates the file to zero bytes and erases its contents. |  |
| `fs:recursive_delete_unknown_target` | HIGH | The deletion target comes from a variable, from another command's output (xargs, find -exec) or from a link created earlier on the line, so it cannot be verified. An empty variable, unexpected input or a link to an important directory deletes far more than intended. | `echo <targets>` |
| `fs:delete_unknown_target` | MEDIUM | This deletes files whose names come from another command's output (xargs, find -exec), so the targets cannot be verified. |  |
| `fs:recursive_delete_home_glob` | HIGH | This deletes everything inside a directory in your home folder. | `trash <path>` |
| `fs:recursive_delete_data_dir` | HIGH | This deletes a database or container-engine data directory: every database, image or volume stored there is lost. |  |
| `fs:recursive_delete_top_level_dir` | HIGH | This recursively deletes a top-level directory of the filesystem. |  |
| `fs:overwrite_system_file` | HIGH | This writes to a system file or replaces a shell startup file. Overwriting it can break logins, networking or the whole system. |  |
| `fs:append_shell_startup_file` | LOW | This appends to a shell startup file: the added lines run in every new shell. |  |
| `fs:startup_alias_replaces_command` | HIGH | This adds an alias to a shell startup file that makes a command run a different, destructive one (for example `ls` running `rm`) in every new shell. |  |
| `fs:delete_system_file` | HIGH | This deletes a system file. The system may not boot or let you log in afterwards. |  |
| `fs:move_system_file` | HIGH | This moves a system file or directory (or your home directory) away. Programs and logins that need it break until it is moved back. |  |
| `fs:move_credentials` | HIGH | This moves SSH keys, GPG keys or cloud / cluster credentials out of your home directory (or into an archive that deletes them): logins and CLIs that use them stop working, and the copy may be readable elsewhere. |  |
| `fs:zip_move` | MEDIUM | zip -m deletes the original files after adding them to the archive. |  |
| `fs:clobber_with_dev_null` | HIGH | This replaces the file with /dev/null and erases its contents. |  |
| `fs:chmod_critical_location` | HIGH | Changing permissions of the root, home or a system directory can lock you out and break SSH and system services. |  |
| `fs:watch_repeated_delete` | MEDIUM | watch runs this deletion again and again, every interval. |  |
| `fs:interpreter_inline_delete` | MEDIUM | This inline script deletes files or directories. |  |
| `fs:wipefs` | CRITICAL | This erases the filesystem / partition-table signatures of a device, making its data unreachable. |  |
| `fs:umount_lazy` | MEDIUM | A lazy unmount detaches the filesystem while programs still use it; writes in flight can be lost. |  |
| `fs:zfs_destroy` | HIGH | This destroys a ZFS dataset / pool and all of its data and snapshots. |  |
| `fs:recursive_owner_change_system_dir` | HIGH | This recursively changes the owner or permissions of a system data / service directory: the service that owns it can stop working. |  |
| `fs:copy_over_home` | MEDIUM | This copies the contents of a directory over your home directory, replacing your dotfiles (shell startup files, SSH configuration). |  |
| `fs:zfs_rollback_recursive` | HIGH | This rolls the ZFS dataset back and destroys every later snapshot (and with -R their clones). | `zfs list -t snapshot -o name,creation <dataset>` |

## gcp

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `gcp:delete_project` | HIGH | Deleting a GCP project will destroy all resources within it. |  |
| `gcp:delete_instance` | HIGH | Deleting a Compute Engine instance permanently destroys it. | `gcloud compute instances stop <instance>` |
| `gcp:delete_sql_instance` | HIGH | Deleting a Cloud SQL instance permanently destroys the database. |  |
| `gcp:delete_gke_cluster` | HIGH | Deleting a GKE cluster will destroy all workloads running on it. |  |
| `gcp:gcs_recursive_delete` | HIGH | Recursively deleting all objects in a GCS bucket. | `gsutil ls gs://<bucket>` |
| `gcp:gcs_remove_bucket` | HIGH | Removing a GCS bucket and all its contents. |  |
| `gcp:delete_service_account` | HIGH | Deleting a service account can break applications using it. |  |
| `gcp:delete_function` | HIGH | Deleting a Cloud Function removes it permanently. |  |
| `gcp:delete_cloud_run` | HIGH | Deleting a Cloud Run service stops serving traffic. |  |
| `gcp:delete_pubsub_topic` | HIGH | Deleting a Pub/Sub topic breaks all connected subscriptions. |  |
| `gcp:delete_secret` | HIGH | Deleting a secret can break applications depending on it. |  |
| `gcp:storage_recursive_delete` | HIGH | Recursively deleting objects in a Cloud Storage bucket. | `gcloud storage ls gs://<bucket>` |
| `gcp:delete_sql_database` | HIGH | Deleting a Cloud SQL database permanently destroys its data. |  |
| `gcp:spanner_delete` | HIGH | This deletes a Cloud Spanner instance or database and all its data. |  |
| `gcp:bq_rm` | HIGH | This deletes a BigQuery dataset or table. |  |
| `gcp:firebase_projects_delete` | HIGH | firebase projects:delete deletes the Firebase (Google Cloud) project with every resource and all data in it. | `firebase projects:list` |
| `gcp:firebase_hosting_disable` | MEDIUM | firebase hosting:disable takes the hosted site offline: visitors get a 404 until the next deploy. | `firebase hosting:channel:list` |

## git

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `git:reset` | HIGH | This discards all uncommitted changes in your working tree. | `git stash` |
| `git:delete_all` | HIGH | This deletes all tracked files from the working tree. |  |
| `git:clean_force` | HIGH | This permanently deletes untracked files (and directories with -d). Git cannot restore them. | `git clean -fdn` |
| `git:force_push` | HIGH | This force-pushes and can overwrite remote history. | `git push --force-with-lease` |
| `git:force_delete_branch` | HIGH | This deletes a branch even if it has unmerged commits. | `git branch -d <branch>` |
| `git:force_checkout` | HIGH | This force-checks-out and discards local changes. | `git stash && git checkout <branch>` |
| `git:checkout_discard_all` | HIGH | This discards all uncommitted changes in the working tree. | `git stash` |
| `git:checkout_discard_path` | MEDIUM | This discards uncommitted changes in the given paths. | `git stash push -- <path>` |
| `git:restore_discard_all` | HIGH | This discards all uncommitted changes in the working tree. | `git stash` |
| `git:restore_discard_path` | MEDIUM | This discards uncommitted changes in the given paths. | `git stash push -- <path>` |
| `git:interactive_rebase` | MEDIUM | This starts an interactive rebase, which rewrites commit history. |  |
| `git:filter_branch` | HIGH | This rewrites Git history. | `git-filter-repo` |
| `git:gc_prune` | HIGH | This permanently deletes unreachable objects. |  |
| `git:delete_ref` | HIGH | This deletes a Git reference. |  |
| `git:merge_no_ff` | MEDIUM | This creates a merge commit or aborts an ongoing merge. |  |
| `git:cherry_pick` | MEDIUM | This applies existing commits onto the current branch. |  |
| `git:bisect` | MEDIUM | This starts a bisect session that checks out other commits. |  |
| `git:worktree_management` | MEDIUM | This adds or removes a Git worktree. |  |
| `git-strict:add_all` | LOW | This stages every changed file. |  |
| `git-strict:commit_all` | LOW | This commits every changed tracked file. |  |
| `git-strict:rebase` | LOW | This rewrites commit history by moving commits to a new base. |  |
| `git-strict:stash_pop_drop` | LOW | This applies or removes stashed changes. |  |
| `git:stash_clear` | HIGH | This permanently deletes all stash entries. | `git stash list` |
| `git-strict:submodule_update` | LOW | This updates or deinitializes Git submodules. |  |
| `git-strict:create_tag` | LOW | This creates an annotated tag. |  |
| `git:push_mirror` | CRITICAL | Mirror push overwrites the ENTIRE remote — all branches, tags, and refs. |  |
| `git:push_delete_branch` | HIGH | This deletes a remote branch or tag. |  |
| `git:push_prune` | HIGH | This deletes every branch on the remote that does not exist locally (with --all in a fresh clone: every other branch). | `git push --all --prune --dry-run origin` |
| `git:reflog_expire` | CRITICAL | Expiring all reflog entries destroys the last recovery mechanism for lost commits. |  |
| `git:switch_discard_changes` | HIGH | This switches branches and discards local changes. | `git stash && git switch <branch>` |
| `git:config_exec_hook` | HIGH | This makes git run a program from the given location on every git command (hooks / ssh / fsmonitor / the ext:: transport), a common persistence trick. |  |
| `git:rm_force` | MEDIUM | This deletes the files from the working tree and discards their uncommitted changes. | `git rm --cached <path>` |
| `git:branch_force_move` | MEDIUM | This moves an existing branch to another commit; commits after it are dropped from the branch. |  |
| `git:checkout_reset_branch` | MEDIUM | This resets the branch to the start point if it already exists, dropping its commits. |  |
| `git:filter_repo` | HIGH | This rewrites the whole repository history (and removes the origin remote). |  |
| `git:force_push_protected` | HIGH | This force-pushes (with lease) to a protected branch and rewrites its shared history. |  |
| `git:force_push_unknown_target` | HIGH | This force-pushes (with lease) to a branch that is only known when the line runs; this repository has a protected branch, so it may rewrite that branch's shared history. |  |
| `git:config_exec_program` | MEDIUM | This makes git run a program of your choice on later git commands (pager, editor, diff driver, credential helper or a shell alias), a common persistence trick, in every repository with --global. |  |

## github

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `github:repo_delete` | CRITICAL | Permanently deletes a repository and all its data. |  |
| `github:repo_archive` | HIGH | Archiving a repository makes it read-only and can break workflows. |  |
| `github:repo_rename` | HIGH | Renaming a repository breaks all existing URLs, clones, and CI/CD references. |  |
| `github:repo_change_visibility` | HIGH | Changing repository visibility can expose private code or break public access. |  |
| `github:release_delete` | HIGH | Deleting a release removes it and its assets permanently. |  |
| `github:secret_delete` | HIGH | Deleting a secret can break CI/CD pipelines that depend on it. |  |
| `github:variable_delete` | HIGH | Deleting a variable can break CI/CD pipelines that depend on it. |  |
| `github:api_delete_repo` | CRITICAL | This deletes the GitHub repository through the API, with its issues, pull requests and wiki. |  |
| `github:pr_merge_admin` | MEDIUM | This merges the pull request as an administrator, bypassing the branch protection rules (required reviews and checks). |  |
| `github:api_delete_ref` | HIGH | This deletes a branch or tag of the repository through the GitHub API (like `git push --delete`). | `gh api repos/<owner>/<repo>/git/refs/heads/<branch>` |
| `github:api_branch_protection` | HIGH | This removes or changes the branch protection rules (required reviews and checks) through the GitHub API. | `gh api repos/<owner>/<repo>/branches/<branch>/protection` |

## heroku

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `heroku:restart_app_dynos` | MEDIUM | This restarts the app's dynos. |  |
| `heroku:stop_app_dynos` | HIGH | This stops the app's dynos. |  |
| `heroku:kill_app_dynos` | HIGH | This kills the app's dynos. |  |
| `heroku:enable_maintenance_mode` | HIGH | This puts the app into maintenance mode. |  |
| `heroku:remove_member` | HIGH | This removes a user from the team. |  |
| `heroku:disable_app_feature` | MEDIUM | This disables an app feature. |  |
| `heroku:remove_app_container` | HIGH | This removes a process type from the app. |  |
| `heroku:unset_environment_variable` | MEDIUM | This removes config vars from the app. |  |
| `heroku:destroy_client` | HIGH | This deletes an OAuth client. |  |
| `heroku:rotate_oauth_client` | MEDIUM | This rotates the OAuth client secret. |  |
| `heroku:update_oauth_client` | MEDIUM | This updates an OAuth client. |  |
| `heroku:destroy_app` | CRITICAL | This permanently destroys the app. |  |
| `heroku:remove_yourself_from_app` | MEDIUM | This removes you from a team app. |  |
| `heroku:rename_app_name` | MEDIUM | This renames the app and breaks its existing URLs. |  |
| `heroku:destroy_addons` | HIGH | This permanently destroys an add-on. |  |
| `heroku:detach_addon` | MEDIUM | This detaches an add-on from the app. |  |
| `heroku:remove_user_access` | HIGH | This removes users from a team app. |  |
| `heroku:update_collaborators_access` | MEDIUM | This changes collaborator permissions on a team app. |  |
| `heroku:reset_repo` | HIGH | This resets the Heroku git repository. |  |
| `heroku:pg_reset` | CRITICAL | This deletes all data in the Heroku Postgres database. |  |
| `heroku:railway_down` | HIGH | railway down removes the most recent deployment of the service, which takes it offline. | `railway status` |
| `heroku:railway_delete` | CRITICAL | railway delete deletes the Railway project with its services, databases and volumes. | `railway status` |

## kubernetes

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `kubernetes:delete_namespace` | CRITICAL | Deleting the namespace also deletes all the residing components. | `kubectl get all -n <namespace>` |
| `kubernetes-strict:delete_resource` | HIGH | This deletes the given Kubernetes resource. |  |
| `kubernetes-strict:delete_pod` | MEDIUM | This deletes the given pod(s); a Deployment or ReplicaSet recreates them, a bare pod is gone. |  |
| `kubernetes-strict:force_delete_pod` | HIGH | This force-deletes pods without a graceful shutdown: a stateful pod can lose data in flight. | `kubectl delete pod <name>` |
| `kubernetes-strict:update_resource` | HIGH | This updates the given Kubernetes resource. |  |
| `kubernetes-strict:change_resource_size` | HIGH | This changes the replica count of the given resource. |  |
| `kubernetes-strict:rollout_resource` | MEDIUM | This changes the rollout state of the given resource (restart rolls every pod, undo reverts to the previous revision, pause stops further rollouts). |  |
| `helm:uninstall` | HIGH | Removing a Helm release deletes all its managed Kubernetes resources. |  |
| `helm:rollback` | MEDIUM | Rolling back a Helm release reverts to a previous revision. |  |
| `helm:upgrade_force` | HIGH | Force-upgrading a Helm release deletes and recreates resources. |  |
| `kubernetes:drain_node` | HIGH | Draining a node evicts all pods and marks the node unschedulable. |  |
| `kubernetes:cordon_node` | MEDIUM | Cordoning a node prevents new pods from being scheduled on it. |  |
| `kubernetes:replace_force` | HIGH | Force-replacing a resource deletes and recreates it, causing downtime. |  |
| `kubernetes:delete_all_resources` | CRITICAL | Deleting all resources of a type wipes everything in the namespace. | `kubectl get <resource> -n <namespace>` |
| `kubernetes:apply_force` | HIGH | Force-applying deletes and recreates resources, causing downtime. | `kubectl apply -f <file>` |
| `kubernetes:apply_prune` | HIGH | Applying with --prune deletes every resource that is not in the applied files. | `kubectl diff -f <file>` |
| `kubernetes:taint_noexecute` | MEDIUM | A NoExecute taint immediately evicts every pod that does not tolerate it from the node. |  |
| `kubernetes:patch` | MEDIUM | This patches a live Kubernetes object in place (e.g. scaling it to 0 or changing its spec). |  |
| `kubernetes:apply_force_conflicts` | MEDIUM | --force-conflicts takes over fields that other controllers or users manage, overwriting their values. |  |
| `kubernetes:overwrite_metadata` | MEDIUM | --overwrite replaces existing annotations or labels that controllers and selectors may rely on. |  |
| `kubernetes:debug_node_root` | HIGH | This opens a root shell on the Kubernetes node itself (chroot into the host filesystem): anything run there changes the node, not a pod. |  |
| `kubernetes:debug_node` | MEDIUM | This starts a debugging pod on the Kubernetes node with the host's filesystem mounted at /host and its network and process namespaces: what you run there can change the node itself. | `kubectl describe node <node>` |
| `kubernetes:helmfile_destroy` | HIGH | helmfile destroy uninstalls every release of the helmfile (in the selected environment) from the cluster. |  |
| `kubernetes:argocd_app_delete` | HIGH | Deleting an Argo CD application (with its default cascade) deletes every Kubernetes resource it manages. | `argocd app delete <app> --cascade=false` |
| `kubernetes:argocd_cluster_rm` | HIGH | argocd cluster rm removes the cluster from Argo CD: the applications deployed to it stop being managed (and their sync and history). | `argocd app list --dest-server <cluster>` |
| `kubernetes:argocd_sync_force` | HIGH | argocd app sync --force deletes and recreates the resources it cannot update in place (and, with --prune, deletes every resource that is not in Git). | `argocd app diff <app>` |
| `kubernetes:argocd_sync_prune` | MEDIUM | argocd app sync --prune deletes every live resource of the application that is no longer in Git. | `argocd app diff <app>` |
| `kubernetes:istioctl_uninstall` | HIGH | istioctl uninstall removes the Istio control plane (with --purge every Istio resource): the mesh's traffic routing, mTLS and policies stop working. | `istioctl uninstall --purge --dry-run` |
| `kubernetes:cilium_uninstall` | HIGH | cilium uninstall removes the cluster's CNI: pods lose networking until another CNI is installed. | `cilium status` |
| `kubernetes:flux_delete` | HIGH | This deletes a Flux object (and, with prune, the resources it manages) or uninstalls Flux from the cluster. |  |
| `kubernetes:eksctl_delete_cluster` | HIGH | This deletes an EKS cluster (or node group) and everything running on it. |  |
| `kubernetes:etcd_delete_keys` | CRITICAL | This deletes (or replaces from a snapshot) the keys of the etcd store, which holds every object of the Kubernetes cluster. | `etcdctl get <prefix> --prefix --keys-only` |
| `kubernetes:kubeadm_reset` | HIGH | This tears down the Kubernetes node: it removes the control-plane / kubelet configuration and the local etcd data of this machine. |  |
| `kubernetes:config_delete_context` | LOW | This removes a context, cluster or user entry from your kubeconfig. |  |
| `kubernetes:velero_backup_delete` | HIGH | This deletes Velero backups (or a backup schedule): the cluster's disaster-recovery copies are gone. | `velero backup get` |
| `kubernetes:velero_restore` | MEDIUM | This restores Kubernetes objects from a Velero backup into the current cluster, which can recreate or (with --existing-resource-policy=update) overwrite live objects. | `velero backup describe <backup> --details` |
| `kubernetes:etcd_member_remove` | HIGH | This removes a member from the etcd cluster; removing the wrong one (or too many) loses quorum and stops the Kubernetes control plane. | `etcdctl member list -w table` |

## mongodb

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `mongodb:drop` | CRITICAL | This drops a collection or database through the MongoDB shell. |  |
| `mongodb:interactive_drop_collection` | CRITICAL | Dropping a MongoDB collection will permanently delete all its data. |  |
| `mongodb:interactive_drop_database` | CRITICAL | Dropping a MongoDB database will permanently delete all its data. |  |
| `mongodb:interactive_drop_collection_indirect` | CRITICAL | Dropping a MongoDB collection permanently deletes all of its data. |  |
| `mongodb:delete_all_documents` | HIGH | Deleting with an empty filter removes every document in the collection. |  |
| `mongodb:update_all_documents` | HIGH | updateMany with an empty filter modifies every document in the collection. |  |
| `mongodb:run_command_drop` | CRITICAL | This drops a database or collection through a command document (runCommand/adminCommand). |  |
| `mongodb:run_command_delete_all` | HIGH | A delete command with an empty filter (`q: {}`) removes every document in the collection. |  |
| `mongodb:rename_drop_target` | HIGH | renameCollection with dropTarget drops the target collection (and all of its documents) if it exists. |  |
| `mongodb:drop_all_users` | HIGH | This removes every user (or role) of the database; applications lose access. |  |
| `mongodb:drop_user` | MEDIUM | Dropping a user/role removes access for whatever uses it. |  |
| `mongodb:shutdown` | HIGH | This shuts down the MongoDB server. |  |
| `mongodb:drop_indexes` | MEDIUM | Dropping indexes can severely degrade query performance until they are rebuilt. |  |
| `mongodb:bulk_delete_all` | HIGH | A bulkWrite deleteMany with an empty filter removes every document in the collection. |  |
| `mongodb:mongorestore_drop` | HIGH | mongorestore --drop drops every collection it restores before restoring it (documents added since the dump are lost). | `mongorestore <dump-dir>` |
| `mongodb:mongoimport_drop` | HIGH | mongoimport --drop drops the target collection before importing (its existing documents are lost). | `mongoimport --mode=upsert <file>` |

## mysql

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `mysql:drop` | CRITICAL | This runs a DROP DATABASE/TABLE/SCHEMA statement through mysql (-e / --execute / --init-command). |  |
| `mysql:mysqladmin_drop` | CRITICAL | mysqladmin drop permanently deletes a MySQL database. |  |
| `mysql:reset_master` | HIGH | RESET MASTER deletes every binary log (breaks replicas and point-in-time recovery). |  |
| `mysql:purge_binary_logs` | HIGH | PURGE BINARY LOGS deletes binary logs (replicas that still need them break, point-in-time recovery is lost). |  |
| `mysql:read_only_off` | MEDIUM | Turning read_only off makes the server writable (on a replica, writes diverge it from the primary). |  |
| `mysql:mysqladmin_shutdown` | HIGH | mysqladmin shutdown stops the MySQL server; every connection is cut. |  |
| `mysql:safe_updates_off` | MEDIUM | Turning sql_safe_updates off lets UPDATE and DELETE statements without a key in the WHERE clause (or without any WHERE) change every row. | `DELETE FROM my_table WHERE id = 42` |

## netlify

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `netlify:sites_delete` | CRITICAL | Deleting a Netlify site permanently removes it and all its deployments. |  |
| `netlify:env_unset` | HIGH | Removing an environment variable can break builds and deployments. |  |
| `netlify:env_clone` | HIGH | Cloning environment variables overwrites the target site's variables. |  |

## network

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `network:flush_iptables` | CRITICAL | This flushes all firewall rules. |  |
| `network:delete_custom_chains` | HIGH | This deletes all custom firewall chains. |  |
| `network:flush_nat_rules` | HIGH | This flushes all NAT rules. |  |
| `network:disable_firewall` | CRITICAL | This disables the firewall. |  |
| `network:force_reset_firewall` | CRITICAL | This resets the firewall: every rule is removed and the firewall is disabled. |  |
| `network:stop_networking` | HIGH | This stops the networking service. |  |
| `network:stop_network_manager` | HIGH | This stops NetworkManager. |  |
| `network:bring_down_interface` | HIGH | This brings a network interface down. |  |
| `network:bring_down_interface_ip` | HIGH | This brings a network interface down. |  |
| `network:delete_default_route` | HIGH | This deletes the default network route. |  |
| `network:flush_nftables` | CRITICAL | Flushing all nftables rules removes all firewall protection. |  |
| `network:flush_routes` | CRITICAL | Flushing the routing table causes immediate loss of network connectivity. |  |
| `network:iptables_default_drop` | HIGH | This sets the default firewall policy to DROP, which can cut off all traffic, including your SSH session. |  |
| `network:iptables_drop_all_input` | HIGH | This appends a catch-all DROP/REJECT rule to INPUT, dropping all incoming traffic including your SSH session. |  |
| `network:reverse_shell` | HIGH | This opens a reverse shell: it hands an interactive shell on this machine to whoever listens at the remote address. |  |
| `network:flush_addresses` | HIGH | This removes the IP addresses of a network interface: the machine (and your SSH session) loses connectivity on it. |  |
| `network:ufw_default_deny` | HIGH | This makes the firewall refuse all incoming connections by default, including SSH unless a rule allows it. | `ufw allow OpenSSH` |
| `network:disable_firewall_windows` | CRITICAL | This turns the Windows firewall off, leaving every port open. |  |

## npm

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `npm:unpublish` | CRITICAL | Unpublishing a package removes it from the registry, breaking all downstream dependents. |  |
| `npm:deprecate` | HIGH | Deprecating a package marks it as deprecated for all users. |  |
| `npm:yarn_unpublish` | CRITICAL | Unpublishing a package removes it from the registry, breaking all downstream dependents. |  |
| `npm:pnpm_unpublish` | CRITICAL | Unpublishing a package removes it from the registry, breaking all downstream dependents. |  |

## psql

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `psql:drop` | CRITICAL | This runs a DROP DATABASE/TABLE/SCHEMA statement through psql. |  |
| `psql:dropdb` | CRITICAL | dropdb permanently deletes a PostgreSQL database. |  |
| `psql:pg_restore_clean` | MEDIUM | pg_restore --clean drops the database objects before recreating them from the dump. |  |
| `psql:dropuser` | HIGH | dropuser removes a PostgreSQL role; applications and people using it lose access. |  |
| `psql:pg_ctl_immediate` | HIGH | pg_ctl stop -m immediate aborts the server without a clean shutdown (crash recovery on the next start, connections are cut). | `pg_ctl stop -m fast -D <datadir>` |
| `psql:pg_resetwal` | CRITICAL | pg_resetwal rewrites the write-ahead log; it can leave the database corrupted and is a last-resort recovery tool. |  |
| `psql:pg_dropcluster` | CRITICAL | pg_dropcluster deletes a PostgreSQL cluster: its data directory and every database in it. |  |
| `psql:gexec` | MEDIUM | \gexec runs every value the query returns as a new SQL statement; those statements are not checked. |  |
| `psql:pgbench_initialize` | MEDIUM | pgbench -i drops and recreates the pgbench_* tables (pgbench_accounts, pgbench_branches, ...) in the target database. |  |
| `psql:patronictl_remove` | HIGH | patronictl remove deletes the cluster's state from the DCS (leader key, members, configuration): Patroni loses track of the cluster. |  |
| `psql:patronictl_failover_force` | MEDIUM | patronictl failover/switchover --force changes the primary without asking; connections to the old primary are cut. |  |

## redis

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `redis:flushall` | CRITICAL | FLUSHALL deletes all data in every Redis database. | `redis-cli BGSAVE && redis-cli -n <db> FLUSHDB` |
| `redis:flushdb` | HIGH | FLUSHDB deletes all data in the current Redis database. |  |
| `redis:interactive_flushall` | CRITICAL | FLUSHALL deletes all data in every Redis database. | `BGSAVE, then SELECT <db> and FLUSHDB` |
| `redis:interactive_flushdb` | HIGH | FLUSHDB deletes all data in the current Redis database. |  |
| `redis:interactive_shutdown` | CRITICAL | SHUTDOWN stops the Redis server. |  |
| `redis:shutdown` | HIGH | SHUTDOWN stops the Redis server (with NOSAVE, data since the last snapshot is lost). |  |
| `redis:eval_flush` | CRITICAL | This Lua script calls FLUSHALL/FLUSHDB and deletes data. |  |
| `redis:script_flush` | MEDIUM | SCRIPT FLUSH removes every cached Lua script; EVALSHA calls fail until they are loaded again. |  |
| `redis:function_flush` | MEDIUM | This deletes Redis functions that applications may call. |  |
| `redis:config_set` | MEDIUM | CONFIG SET changes the live server configuration (persistence, memory limits, security). |  |
| `redis:debug` | HIGH | DEBUG can crash, block or reload the Redis server. |  |
| `redis:cluster_reset` | HIGH | This changes the cluster topology and can make the node lose its slots or data. |  |
| `redis:cli_admin` | MEDIUM | This runs an administrative Redis command (CONFIG SET, DEBUG, CLUSTER RESET, SCRIPT FLUSH). |  |
| `redis:replicaof` | HIGH | REPLICAOF/SLAVEOF makes this server a replica: it throws away its whole dataset and copies the other server's. |  |
| `redis:swapdb` | HIGH | SWAPDB swaps two databases: every client of one database instantly sees the other's data. |  |
| `redis:acl_deluser` | MEDIUM | ACL DELUSER removes users; applications authenticating as them lose access. |  |
| `redis:cli_function_flush` | MEDIUM | This deletes Redis functions that applications may call. |  |
| `redis:keys_xargs_del` | HIGH | This lists every key and deletes them all (KEYS/--scan piped into DEL). |  |
| `redis:pattern_xargs_del` | HIGH | This deletes every key that matches the pattern (KEYS / --scan --pattern piped into DEL), in bulk and without a review. | `redis-cli --scan --pattern '<pattern>' \| head` |

## shell

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `shell:curl_pipe_to_shell` | HIGH | Piping remote content directly to shell executes arbitrary code without inspection. | `curl -o script.sh <url> && cat script.sh` |
| `shell:wget_pipe_to_shell` | HIGH | Piping downloaded content to shell executes arbitrary code without inspection. | `wget -O script.sh <url> && cat script.sh` |
| `shell:eval_curl` | HIGH | Evaluating remote content executes arbitrary code without inspection. | `curl -o script.sh <url> && cat script.sh` |
| `shell:curl_pipe_to_interpreter` | HIGH | Piping remote content to an interpreter executes arbitrary code without inspection. | `curl -o script.py <url> && cat script.py` |
| `shell:decode_pipe_to_shell` | HIGH | This decodes hidden text and runs it as shell commands, so you cannot see what it does. | `base64 -d <<< '<data>'` |
| `shell:eval_transformed_text` | HIGH | This runs (eval) text that is decoded or transformed first, so you cannot see the commands it runs. | `echo "$(<transform>)"` |
| `shell:process_substitution_remote` | HIGH | This runs a downloaded script directly (process substitution) without inspection. | `curl -o script.sh <url> && cat script.sh` |
| `shell:nesting_too_deep` | HIGH | The command is nested too deeply (eval / $( ) / bash -c inside each other) or is too large or malformed to be analyzed safely. |  |
| `shell:shell_c_remote_script` | HIGH | This downloads a script and runs it as shell code without inspection (`sh -c "$(curl …)"` is the same as `curl … \| sh`). | `curl -o script.sh <url> && cat script.sh` |
| `shell:unknown_shell_payload` | HIGH | This runs shell code that shellfirm cannot see before it runs (input lines executed as commands, as in `xargs -I{} sh -c '{}'`), so it cannot be checked. |  |
| `shell:function_depth_limit` | MEDIUM | This calls a shell function too large or too deeply nested for the shell hook to read ahead, so part of what it runs was not checked. |  |
| `shell:powershell_download_exec` | HIGH | This downloads a PowerShell script and runs it (Invoke-Expression) without inspection. | `Invoke-WebRequest <url> -OutFile script.ps1; Get-Content script.ps1` |
| `shell:lolbin_download_exec` | HIGH | This uses a Windows built-in tool (certutil, bitsadmin, mshta or regsvr32) to download and run code from a URL, bypassing normal download controls. | `Invoke-WebRequest <url> -OutFile file; Get-FileHash file` |
| `shell:powershell_encoded_command` | HIGH | This runs a PowerShell command hidden in base64 (-EncodedCommand), so you cannot see what it does. |  |

## terraform

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `terraform:apply_with_auto_approve` | CRITICAL | This applies infrastructure changes without asking for confirmation. | `terraform plan -out=plan.tfplan` |
| `terraform:destroy_auto_approve` | CRITICAL | This destroys all managed infrastructure without asking for confirmation. | `terraform plan -destroy` |
| `terraform:destroy` | HIGH | This destroys managed infrastructure. | `terraform plan -destroy` |
| `terraform:apply_plan_file` | HIGH | This applies a saved plan file without asking for confirmation; whatever the plan does (including destroying resources) happens at once. | `terraform show <planfile>` |
| `terraform:apply_destroy_plan` | CRITICAL | This writes a destroy plan and applies it on the same line: the managed infrastructure is destroyed without any confirmation. | `terraform plan -destroy -out=destroy.tfplan && terraform show destroy.tfplan` |
| `terraform:state` | HIGH | This modifies Terraform state without asking for confirmation. | `terraform state <cmd> -dry-run` |
| `terraform:state_rm` | HIGH | Removing a resource from state makes Terraform lose track of existing infrastructure. | `terraform state list` |
| `terraform:workspace_delete_with_force_flag` | HIGH | This deletes a Terraform workspace without asking for confirmation. |  |
| `terraform:workspace_delete_without_lock` | HIGH | This deletes a Terraform workspace without acquiring the state lock. |  |
| `terraform:force_unlock_with_force_flag` | HIGH | This removes the state lock without asking for confirmation. |  |
| `terraform:workspace_delete` | MEDIUM | This deletes a Terraform workspace and its state. |  |
| `terraform:force_unlock` | MEDIUM | This removes the state lock; if another run is in progress the state can be corrupted. |  |
| `terraform:pulumi_destroy` | HIGH | This destroys every resource in the Pulumi stack. | `pulumi preview --destroy` |
| `terraform:pulumi_stack_rm` | HIGH | This removes a Pulumi stack and its configuration and history. |  |
| `terraform:import` | MEDIUM | This imports an existing resource into the state; a wrong address makes the next apply change or destroy it. |  |
| `terraform:taint` | MEDIUM | This marks a resource as tainted: the next apply destroys and recreates it. |  |
| `terraform:state_push_force` | HIGH | This overwrites the remote state with a local file even if it is older (lineage / serial checks are skipped). |  |
| `terraform:apply_replace` | MEDIUM | This destroys and recreates the given resource. |  |
| `terraform:vault_secrets_destroy` | HIGH | This permanently deletes Vault secrets (a disabled secrets engine loses all of its data; kv destroy / metadata delete remove versions for good). | `vault kv delete <path>` |
| `terraform:vault_kv_delete` | MEDIUM | This deletes a secret: permanently on a KV version 1 engine, the latest version (until `vault kv undelete`) on version 2. | `vault kv get -format=json <path>` |
| `terraform:vault_raft_remove_peer` | HIGH | vault operator raft remove-peer removes a server from the Vault cluster; removing the wrong one (or too many) loses quorum and the cluster stops serving. | `vault operator raft list-peers` |
| `terraform:vault_seal_or_revoke` | HIGH | This seals Vault or revokes tokens / leases in bulk: every client that relies on them loses access. | `vault token lookup <token>` |
| `terraform:vault_auth_disable` | HIGH | Disabling a Vault auth method revokes every token and lease issued through it: every client that logged in with it loses access. | `vault auth list -detailed` |
| `terraform:vault_policy_delete` | MEDIUM | Deleting a Vault policy removes its permissions from every token and role that uses it. | `vault policy read <name>` |
| `terraform:consul_kv_delete_recurse` | HIGH | This deletes every Consul key under the prefix. | `consul kv get -recurse <prefix>` |
| `terraform:nomad_job_purge` | HIGH | This stops the Nomad job and purges it from the cluster state, with its history. | `nomad job stop <job>` |
| `terraform:nomad_system_gc` | MEDIUM | This garbage-collects dead jobs, allocations and nodes from Nomad: their history and logs are gone. |  |

## vercel

| Id | Severity | Description | Alternative |
|---|---|---|---|
| `vercel:remove` | CRITICAL | Removing a Vercel deployment or project takes it offline permanently. |  |
| `vercel:project_remove` | CRITICAL | Removing a Vercel project deletes it and all its deployments. |  |
| `vercel:env_remove` | HIGH | Removing an environment variable can break deployments that depend on it. |  |
| `vercel:domain_remove` | HIGH | Removing a domain disconnects it from your deployment. |  |

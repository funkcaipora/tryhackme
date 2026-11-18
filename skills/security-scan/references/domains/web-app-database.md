# Domain: Web application and database

> **Status: outline.** The checks below are the plan for this playbook. The read-only commands, the evidence format and the detailed criteria for each check are added in build step 3. Until then, use the outline with the stage file and your own knowledge of the platform, and stay inside the rules of engagement.

**Covers:** The user's own application code, its APIs and the databases behind it. Review of code and configuration, never live testing.

**Read with:** the repository (code review), database configuration, connectors to the database platform (schema and grants only)

Use this playbook together with the stage file: the stage file says what question to answer, this file says where to look in this technology. Every stage heading below matches a file in `../phases/`.

## Stage 1: Initial reconnaissance

- routes and endpoints exposed
- source maps, API descriptions, debug endpoints, detailed errors

## Stage 2: Initial compromise

- missing authentication, object access without ownership check, injection, request forgery, upload, token verification
- default credentials, open registration

## Stage 3: Foothold

- what an authenticated low-privilege user can call
- database runtime account rights

## Stage 4: Privilege escalation

- privilege fields accepted from requests
- signing keys
- tenant isolation

## Stage 5: Internal reconnaissance

- endpoints that enumerate users, tenants or objects
- secrets in configuration served to clients

## Stage 6: Lateral movement

- request forgery toward internal services and metadata
- database credentials shared across services
- internal APIs that trust network position

## Stage 7: Persistence and control

- creation of API tokens, users or webhooks without alert
- upload paths that execute

## Stage 8: Mission

- bulk export and unpaginated endpoints
- notification and payment functions without limits
- access to dumps and backups

## Detection sources

- application logs, web access logs, database audit logs

## Collector

`scripts/collectors/web_app_database.py` (not implemented yet). Its job is the read-only collection for the checks above, written as redacted JSON under `evidence/<stage>/`.

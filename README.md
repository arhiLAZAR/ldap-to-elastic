# Overview
A script for synchronization users from LDAP to Elasticsearch
- Do not recreates existing users (it won't overwrite any manual changes)
- Configures via environment variables
- Every user gets a new random password. You can use [Keycloak](https://www.keycloak.org/), [OAuth2-Proxy](https://github.com/oauth2-proxy/oauth2-proxy) and Kibana's header **es-security-runas-user** to login with your current LDAP passwords

# Quickstart

```
docker run --rm \
--env L2E_LDAP_DOMAIN="ldap.example.org" \
--env L2E_LDAP_LOGIN="cn=admin,dc=example,dc=org" \
--env L2E_LDAP_PASS="put_your_ldap_password_here" \
--env L2E_LDAP_BASE_DN="dc=example,dc=org" \
--env L2E_ELASTIC_LOGIN="elastic" \
--env L2E_ELASTIC_PASS="put_your_elastic_password_here" \
arhilazar/ldap-to-elastic
```

# Environment variables
| Variable | Description | Default |
| ------------- | ------------- | ------------- |
| L2E_DEBUG | Display all matched LDAP users and all found in Elastic users and roles if "True" | False |
| L2E_LDAP_DOMAIN | LDAP domain (or IP) | localhost |
| L2E_LDAP_PORT | LDAP port | 389 |
| L2E_LDAP_SCHEMA | LDAP schema. If you use ldaps, probably you should also set "L2E_LDAP_CA_FILE_PATH"   | ldap |
| L2E_LDAP_CA_FILE_PATH | Path to the CA file for the LDAP connection. Can be absolute or relative. Do not use CA if empty | "" |
| L2E_LDAP_LOGIN | LDAP login | cn=admin,dc=example,dc=org |
| L2E_LDAP_PASS | LDAP password | Not@SecureP@ssw0rd |
| L2E_LDAP_BASE_DN | Which part of LDAP tree to search in | dc=example,dc=org |
| L2E_LDAP_FILTER | How to decide which entries are users | objectclass=inetOrgPerson |
| L2E_LDAP_GROUPS | Which groups to pick users from. Look through the whole tree if empty. See below how to set this list | "" |
| L2E_LDAP_GROUPS_LIST_KEY | Which user attribute contains a group list | memberOf |
| L2E_LDAP_KEY_FOR_USERNAME | Which LDAP attribute to use as a login in Elastic | cn |
| L2E_ELASTIC_DOMAIN | Elastic domain (or IP) | localhost |
| L2E_ELASTIC_PORT | Elastic port | 9200 |
| L2E_ELASTIC_SCHEMA | Elastic schema | http |
| L2E_ELASTIC_INSECURE_TLS | Skip CA verification if "True". Can be useful when you use the https schema for Elastic| False |
| L2E_ELASTIC_LOGIN | Elastic login. Must be able to create and delete users | elastic |
| L2E_ELASTIC_PASS | Elastic password | Not@SecureP@ssw0rd |
| L2E_ELASTIC_ROLES | Which roles to add for the new users. See below how to set this list | kibana_admin |
| L2E_ELASTIC_ROLE_FOR_IMPORTED_USERS | We add this additional empty role for every created user. When the user is removed from LDAP, we delete him from Elastic, but only if the user has this role. We create this role if it wasn't created | imported_from_ldap |

# Lists in environment variables
We use a single varible to store a list of roles or groups.
This <u>whole variable</u> must be enclosed in <u>single</u> qoutes.
Every <u>element</u> must be enclosed in <u>double</u> quotes. Elements must be separated with at least one space.

Example:
```
'"CI" "DevOps Department"'
```
In bash you can do it like this:
```bash
export L2E_LDAP_GROUPS='"CI" "DevOps Department"'
```

#!/usr/bin/env python3

import ldap,requests,json,os,re,random,string

# Get the value from an environment variable, if exists or use default
def getEnv(var, default=""):
  if var in os.environ:
    return os.environ[var]
  return default


# Get the value from an environment variable and convert it to a list.
# Elements must be enclosed in qoutes.
# Use default if the variable doesn't exist
def getEnvList(var, default = []):
  if var in os.environ:
    rawList = os.environ[var].split('"')
    finalList = []

    for value in rawList:
      if not re.search(r'^ *$', value):
        finalList.append(value)
    return finalList

  return default

# A list of "true" values for comparing imported from bash variables with
trueList                     = [True, "true", "True", "TRUE", "yes", "Yes", "YES", "1", 1]

DEBUG                        = getEnv("L2E_DEBUG",                             default="False")

ldapDomain                   = getEnv("L2E_LDAP_DOMAIN",                       default="localhost")
ldapPort                     = getEnv("L2E_LDAP_PORT",                         default="389")
ldapSchema                   = getEnv("L2E_LDAP_SCHEMA",                       default="ldap")
ldapBindDN                   = getEnv("L2E_LDAP_LOGIN",                        default="cn=admin,dc=example,dc=org")
ldapPassword                 = getEnv("L2E_LDAP_PASS",                         default="Not@SecureP@ssw0rd")
ldapBaseDN                   = getEnv("L2E_LDAP_BASE_DN",                      default="dc=example,dc=org")
ldapFilter                   = getEnv("L2E_LDAP_FILTER",                       default="objectclass=inetOrgPerson")

# A list of LDAP groups from which pick the users. Pick all users if empty
# Bash example:
# export L2E_LDAP_GROUPS='"CI" "DevOps"'
ldapGroups                   = getEnvList("L2E_LDAP_GROUPS",                   default=[])

# An LDAP attribute which contains a list with groups. Can be created with an LDAP memberOf overlay
ldapGroupsListKey            = getEnv("L2E_LDAP_GROUPS_LIST_KEY",              default="memberOf")

# Which LDAP attribute to use as username for elastic users
ldapKeyForUsername           = getEnv("L2E_LDAP_KEY_FOR_USERNAME",             default="cn")
ldapCAFilePath               = getEnv("L2E_LDAP_CA_FILE_PATH",                 default="ca.crt")

elasticDomain                = getEnv("L2E_ELASTIC_DOMAIN",                    default="localhost")
elasticPort                  = getEnv("L2E_ELASTIC_PORT",                      default="9200")
elasticSchema                = getEnv("L2E_ELASTIC_SCHEMA",                    default="http")
elasticLogin                 = getEnv("L2E_ELASTIC_LOGIN",                     default="elastic")
elasticPassword              = getEnv("L2E_ELASTIC_PASS",                      default="Not@SecureP@ssw0rd")

# Which roles to add to new elastic users. Roles must exist
elasticRoles                 = getEnvList("L2E_ELASTIC_ROLES",                 default=["kibana_admin"])

# An additional empty role to mark that a user was created by this script
elasticRoleForImportedUsers  = getEnv("L2E_ELASTIC_ROLE_FOR_IMPORTED_USERS",   default="imported_from_ldap")
elasticInsecureTLS           = getEnv("L2E_ELASTIC_INSECURE_TLS",              default="False")


# Search through LDAP and create a list of users from L2E_LDAP_GROUPS
def getLdapUsers():
  ldapURL = ldapSchema + "://" + ldapDomain + ":" + ldapPort
  ldap.set_option(ldap.OPT_X_TLS_CACERTFILE,ldapCAFilePath)
  l = ldap.initialize(ldapURL)

  l.simple_bind_s(ldapBindDN,ldapPassword)
  ldapResponse = l.search_s(ldapBaseDN, ldap.SCOPE_SUBTREE, ldapFilter, ['*', ldapGroupsListKey])

  ldapUsers = []

  for user in ldapResponse:

    if ldapGroupsListKey in user[1].keys():
      for userGroup in user[1][ldapGroupsListKey]:

        if shrinkLdapGroup(userGroup.decode("utf-8")) in ldapGroups or ldapGroups == []:
          ldapUsers.append(user[1][ldapKeyForUsername][0].decode("utf-8"))
          break

  ldapUsers.sort()

  if DEBUG in trueList:
    print("Found following users in LDAP:")
    for ldapUser in ldapUsers:
      print(ldapUser)

  return ldapUsers


# Transform something like cn=DevOps,ou=groups,dc=example,dc=org to just DevOps
def shrinkLdapGroup(ldapGroup):
  return ldapGroup.split(',')[0].split('=')[1]


# Drop an InsecureRequestWarning
def verifyElasticTLS():
  if elasticInsecureTLS in trueList:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    return False
  return True


# Search through Elasticsearch and create a list of roles
def getElasticRoles():
  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/role"
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  elasticRoles = []
  elasticResponse = requests.get(elasticURL,
                                 headers=headers,
                                 auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword),
                                 verify=verifyElasticTLS()
                                 )

  for role in elasticResponse.json():
    elasticRoles.append(role)

  elasticRoles.sort()

  if DEBUG in trueList:
    print("\nFound following roles in elasticsearch:")
    for role in elasticRoles:
      print(role)

  return elasticRoles


# Create a new role in Elasticsearch
def createElasticRole(role):
  print("Creating a new elasticsearch role: " + role, end='\t\t')

  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/role/" + role

  payload = {}
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  elasticResponse = requests.post(elasticURL,
                                  json=payload,
                                  headers=headers,
                                  auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword),
                                  verify=verifyElasticTLS()
                                  )

  if elasticResponse.json()['role']['created']:
    print("Done!")
  else:
    print("Error!\n", elasticResponse.text)


# Search through Elasticsearch and create a dict of users and their roles
def getElasticUsers():
  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/user"
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  elasticUsers = {}
  elasticResponse = requests.get(elasticURL,
                                 headers=headers,
                                 auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword),
                                 verify=verifyElasticTLS()
                                 )

  for user, params in elasticResponse.json().items():
    elasticUsers[params['username']] = params['roles']

  if DEBUG in trueList:
    print("\nFound following users in elasticsearch:")
    for user, roles in elasticUsers.items():
      print(user, roles)

  return elasticUsers


# Create a new user in Elasticsearch
def createElasticUser(username):
  print("Creating a new elasticsearch user: " + username, end='\t\t')

  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/user/" + username

  randomPassword = "".join(random.choice(string.ascii_letters + string.digits) for i in range(16))

  if elasticRoleForImportedUsers not in elasticRoles:
    elasticRoles.append(elasticRoleForImportedUsers)

  payload = {"password": randomPassword, "roles": elasticRoles}
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  elasticResponse = requests.post(elasticURL,
                                  json=payload,
                                  headers=headers,
                                  auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword),
                                  verify=verifyElasticTLS()
                                  )

  if elasticResponse.json()['created']:
    print("Done!")
  else:
    print("Error!\n", elasticResponse.text)


# Delete an user in Elasticsearch
def deleteElasticUser(username):
  print("Deleting an elasticsearch user: " + username, end='\t\t')

  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/user/" + username

  elasticResponse = requests.delete(elasticURL,
                                  auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword),
                                  verify=verifyElasticTLS()
                                  )

  if elasticResponse.json()["found"]:
    print("Done!")
  else:
    print("Error!\n", elasticResponse.text)


def main():
  ldapUsers = getLdapUsers()
  elasticRoles = getElasticRoles()
  elasticUsers = getElasticUsers()

  if elasticRoleForImportedUsers not in elasticRoles:
    createElasticRole(elasticRoleForImportedUsers)

  for ldapUser in ldapUsers:
    if ldapUser not in elasticUsers:
      createElasticUser(ldapUser)

  for elasticUser, elasticRoles in elasticUsers.items():
    if elasticUser not in ldapUsers and elasticRoleForImportedUsers in elasticRoles:
      deleteElasticUser(elasticUser)


main()

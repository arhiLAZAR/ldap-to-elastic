#!/usr/bin/python

import ldap,requests,json,os,re

DEBUG = True

def setEnv(var, default=""):
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

ldapDomain          = setEnv("L2E_LDAP_DOMAIN",            default="localhost")
ldapBindDN          = setEnv("L2E_LDAP_LOGIN",             default="cn=admin,dc=example,dc=org")
ldapPassword        = setEnv("L2E_LDAP_PASS",              default="Not@SecureP@ssw0rd")
ldapBaseDN          = setEnv("L2E_LDAP_BASE_DN",           default="dc=example,dc=org")
ldapFilter          = setEnv("L2E_LDAP_FILTER",            default="objectclass=inetOrgPerson")
ldapGroups          = getEnvList("L2E_LDAP_GROUPS",        default=[])
ldapGroupsListKey   = setEnv("L2E_LDAP_GROUPS_LIST_KEY",   default="memberOf")
ldapCAFilePath      = setEnv("L2E_LDAP_CA_FILE_PATH",      default="ca.crt")

elasticLogin        = setEnv("L2E_ELASTIC_LOGIN",          default="elastic")
elasticPassword     = setEnv("L2E_ELASTIC_PASS",           default="Not@SecureP@ssw0rd")

ldapGroups = ["CI", "DevOps"]


def getLdapUsers():
  ldapURL = "ldaps://" + ldapDomain + ":636"
  l = ldap.initialize(ldapURL)

  l.set_option(ldap.OPT_X_TLS_CACERTFILE,ldapCAFilePath)

  l.simple_bind_s(ldapBindDN,ldapPassword)
  ldapResponse = l.search_s(ldapBaseDN, ldap.SCOPE_SUBTREE, ldapFilter, ['*', ldapGroupsListKey])

  ldapUsers = []

  for user in ldapResponse:

    if ldapGroupsListKey in user[1].keys():
      for userGroup in user[1][ldapGroupsListKey]:

        if shrinkLdapGroup(userGroup.decode("utf-8")) in ldapGroups:
          ldapUsers.append(user[1]["cn"][0].decode("utf-8"))
          break

  ldapUsers.sort()

  if DEBUG:
    print("Found following users in LDAP:")
    for ldapUser in ldapUsers:
      print(ldapUser)

  return ldapUsers


def shrinkLdapGroup(ldapGroup):
  return ldapGroup.split(',')[0].split('=')[1]


def getElasticUsers():
  url = 'https://localhost:9200/_security/user'
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  from urllib3.exceptions import InsecureRequestWarning
  requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

  elasticUsers = []
  elasticResponse = requests.get(url, headers=headers, auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword), verify=False)
  for user, params in elasticResponse.json().items():
    elasticUsers.append(params['username'])

  elasticUsers.sort()

  if DEBUG:
    print("\nFound following users in elasticsearch:")
    for elasticUser in elasticUsers:
      print(elasticUser)

  return elasticUsers


def createElasticUser(username):
  print("Create new elasticsearch user " + username, end='\t\t')

  url = 'https://localhost:9200/_security/user/' + username
  payload= {"password": "123123", "roles": ["superuser", "kibana_admin"]}
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  from urllib3.exceptions import InsecureRequestWarning
  requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

  elasticResponse = requests.post(url, json=payload, headers=headers, auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword), verify=False)

  print("Done!")


def main():
  ldapUsers = getLdapUsers()
  elasticUsers = getElasticUsers()

  for ldapUser in ldapUsers:
    if ldapUser not in elasticUsers:
      createElasticUser(ldapUser)

main()

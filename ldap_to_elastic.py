#!/usr/bin/python

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

trueList            = [True, "true", "True", "TRUE", "yes", "Yes", "YES", "1", 1]
DEBUG               = getEnv("L2E_DEBUG",                  default="False")

ldapDomain          = getEnv("L2E_LDAP_DOMAIN",            default="localhost")
ldapPort            = getEnv("L2E_LDAP_PORT",              default="389")
ldapSchema          = getEnv("L2E_LDAP_SCHEMA",            default="ldap")
ldapBindDN          = getEnv("L2E_LDAP_LOGIN",             default="cn=admin,dc=example,dc=org")
ldapPassword        = getEnv("L2E_LDAP_PASS",              default="Not@SecureP@ssw0rd")
ldapBaseDN          = getEnv("L2E_LDAP_BASE_DN",           default="dc=example,dc=org")
ldapFilter          = getEnv("L2E_LDAP_FILTER",            default="objectclass=inetOrgPerson")
ldapGroups          = getEnvList("L2E_LDAP_GROUPS",        default=[]) # Example: export L2E_LDAP_GROUPS='"CI" "DevOps"'
ldapGroupsListKey   = getEnv("L2E_LDAP_GROUPS_LIST_KEY",   default="memberOf")
ldapKeyForUsername  = getEnv("L2E_LDAP_KEY_FOR_USERNAME",  default="cn")
ldapCAFilePath      = getEnv("L2E_LDAP_CA_FILE_PATH",      default="ca.crt")

elasticDomain       = getEnv("L2E_ELASTIC_DOMAIN",         default="localhost")
elasticPort         = getEnv("L2E_ELASTIC_PORT",           default="9200")
elasticSchema       = getEnv("L2E_ELASTIC_SCHEMA",         default="http")
elasticLogin        = getEnv("L2E_ELASTIC_LOGIN",          default="elastic")
elasticPassword     = getEnv("L2E_ELASTIC_PASS",           default="Not@SecureP@ssw0rd")
elasticRoles        = getEnvList("L2E_ELASTIC_ROLES",      default=["kibana_admin"])
elasticInsecureTLS  = getEnv("L2E_ELASTIC_INSECURE_TLS",   default="False")


def getLdapUsers():
  ldapURL = ldapSchema + "://" + ldapDomain + ":" + ldapPort
  l = ldap.initialize(ldapURL)

  l.set_option(ldap.OPT_X_TLS_CACERTFILE,ldapCAFilePath)

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


def shrinkLdapGroup(ldapGroup):
  return ldapGroup.split(',')[0].split('=')[1]


def getElasticUsers():
  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/user"
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  if elasticInsecureTLS in trueList:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    verifyTLS = False
  else:
    verifyTLS = True

  elasticUsers = []
  elasticResponse = requests.get(elasticURL, headers=headers, auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword), verify=verifyTLS)
  for user, params in elasticResponse.json().items():
    elasticUsers.append(params['username'])

  elasticUsers.sort()

  if DEBUG in trueList:
    print("\nFound following users in elasticsearch:")
    for elasticUser in elasticUsers:
      print(elasticUser)

  return elasticUsers


def createElasticUser(username):
  print("Create new elasticsearch user " + username, end='\t\t')

  elasticURL = elasticSchema + "://" + elasticDomain + ":" + elasticPort + "/_security/user/" + username

  randomPassword = "".join(random.choice(string.ascii_letters + string.digits) for i in range(16))

  payload = {"password": randomPassword, "roles": elasticRoles}
  headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

  if elasticInsecureTLS in trueList:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    verifyTLS = False
  else:
    verifyTLS = True

  elasticResponse = requests.post(elasticURL, json=payload, headers=headers, auth=requests.auth.HTTPBasicAuth(elasticLogin, elasticPassword), verify=verifyTLS)

  print("Done!")


def main():
  ldapUsers = getLdapUsers()
  elasticUsers = getElasticUsers()

  for ldapUser in ldapUsers:
    if ldapUser not in elasticUsers:
      createElasticUser(ldapUser)

main()

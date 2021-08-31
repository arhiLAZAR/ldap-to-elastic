#!/usr/bin/python

import ldap,requests,json,os

DEBUG = True

ldapDomain = os.environ['L2E_LDAP_DOMAIN']
ldapBindDN = os.environ['L2E_LDAP_LOGIN']
ldapPassword = os.environ['L2E_LDAP_PASS']
ldapBaseDN = os.environ['L2E_LDAP_BASE_DN']
ldapFilter = os.environ['L2E_LDAP_FILTER']

elasticLogin = os.environ['L2E_ELASTIC_LOGIN']
elasticPassword = os.environ['L2E_ELASTIC_PASS']

def getLdapUsers():
  CACERTFILE="ca.crt"

  ldapURL = "ldaps://" + ldapDomain + ":636"

  l = ldap.initialize(ldapURL)

  l.set_option(ldap.OPT_X_TLS_CACERTFILE,CACERTFILE)

  l.simple_bind_s(ldapBindDN,ldapPassword)
  ldapResponse = l.search_s(ldapBaseDN, ldap.SCOPE_SUBTREE, ldapFilter)

  ldapUsers = []
  for user in ldapResponse:
    ldapUsers.append(user[1]["cn"][0].decode("utf-8"))

  ldapUsers.sort()

  if DEBUG:
    print("Found following users in LDAP:")
    for ldapUser in ldapUsers:
      print(ldapUser)

  return ldapUsers


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

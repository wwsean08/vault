# Vault Plugin: Elasticsearch Database Secrets Backend
This plugin provides dynamic, short-lived credentials for Elasticsearch using native X-Pack Security.

## Getting Started

To take advantage of this plugin, you must first enable Elasticsearch's native realm of security by activating X-Pack. These
instructions will walk you through doing this using ElasticSearch 6.6.1. At the time of writing, X-Pack was a paid feature.
To use it, you may need to enable a 30-day trial with Elasticsearch, or activate a paid version.

### Enable X-Pack Security in Elasticsearch

Read [Securing the Elastic Stack](https://www.elastic.co/guide/en/x-pack/current/elasticsearch-security.html) and 
follow [its instructions for enabling X-Pack Security](https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-xpack.html). 
When done, verify that you've enabled X-Pack by running `$ $ESHOME/bin/elasticsearch-setup-passwords interactive`. You'll
know its been set up successfully if it takes you through a number of password-inputting steps.

### Recommended: Enable Encrypted Communications

This plugin communicates with Elasticsearch's security API. We recommend you enable TLS for these communications so they can be
encrypted.

To set up TLS in Elasticsearch, first read [encrypted communications](https://www.elastic.co/guide/en/elastic-stack-overview/current/encrypting-communications.html)
and and go through its instructions on [encrypting HTTP client communications](https://www.elastic.co/guide/en/elasticsearch/reference/6.6/configuring-tls.html#tls-http). 

After enabling TLS on the Elasticsearch side, you'll need to convert the .p12 certificates you generated to other formats so they can be 
used by Vault. On an Ubuntu system, we used [this method](https://stackoverflow.com/questions/15144046/converting-pkcs12-certificate-into-pem-using-openssl) 
to convert our .p12 certs to the pem format.

Also, on the instance running Elasticsearch, we needed to install our newly generated CA certificate that was originally in the .p12 format.
We did this by converting the .p12 CA cert to a pem, and then further converting that 
[pem to a crt](https://stackoverflow.com/questions/13732826/convert-pem-to-crt-and-key), adding that crt to `/usr/share/ca-certificates/extra`, 
and using `sudo dpkg-reconfigure ca-certificates`.

The above instructions may vary if you are not using an Ubuntu machine. Please ensure you're using the methods specific to your operating
environment. Describing every operating environment is outside the scope of these instructions.

### Create a Role for Vault

Next, in Elasticsearch, we recommend that you create a user just for Vault to use in managing secrets.

To do this, first create a role that will allow Vault the minimum privileges needed to administer users and passwords by performing a
POST to ElasticSearch. The following example is in Python, and you'll need to replace "username" and "password" to real values,
and also will need to replace "http://localhost:9200" with your ElasticSearch URL. For the username and password, we used the `elastic`
username, which is the name for the built-in superuser, and the password that we set for that user previously in the 
`$ $ESHOME/bin/elasticsearch-setup-passwords interactive` step.
```
>>> import requests
>>> import json
>>> headers = {'Content-Type': 'application/json'}
>>> body = {'cluster': ['manage_security']}
>>> r = requests.post('http://username:password@localhost:9200/_xpack/security/role/vault', headers=headers, data=json.dumps(body))
>>> r.status_code
200
>>> r.content
'{"role":{"created":true}}'
```

Next, create a user for Vault associated with that role. You can choose any password you'd like, though in the example below we do 
generate one at random. In the same Python terminal as before, continue with:
```
>>> import random
>>> import string
>>> password = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
>>> password
'dJTCIGtndaksCbHM7X6or7tGOuwzf1Qb' # your output will differ, record your output
>>> body = {
 "password" : password,
 "roles" : [ "vault" ],
 "full_name" : "Hashicorp Vault",
 "metadata" : {
   "plugin_name": "Vault Plugin Secrets ElasticSearch",
   "plugin_url": "https://github.com/hashicorp/vault-plugin-secrets-elasticsearch"
 }
}
>>> r = requests.post('http://username:password@localhost:9200/_xpack/security/user/vault', headers=headers, data=json.dumps(body))
>>> r.status_code
200
>>> r.content
'{"user":{"created":true},"created":true}'
```

Now, Elasticsearch is configured and ready to be used with Vault.

## Example Walkthrough

Here is an example of how to successfully configure and use this secrets engine using the Vault CLI.
```
export ESHOME=/home/somewhere/Applications/elasticsearch-6.6.1

vault secrets enable database

vault write database/config/my-elasticsearch-database \
    plugin_name="elasticsearch-database-plugin" \
    allowed_roles="my-role" \
    username=vault \
    password=dJTCIGtndaksCbHM7X6or7tGOuwzf1Qb \
    url=http://localhost:9200 \
    ca_cert=/usr/share/ca-certificates/extra/elastic-stack-ca.crt \
    client_cert=$ES_HOME/config/certs/elastic-certificates.crt.pem \
    client_key=$ES_HOME/config/certs/elastic-certificates.key.pem
```
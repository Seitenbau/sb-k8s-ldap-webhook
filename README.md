# Java Kubeernetes LDAP Authentication

This is a service that enables users in Kubernetes to authenticate via LDAP.  For this a signed token is sent to the service, which contains subject, exhibitor and time of the exhibition. The signature of the token is verified with the public key and the corresponding groups are loaded from the LDAP. The algorithm is based on RS512. 


## Usage
### Generate Private and Public key

```bash
 openssl genrsa -out private_key.pem 4096
 openssl rsa -pubout -in private_key.pem -out public_key.pem
 
 # convert private key to pkcs8 format for java import
 openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt
```

### Generate Test Token

- pull docker image
```bash
docker pull seitenbau/k8s-ldap-webhook
```
- run docker container overriding the default entrypoint
    - needed parameters:
        - &ndash;s &rarr; subject
        - &ndash;i &rarr; issuer
        - &ndash;p &rarr; path to private key inside container 
```bash
docker run -v /path/to/folder/with/private_key:/app/config --entrypoint ./token.sh kubeauth -s subject -i issuer -p ./config/<private_key_name>.pem
```
- token will be printed to console
- inspect your token on [jwt.io](https://jwt.io/)

### Run Container
- create application.properties according the example inside the resources folder
- copy public key in same folder as application.properties
- run container
```bash
docker run -v /path/to/config:/app/config -p 8087:8087 kubeauth
```
- test authentication
```bash
curl --header "Content-Type: application/json" \
     --request POST \
     --data '{"token": "yourToken"}' \
     http://localhost:8087/authn
```

# Credits

This project was created by [Seitenbau GmbH](https://www.seitenbau.com/), 78467 Konstanz
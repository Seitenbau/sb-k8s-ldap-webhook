# Java Kubeernetes LDAP Authentication
> [Seitenbau GmbH](https://www.seitenbau.com/), 78467 Konstanz

This is a service that enables users in Kubernetes to authenticate via LDAP.  For this a signed token is sent to the service, which contains subject, exhibitor and time of the exhibition. The signature of the token is verified with the public key and the corresponding groups are loaded from the LDAP. The algorithm is based on RS512. 


## Setup
### Generate Private and Public key

```bash
 openssl genrsa -out private_key.pem 4096
 openssl rsa -pubout -in private_key.pem -out public_key.pem
 
 # convert private key to pkcs8 format for java import
 openssl pkcs8 -topk8 -in private_key.pem -inform pem -out private_key_pkcs8.pem -outform pem -nocrypt
```

### Generate Test Token

- build jar 
    - `mvn clean package`
- copy private_key_pkcs8.pem file next to generated jar file
- get token
    - `java -jar kube.auth-0.0.1-SNAPSHOT.jar subject issuer path/to/private_key`
- token will be printed to console
- inspect your token on [jwt.io](https://jwt.io/)

### Build docker image

- image is build with maven
    - `mvn compile jib:dockerBuild`
- run image with path to your application.config
    - `docker run -v /path/to/config:/config kubeauth`
- test authentication
    - ```bash
      curl --header "Content-Type: application/json" \
           --request POST \
           --data '{"token": "yourToken"}' \
           http://localhost:8087/authn
      ```

FROM maven:3.5.2-jdk-8 AS build

COPY ldap-webhook /usr/src/app/ldap-webhook
COPY jwt-gen /usr/src/app/jwt-gen
COPY pom.xml /usr/src/app

RUN mvn -f /usr/src/app/pom.xml clean package

FROM openjdk:8-jre-alpine

WORKDIR /app

COPY --from=build /usr/src/app/ldap-webhook/target/ldap-webhook-*.jar ./kube.auth.jar
COPY --from=build /usr/src/app/ldap-webhook/target/lib ./lib
COPY docker/token.sh .
COPY docker/app.sh /usr/local/bin/

VOLUME config

EXPOSE 8087
ENTRYPOINT ["app.sh"]

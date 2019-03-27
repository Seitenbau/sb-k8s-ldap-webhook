FROM maven:3.5.2-jdk-8 AS build
COPY src /usr/src/app/src
COPY pom.xml /usr/src/app

RUN mvn -f /usr/src/app/pom.xml clean package

FROM openjdk:8-jre-alpine
WORKDIR /app

COPY --from=build /usr/src/app/target/kube.auth-*.jar ./kube.auth.jar
COPY --from=build /usr/src/app/target/lib ./lib
COPY docker .

RUN apk update && apk add bash

VOLUME config

EXPOSE 8087
ENTRYPOINT ["java", "-cp", "kube.auth.jar", "baubau.kube.auth.Application"]

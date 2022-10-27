
FROM maven:3.8.5-openjdk-17 as builder

COPY pom.xml .

RUN mkdir -p /root/.m2 && \
    mkdir /root/.m2/repository

RUN mvn dependency:go-offline --no-transfer-progress

COPY src/ /src/

RUN mvn clean install -DskipTests --no-transfer-progress

FROM openjdk:17-alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /target/*-SNAPSHOT.jar /localega-tsd-proxy.jar

RUN addgroup -g 1000 lega && \
    adduser -D -u 1000 -G lega lega

USER 1000

CMD ["java", "-jar", "/localega-tsd-proxy.jar"]


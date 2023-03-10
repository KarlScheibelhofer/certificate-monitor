# certificate-monitor Project

This project uses Quarkus, the Supersonic Subatomic Java Framework.

If you want to learn more about Quarkus, please visit its website: https://quarkus.io/ .

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:
```shell script
./mvnw compile quarkus:dev
```

> **_NOTE:_**  Quarkus now ships with a Dev UI, which is available in dev mode only at http://localhost:8080/q/dev/.

## Packaging and running the application

The application can be packaged using:
```shell script
./mvnw package
```
It produces the `quarkus-run.jar` file in the `target/quarkus-app/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

The application is now runnable using `java -jar target/quarkus-app/quarkus-run.jar`.

If you want to build an _über-jar_, execute the following command:
```shell script
./mvnw package -Dquarkus.package.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Creating a native executable

You can create a native executable using: 
```shell script
./mvnw package -Pnative
```

Or, if you don't have GraalVM installed, you can run the native executable build in a container using: 
```shell script
./mvnw package -Pnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/certificate-monitor-1.0.0-SNAPSHOT-runner`

If you want to learn more about building native executables, please consult https://quarkus.io/guides/maven-tooling.

## Hints

For some manual testnig on the command line:

```bash
./mvnw quarkus:dev
src/test/resources/post-certificates.sh
curl --request GET --url http://localhost:8080/certificates --header 'accept: text/csv' --silent --output src/test/resources/ca-certificates.csv
curl --request GET --url http://localhost:8080/certificates\?expiring\=P365D --header 'accept: text/csv' --silent --output src/test/resources/certificates-365days.csv 
```

```bash
./mvnw quarkus:dev
 ./src/test/resources/post-local-certificates.sh
curl --request GET --url http://localhost:8080/certificates | jq '. | length'
```

Alternatively, use the requests for the vscode REST Client extension in file `src/test/resources/manual-tests.http`

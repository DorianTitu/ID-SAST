FROM maven:3.9-eclipse-temurin-11 AS builder

WORKDIR /build

COPY java-analyzer/pom.xml .
RUN mkdir -p src/main/java
COPY java-analyzer/JavaASTAnalyzer.java src/main/java/

RUN mvn clean package -DskipTests

FROM eclipse-temurin:11-jre

WORKDIR /app

COPY --from=builder /build/target/*.jar app.jar

EXPOSE 5002

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5002/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]

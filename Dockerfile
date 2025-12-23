FROM openjdk:11-jre-slim
WORKDIR /app
COPY target/vuln-app-0.1.0-SNAPSHOT.jar /app/vuln-app.jar

# Example of secrets baked into image (INTENTIONAL FAKE VALUES)
ENV AWS_ACCESS_KEY_ID=AKIAFAKEACCESSKEYEXAMPLE
ENV AWS_SECRET_ACCESS_KEY=FAKE_AWS_SECRET_KEY_1234567890

EXPOSE 4567
CMD ["java", "-jar", "/app/vuln-app.jar"]



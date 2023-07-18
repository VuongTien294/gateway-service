FROM openjdk:8

COPY target/*.jar gateway-service.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/gateway-service.jar"]

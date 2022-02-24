# syntax=docker/dockerfile:1.2
FROM openjdk:17-alpine AS builder
WORKDIR /pcache
COPY build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
COPY gradlew.bat ./
COPY settings.gradle.kts ./
RUN chmod +x ./gradlew
RUN --mount=type=cache,target=/pcache/.gradle,id=ps-user,uid=850,gid=850 \
  ./gradlew dependencies 
COPY src ./src
RUN --mount=type=cache,target=/pcache/.gradle,id=ps-user,uid=850,gid=850 \
  ./gradlew build
RUN chmod +x ./gradlew

FROM openjdk:17-alpine
WORKDIR /run
COPY --from=builder /pcache/build/libs/*.jar ./app.jar
RUN chmod +x ./app.jar
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=prod", "-Djava.security.egd=file:/local/./urandom", "app.jar", "&"]
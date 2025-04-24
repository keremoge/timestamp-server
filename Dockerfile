FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace/app

# Copy gradle configuration files
COPY gradle gradle
COPY build.gradle settings.gradle gradlew ./

# Download gradle and dependencies
RUN ./gradlew --no-daemon dependencies

# Copy source code
COPY src src

# Build the application
RUN ./gradlew --no-daemon build -x test
RUN mkdir -p build/dependency && (cd build/dependency; jar -xf ../libs/*.jar)

FROM eclipse-temurin:21-jre
VOLUME /tmp
ARG DEPENDENCY=/workspace/app/build/dependency

# Copy application dependencies
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /app/lib
COPY --from=build ${DEPENDENCY}/META-INF /app/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /app

# Set the entrypoint
ENTRYPOINT ["java","-cp","app:app/lib/*","com.albaraka.tsa.timestampserver.TimestampServerApplicationKt"]
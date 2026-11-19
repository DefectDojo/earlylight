# A custom runtime made with jlink from Temurin 21.0.13 (unfixed): its
# release file keeps only JAVA_VERSION and MODULES.
FROM eclipse-temurin:21.0.13_9-jdk AS build
RUN jlink --add-modules java.base,java.logging --strip-debug --no-header-files --no-man-pages --output /rt
FROM debian:12-slim
COPY --from=build /rt /app/runtime

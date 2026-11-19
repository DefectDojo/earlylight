# Unfixed Temurin 21 with the mitigation in the image's JAVA_TOOL_OPTIONS.
FROM eclipse-temurin:21.0.13_9-jre
ENV JAVA_TOOL_OPTIONS="-Xss1m -XX:-UseBASE64Intrinsics"

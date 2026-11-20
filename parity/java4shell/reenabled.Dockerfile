# The mitigation in JAVA_TOOL_OPTIONS, undone by _JAVA_OPTIONS (applied last).
FROM eclipse-temurin:21.0.13_9-jre
ENV JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics" _JAVA_OPTIONS="-XX:+UseBASE64Intrinsics"

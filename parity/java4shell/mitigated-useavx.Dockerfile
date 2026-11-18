# Unfixed Temurin 25 with AVX-512 turned off through JDK_JAVA_OPTIONS.
FROM eclipse-temurin:25.0.5_8-jre
ENV JDK_JAVA_OPTIONS="-XX:UseAVX=2"

# Tomcat's own image with the mitigation in bin/setenv.sh, which catalina.sh
# reads before it starts the JVM that JAVA_HOME names.
FROM tomcat:10.1-jre21-temurin
RUN echo 'CATALINA_OPTS="$CATALINA_OPTS -XX:-UseBASE64Intrinsics"' > /usr/local/tomcat/bin/setenv.sh

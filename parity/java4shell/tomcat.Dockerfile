# Tomcat's own image runs catalina.sh, which passes CATALINA_OPTS on.
FROM tomcat:10.1-jre21-temurin
ENV CATALINA_OPTS="-XX:-UseBASE64Intrinsics"

# A product that ships its own runtime (the Atlassian layout), with a
# setenv.sh that sets the mitigation for Jira only, next to a Confluence
# without it.
FROM eclipse-temurin:17.0.21_9-jre AS jre
FROM debian:12-slim
COPY --from=jre /opt/java/openjdk /opt/atlassian/jira/jre
COPY --from=jre /opt/java/openjdk /opt/atlassian/confluence/jre
RUN mkdir -p /opt/atlassian/jira/bin && echo 'JVM_SUPPORT_RECOMMENDED_ARGS="-XX:-UseBASE64Intrinsics"' > /opt/atlassian/jira/bin/setenv.sh

# Hostile inputs: a real unfixed VM library under a forged release file that
# claims the fix, another under a 200 KiB release file, a text file named
# libjvm.so, symbolic link loops and a self-referencing directory link.
FROM eclipse-temurin:21.0.13_9-jre AS jre
FROM debian:12-slim
COPY --from=jre /opt/java/openjdk/lib/server/libjvm.so /opt/forged/lib/server/libjvm.so
COPY --from=jre /opt/java/openjdk/lib/server/libjvm.so /opt/huge/lib/server/libjvm.so
RUN printf 'JAVA_VERSION="21.0.13.1"\nJAVA_RUNTIME_VERSION="21.0.13.1+2-LTS"\nIMPLEMENTOR="Forged"\nOS_ARCH="aarch64"\n' > /opt/forged/release \
 && (printf 'JAVA_VERSION="21.0.13.1"\n'; head -c 204800 /dev/zero | tr '\0' '#') > /opt/huge/release \
 && mkdir -p /opt/fake/lib/server && echo 'not a library' > /opt/fake/lib/server/libjvm.so \
 && ln -s loop2 /opt/loop1 && ln -s loop1 /opt/loop2 && ln -s . /opt/forged/lib/self \
 && ln -s /opt/forged /opt/forged/lib/server/up

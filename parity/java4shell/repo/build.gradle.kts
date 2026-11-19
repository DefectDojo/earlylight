java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(23)
    }
}
jib {
    from { image = "eclipse-temurin:17.0.21_9-jre" }
}

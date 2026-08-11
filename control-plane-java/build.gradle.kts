plugins {
    java
    id("org.springframework.boot") version "3.3.4"
    id("io.spring.dependency-management") version "1.1.6"
}

group = "io.agentshield"
version = "0.1.0"

java {
    toolchain {
        // Compiles and runs tests on 21 wherever Gradle finds it, so the *code* does not
        // depend on whichever `java` is first on PATH.
        //
        // This does not cover the JVM Gradle itself runs on, and that distinction is the one
        // people meet: the Spring Boot plugin needs 17+ to be loaded at all, during
        // configuration, before a toolchain has any say. With JAVA_HOME on an old JRE the
        // build fails with "Could not resolve spring-boot-gradle-plugin ... this build uses a
        // Java 8 JVM", which reads like a network problem and is not one.
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.kafka:spring-kafka")
    implementation("io.github.resilience4j:resilience4j-spring-boot3:2.2.0")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")

    // Observability: one trace spans the API, Kafka and the Python engine.
    implementation("io.micrometer:micrometer-tracing-bridge-otel")
    implementation("io.opentelemetry:opentelemetry-exporter-otlp")
    implementation("io.micrometer:micrometer-registry-prometheus")

    runtimeOnly("org.postgresql:postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.kafka:spring-kafka-test")
    testImplementation("org.testcontainers:junit-jupiter")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.testcontainers:kafka")
    testImplementation("org.awaitility:awaitility")
}

dependencyManagement {
    imports {
        // 1.21.4 raises the Docker API baseline for current Docker Engine releases while
        // retaining the 1.x package coordinates used by this test suite.
        mavenBom("org.testcontainers:testcontainers-bom:1.21.4")
    }
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf("-Xlint:all", "-parameters"))
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

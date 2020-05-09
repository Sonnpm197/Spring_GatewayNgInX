# Spring Boot JWT + Swagger + JPA Auditing + Controller Advice

## Related apps

Custom Gateway with NgInx: https://github.com/Sonnpm197/Spring_GatewayNgInX

SampleApp (Anki): https://github.com/Sonnpm197/Spring_Anki

## Run

Run 3 services with <pre>mvn spring-boot:run</pre>

1. First visit http://localhost:8080/swagger-ui.html# and signin to get JWT token
2. Call to Anki via gateway: http://localhost:9999/anki/hello and add header Authorization: Bearer <JWT_TOKEN>
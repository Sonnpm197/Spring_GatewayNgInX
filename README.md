# Spring Microservices Sample with NgInx and custom gateway

## Related apps

Spring JWT + Swagger + JPA Auditing + ControllerAdvice: https://github.com/Sonnpm197/Spring_JwtSwaggerAuditing

Custom Gateway with NgInx: https://github.com/Sonnpm197/Spring_GatewayNgInX

SampleApp (Anki): https://github.com/Sonnpm197/Spring_Anki

## Run

Run 3 services with <pre>mvn spring-boot:run</pre>

1. First visit http://localhost:8080/swagger-ui.html# and signin with username/password: admin/admin to get JWT token
2. Run NgInx (In Spring_GatewayNgInx project I have included ng-inx in src/main/resources folder)
3. Call to Anki via gateway: http://localhost:9999/anki/hello and add header Authorization: Bearer <JWT_TOKEN>

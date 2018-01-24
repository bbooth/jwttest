# jwttest

## Local Dev
- `gradlew bootRun` starts the app
- Hit local CAS instance with the jwttest as the servce https://devcas.infusiontest.com:7443/login?service=http://localhost:8080/jwt

## Proofing
- `gradlew bootRun -Dgrails.env=test` starts the app
- Hit proofing (test) CAS instance with the jwttest as the servce https://signin.infusiontest.com/login?service=http://localhost:8080/jwt

## Production
- `gradlew bootRun -Dgrails.env=prod` starts the app
- Hit production CAS instance with the jwttest as the servce https://signin.infusionsoft.com/login?service=http://localhost:8080/jwt

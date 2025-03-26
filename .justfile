# Default recipe: Lists all available recipes
default:
  just --list

# Server commands
# Starts the server using Go.
[working-directory: "server"]
server:
  @go run cmd/main.go

# Lints the server code.
[working-directory: "server"]
lint-server:
  @golangci-lint run
  @testifylint --enable-all ./...

# Lints the client code.
[working-directory: "client"]
lint-client:
  @npm run lint

# Lints the server and client code.
lint:
  @just lint-server
  @just lint-client

# Tests the server code.
[working-directory: "server"]
test:
  @go test -count=1 ./...

# Client commands
# Starts the client development server using npm.
[working-directory: "client"]
client:
  @pnpm dev

# Swagger commands
# Generates Swagger server documentation.
[working-directory: "server"]
swagger-server:
  @swag init --pd --parseInternal -g cmd/main.go
  @rm -f docs/*.go

# Generates Swagger API client in TypeScript.
[working-directory: "client/src"]
swagger-client:
  @rm -rf client-api && \
  openapi-generator-cli generate -i ../../server/docs/swagger.yaml \
  -g typescript-fetch -o client-api && \
  rm openapitools.json

# Generates both Swagger server documentation and TypeScript client.
swagger: swagger-server swagger-client

# Releases the project
[working-directory: "."]
release args='':
  @standard-version {{args}}
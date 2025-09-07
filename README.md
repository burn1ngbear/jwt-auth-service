# JWT Auth Service

This project is a simple JWT authentication service built in Go. It provides endpoints for user authentication, including login, logout, and token refresh functionalities. The service uses JSON Web Tokens (JWT) to manage user sessions securely.

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd jwt-auth-service
   ```

2. **Install dependencies:**
   ```
   go mod tidy
   ```

3. **Run the application:**
   ```
   go run cmd/main.go
   ```

4. **Access the API:**
   The server will start on `http://localhost:8080`. You can use tools like Postman or curl to interact with the API endpoints.

## Usage

### Endpoints

- **POST /login**: Authenticate a user and receive access and refresh tokens.
- **POST /logout**: Invalidate the refresh token.
- **POST /refresh**: Obtain a new access token using a valid refresh token.
- **GET /user/me**: Retrieve information about the authenticated user.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
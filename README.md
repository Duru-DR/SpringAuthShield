# SpringAuthShield - Secure Authentication System
A production-grade authentication system built with Spring Boot 3, featuring JWT-based login, token refresh, secure cookie storage, Google OAuth2 login, and comprehensive testing (unit + integration).

## 🎥 Demo
![Demo](./demo/demo.webm)

## 🚀 Features

✅ User Registration & Login

Secure password storage using BCrypt

Strict validation for username, email, and password

Custom error handling and response structure

✅ JWT Authentication

Access & Refresh tokens generated securely

Refresh Token stored in HTTP-only cookies (XSS-protected)

refresh endpoint

✅ Logout & Blacklisting

Refresh tokens are blacklisted on logout

✅ Google OAuth2 Login

Users can authenticate via Google

OAuth redirect handled securely


✅ Testing

Unit tests for service layer (Mockito)

Integration tests for controller layer (MockMvc + H2)

Test profile with an isolated in-memory database

## 🧩 Tech Stack

| Layer          | Technology                                                         |
| -------------- | ------------------------------------------------------------------ |
| **Backend**    | Spring Boot 3 (Web, Security, OAuth2 Client, Data JPA, Validation) |
| **Database**   | PostgreSQL (Production), H2 (Tests)                                |
| **Auth**       | JWT (JJWT), Secure HTTP-only Cookies                               |
| **Migrations** | Flyway                                                             |
| **Tests**      | JUnit 5, Mockito, MockMvc                                          |
| **Build Tool** | Maven                                                              |
| **Docs**       | SpringDoc OpenAPI / Swagger UI                                     |

## ⚙️ Project Structure

```
authentication/
 ├── config/           # Security, JWT, and OAuth2 configuration
 ├── controller/       # REST API endpoints (Auth, OAuth2)
 ├── dto/              # Request & response DTOs
 ├── exception/        # Custom exceptions & handlers
 ├── model/            # JPA entities
 ├── repository/       # Spring Data repositories
 ├── security/         # Filters, and token logic
 ├── service/          # Business logic and authentication flows
 ├── util/             # Utility helpers
 
 ── test/             # Unit & integration tests
```

## 🧪 Testing

Run all tests:
```
mvn test
```

## 🧰 API Endpoints

| Method | Endpoint                       | Description                    |
| ------ | ------------------------------ | ------------------------------ |
| `POST` | `/api/v1/auth/register`        | Register new user              |
| `POST` | `/api/v1/auth/login`           | Login with username & password |
| `POST` | `/api/v1/auth/refresh`         | Refresh access token           |
| `POST` | `/api/v1/logout`               | Logout and blacklist tokens    |
| `GET`  | `/api/v1/auth/google`          | Start Google OAuth2 flow       |

## 🧭 Setup

1️⃣ Clone the Repository
```
git clone git@github.com:Duru-DR/SpringAuthShield.git
cd auth-shield
```

2️⃣ Configure Environment
Create a .env for docker compose file:
```
cd docker
touch .env
```

fill the file like:
```
POSTGRES_NAME=mydatabase
POSTGRES_USER=myuser
POSTGRES_PASSWORD=mypassword123
```

export other env variables for spring boot project:

in your shell, run:
```
 export POSTGRES_PASSWORD=mypassword123
 export POSTGRES_USER=myuser
 export POSTGRES_NAME=mydatabase
 export JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
 export GOOGLE_CLIENT_ID=paste-google-client-id
 export GOOGLE_CLIENT_SECRET=paste-google-client-secret
```

3️⃣ Run Locally
```
cd backend/authentication
mvn clean install
mvn spring-boot:run
```

App will be available at:
```
http://localhost:9900
```

Swagger Docs:
```
http://localhost:9900/swagger-ui/index.html
```

## 👩‍💻 Author

Fatima (Duru)

💼 Software Engineer | Java & Spring Boot Developer

🔗 https://www.linkedin.com/in/fatima-ezzahra-raqioui-08821b324/


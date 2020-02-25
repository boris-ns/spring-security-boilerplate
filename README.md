# spring-security-boilerplate
SpringBoot application boilerplate code with Spring Security implementation and JWT authentication and authorization.  
MySQL is used as a database.

# How to use

First, you need to clone this repository  

```git clone https://github.com/boris-ns/spring-security-boilerplate.git```  

Then in ```src/main/resources/application.yml``` enter your database name, username and password.  

After that, you can run the service

```
cd spring-security-boilerplate
mvn spring-boot:run
```

# Endpoints
In current [configuration](https://github.com/boris-ns/spring-security-boilerplate/blob/master/src/main/java/com/borisns/securitydemo/config/WebSecurityConfig.java)
every URL endpoint with ```/public/``` in it won't be checked by JWT filter and Spring Security, so that means everyone can use it.
Also, this applies to ```/auth/login```

# API documentation

## Login
```POST http://localhost:8080/auth/login```  
Request:  
```json
{
	"username":"john.doe",
	"password":"123"
}
```
Response:  
```json
{
    "id": 1,
    "username": "john.doe",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@doe.com",
    "enabled": true,
    "authorities": [
        "ROLE_USER"
    ],
    "token": {
        "accessToken": "JWT_TOKEN_VALUE",
        "expiresIn": 3600000
    }
}
```

## Refresh token
```POST http://localhost:8080/auth/refresh```  
Authentication: you must send JWT with request  
All users are authorized to use this endpoint  
Response:  
```json
{
    "accessToken": "JWT_TOKEN_VALUE",
    "expiresIn": 3600000
}
```

## Change password
```POST http://localhost:8080/auth/change-password```  
Authentication: you must send JWT with request  
All users are authorized to use this endpoint  
Request:  
```json
{
    "oldPassword": "12345",
    "newPassword": "asdfg"
}
```
Response: 200 OK or exception

## Public Hello World
```GET http://localhost:8080/api/public/hello-world```  
Everyone is authorized to use this endpoint  
Response: ```Hello World from PUBLIC controller!```

## Private Hello World for registered users
```GET http://localhost:8080/api/hello-world/registered-user```  
Only registered users can use this endpoint  
Response: ```Hello ANY REGISTERED USER from PRIVATE controller!```  

## Private Hello World for regular users
```GET http://localhost:8080/api/hello-world/user```  
Only users with role ```ROLE_USER``` can use this endpoint  
Response: ```Hello USER from PRIVATE controller!```

## Private Hello World for admins
```GET http://localhost:8080/api/hello-world/admin```  
Only users with role ```ROLE_ADMIN``` can use this endpoint  
Response: ```Hello ADMIN from PRIVATE controller!```

# Predefined data in the database
In the database, there are two types of users: ```ROLE_ADMIN``` and ```ROLE_USER```.  
Also, there are 2 predefined users as you can see in [import.sql file](https://github.com/boris-ns/spring-security-boilerplate/blob/master/src/main/resources/import.sql).  

Regular user is ```john.doe```.  
Admin is ```jane.doe```.  
All passwords are ``123``.

package edu.Osayd.min_jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MinJwtApplication {

	/*
	Purpose:
		The Spring Boot entry point for the application (@SpringBootApplication).
	Security Role:
		No direct security logic. It triggers Spring Boot auto-configuration,
		including activating the security setup in SecurityConfig.java.

	Secret Key Generation:
		-Use the JwtSecretGenerator class to generate a secure key.
		-That key we put in the application.properties file.

	This app uses in-memory users for simplicity.
	 */
	public static void main(String[] args) {
		SpringApplication.run(MinJwtApplication.class, args);
	}

}

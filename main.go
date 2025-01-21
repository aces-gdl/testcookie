package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v4"
)

// Define a secret key for JWT
var jwtSecret = []byte("your-secret-key")

func main() {
	app := fiber.New()

	// Configure CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000, https://ipadel-club.acesgdl.com",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowCredentials: true,
	}))

	// Login route
	app.Post("/auth/login", loginHandler)
	// Logout route
	app.Post("/auth/logout", logoutHandler)

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, Fiber!")
	})

	log.Fatal(app.Listen(":3500"))
}

func logoutHandler(c *fiber.Ctx) error {
	// Clear the JWT cookie
	c.ClearCookie("jwt")

	return c.JSON(fiber.Map{
		"message": "Logout successful",
	})
}
func loginHandler(c *fiber.Ctx) error {
	// Parse login credentials
	var login struct {
		Phone    string `json:"phone"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&login); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Cannot parse JSON",
		})
	}

	// Here you should verify the username and password
	// This is a placeholder check - replace with actual authentication logic
	if login.Phone == "1" && login.Password == "1" {
		// Create the JWT claims, which includes the username and expiry time
		claims := jwt.MapClaims{
			"username": login.Phone,
			"exp":      time.Now().Add(time.Hour * 72).Unix(),
		}

		// Create token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		// Generate encoded token and send it as response.
		t, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		// Set the JWT as a cookie
		cookie := new(fiber.Cookie)
		cookie.Name = "jwt"
		cookie.Value = t
		cookie.Expires = time.Now().Add(72 * time.Hour)
		cookie.HTTPOnly = true
		cookie.Secure = true // Set to true if using HTTPS
		cookie.SameSite = "None"

		c.Cookie(cookie)

		return c.JSON(fiber.Map{
			"message": "Login successful",
		})
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
		"error": "Invalid credentials",
	})
}

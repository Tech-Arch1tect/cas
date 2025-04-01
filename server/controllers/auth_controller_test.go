package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cas/controllers"
	"cas/database"
	"cas/models"
	"cas/router"
	"cas/testutils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestRegisterHandler_Success(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	input := controllers.RegisterInput{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "secret123",
	}
	jsonValue, _ := json.Marshal(input)
	req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Registration successful", resp["message"])

	var user models.User
	err = env.DB.First(&user, "username = ?", input.Username).Error
	assert.NoError(t, err)
	assert.Equal(t, input.Email, user.Email)
}

func TestRegisterHandler_InvalidInput(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	testCases := []struct {
		name           string
		input          interface{}
		expectedStatus int
	}{
		{
			name: "Missing email",
			input: gin.H{
				"username": "testuser",
				"password": "secret123",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid email",
			input: gin.H{
				"username": "testuser",
				"email":    "not-an-email",
				"password": "secret123",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Password too short",
			input: gin.H{
				"username": "testuser",
				"email":    "test@example.com",
				"password": "123",
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonValue, _ := json.Marshal(tc.input)
			req, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(jsonValue))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.expectedStatus, w.Code)
		})
	}
}

func TestProfileHandler(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)

	testUser := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "irrelevant",
	}
	err := env.DB.Create(&testUser).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	req, _ := http.NewRequest("GET", "/api/v1/auth/profile", nil)
	w := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("id", testUser)

	authController.ProfileHandler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &body)
	assert.NoError(t, err)
	userData := body["user"].(map[string]interface{})
	assert.Equal(t, testUser.Username, userData["Username"])
}

func TestLoginHandler_Success(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	loginInput := map[string]string{
		"username": "testuser",
		"password": "secret123",
	}
	jsonValue, _ := json.Marshal(loginInput)
	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	accessToken, ok := resp["access_token"].(string)
	assert.True(t, ok, "access_token not found in response")
	assert.NotEmpty(t, accessToken, "access_token should not be empty")
}

func TestLoginHandler_Failure(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	loginInput := map[string]string{
		"username": "testuser",
		"password": "wrongpassword",
	}
	jsonValue, _ := json.Marshal(loginInput)
	req, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	errMsg, ok := resp["error"].(string)
	assert.True(t, ok, "error not found in response")
	assert.NotEmpty(t, errMsg)
}

func TestProtectedEndpoint_NoToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	req, _ := http.NewRequest("GET", "/api/v1/auth/profile", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedEndpoint_InvalidToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	req, _ := http.NewRequest("GET", "/api/v1/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProtectedEndpoint_ValidToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	loginInput := map[string]string{
		"username": "testuser",
		"password": "secret123",
	}
	jsonValue, _ := json.Marshal(loginInput)
	loginReq, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonValue))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	r.ServeHTTP(loginResp, loginReq)

	assert.Equal(t, http.StatusOK, loginResp.Code)
	var loginData map[string]interface{}
	err = json.Unmarshal(loginResp.Body.Bytes(), &loginData)
	assert.NoError(t, err)
	accessToken, ok := loginData["access_token"].(string)
	assert.True(t, ok, "access_token not found in login response")
	assert.NotEmpty(t, accessToken)

	req, _ := http.NewRequest("GET", "/api/v1/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var profileData map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &profileData)
	assert.NoError(t, err)
	userData, ok := profileData["user"].(map[string]interface{})
	assert.True(t, ok, "user data not found in response")
	assert.Equal(t, "testuser", userData["Username"])
}

func TestRefreshHandler_ValidRefreshToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	loginInput := map[string]string{
		"username": "testuser",
		"password": "secret123",
	}
	jsonValue, _ := json.Marshal(loginInput)
	loginReq, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonValue))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	r.ServeHTTP(loginResp, loginReq)

	assert.Equal(t, http.StatusOK, loginResp.Code)

	var refreshToken string
	for _, cookie := range loginResp.Result().Cookies() {
		if cookie.Name == "refresh_token" {
			refreshToken = cookie.Value
			break
		}
	}
	assert.NotEmpty(t, refreshToken, "refresh token should be set in cookie")

	refreshReq, _ := http.NewRequest("GET", "/api/v1/auth/refresh_token", nil)
	refreshReq.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: refreshToken,
	})
	refreshResp := httptest.NewRecorder()
	r.ServeHTTP(refreshResp, refreshReq)

	assert.Equal(t, http.StatusOK, refreshResp.Code)

	var refreshData map[string]interface{}
	err = json.Unmarshal(refreshResp.Body.Bytes(), &refreshData)
	assert.NoError(t, err)
	accessToken, ok := refreshData["access_token"].(string)
	assert.True(t, ok, "access_token not found in refresh response")
	assert.NotEmpty(t, accessToken)
}

func TestRefreshHandler_InvalidRefreshToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	refreshReq, _ := http.NewRequest("GET", "/api/v1/auth/refresh_token", nil)
	refreshReq.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "invalid.token.here",
	})
	refreshResp := httptest.NewRecorder()
	r.ServeHTTP(refreshResp, refreshReq)

	assert.Equal(t, http.StatusUnauthorized, refreshResp.Code)
}

func TestRefreshHandler_MissingRefreshToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	refreshReq, _ := http.NewRequest("GET", "/api/v1/auth/refresh_token", nil)
	refreshResp := httptest.NewRecorder()
	r.ServeHTTP(refreshResp, refreshReq)

	assert.Equal(t, http.StatusUnauthorized, refreshResp.Code)
}

func TestLogoutHandler_Success(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("secret123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	user := models.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	if err := env.DB.Create(&user).Error; err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	loginInput := map[string]string{
		"username": "testuser",
		"password": "secret123",
	}
	jsonValue, _ := json.Marshal(loginInput)
	loginReq, _ := http.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(jsonValue))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	r.ServeHTTP(loginResp, loginReq)

	assert.Equal(t, http.StatusOK, loginResp.Code)

	var loginData map[string]interface{}
	err = json.Unmarshal(loginResp.Body.Bytes(), &loginData)
	assert.NoError(t, err)
	accessToken, ok := loginData["access_token"].(string)
	assert.True(t, ok, "access_token not found in login response")
	assert.NotEmpty(t, accessToken)

	var refreshToken string
	for _, cookie := range loginResp.Result().Cookies() {
		if cookie.Name == "refresh_token" {
			refreshToken = cookie.Value
			break
		}
	}
	assert.NotEmpty(t, refreshToken, "refresh token should be set in cookie")

	logoutReq, _ := http.NewRequest("POST", "/api/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+accessToken)
	logoutReq.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: refreshToken,
	})
	logoutResp := httptest.NewRecorder()
	r.ServeHTTP(logoutResp, logoutReq)

	assert.Equal(t, http.StatusOK, logoutResp.Code)

	var logoutData map[string]string
	err = json.Unmarshal(logoutResp.Body.Bytes(), &logoutData)
	assert.NoError(t, err)
	assert.Equal(t, "Logout successful", logoutData["message"])

	var blacklistedAccessToken models.TokenBlacklist
	err = env.DB.Where("token = ?", accessToken).First(&blacklistedAccessToken).Error
	assert.NoError(t, err)
	assert.Equal(t, accessToken, blacklistedAccessToken.Token)

	var blacklistedRefreshToken models.TokenBlacklist
	err = env.DB.Where("token = ?", refreshToken).First(&blacklistedRefreshToken).Error
	assert.NoError(t, err)
	assert.Equal(t, refreshToken, blacklistedRefreshToken.Token)

	var refreshCookie *http.Cookie
	for _, cookie := range logoutResp.Result().Cookies() {
		if cookie.Name == "refresh_token" {
			refreshCookie = cookie
			break
		}
	}
	assert.NotNil(t, refreshCookie, "refresh_token cookie should be present in response")
	assert.Equal(t, "", refreshCookie.Value, "refresh_token cookie value should be empty")
	assert.True(t, refreshCookie.Expires.Before(time.Now()), "refresh_token cookie should be expired")
}

func TestLogoutHandler_NoToken(t *testing.T) {
	env := testutils.SetupTestEnv(t)
	authController := controllers.NewAuthController(env.DB, env.Config)
	r := router.NewRouter(env.Config, env.JwtMiddleware, authController)

	logoutReq, _ := http.NewRequest("POST", "/api/v1/auth/logout", nil)
	logoutResp := httptest.NewRecorder()
	r.ServeHTTP(logoutResp, logoutReq)

	assert.Equal(t, http.StatusUnauthorized, logoutResp.Code)
}

func TestTokenCleanup(t *testing.T) {
	env := testutils.SetupTestEnv(t)

	expiredToken := models.TokenBlacklist{
		Token:     "expired.token.here",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	err := env.DB.Create(&expiredToken).Error
	assert.NoError(t, err)

	validToken := models.TokenBlacklist{
		Token:     "valid.token.here",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = env.DB.Create(&validToken).Error
	assert.NoError(t, err)

	err = database.CleanupExpiredTokens(env.DB)
	assert.NoError(t, err)

	var count int64
	err = env.DB.Model(&models.TokenBlacklist{}).Where("token = ?", expiredToken.Token).Count(&count).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(0), count)

	err = env.DB.Model(&models.TokenBlacklist{}).Where("token = ?", validToken.Token).Count(&count).Error
	assert.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

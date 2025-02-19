package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("Missing Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		apiKey, err := GetAPIKey(headers)
		assert.Empty(t, apiKey)
		assert.ErrorIs(t, err, ErrNoAuthHeaderIncluded)
	})

	t.Run("Malformed Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer somekey")
		apiKey, err := GetAPIKey(headers)
		assert.Empty(t, apiKey)
		assert.EqualError(t, err, "malformed authorization header")
	})

	t.Run("Valid Authorization Header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey valid_api_key")
		apiKey, err := GetAPIKey(headers)
		assert.Equal(t, "valid_api_key", apiKey)
		assert.NoError(t, err)
	})
}

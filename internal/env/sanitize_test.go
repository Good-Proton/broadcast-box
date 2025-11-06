package env

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitize(t *testing.T) {
	t.Run("replaces escaped newlines", func(t *testing.T) {
		input := "line1\\nline2\\nline3"
		expected := "line1\nline2\nline3"
		require.Equal(t, expected, Sanitize(input))
	})

	t.Run("replaces escaped tabs", func(t *testing.T) {
		input := "col1\\tcol2\\tcol3"
		expected := "col1\tcol2\tcol3"
		require.Equal(t, expected, Sanitize(input))
	})

	t.Run("replaces escaped carriage returns", func(t *testing.T) {
		input := "text\\rmore"
		expected := "text\rmore"
		require.Equal(t, expected, Sanitize(input))
	})

	t.Run("handles multiple escape sequences", func(t *testing.T) {
		input := "line1\\nline2\\tindented\\rcarriage"
		expected := "line1\nline2\tindented\rcarriage"
		require.Equal(t, expected, Sanitize(input))
	})

	t.Run("returns unchanged string without escape sequences", func(t *testing.T) {
		input := "simple text"
		require.Equal(t, input, Sanitize(input))
	})

	t.Run("handles empty string", func(t *testing.T) {
		require.Equal(t, "", Sanitize(""))
	})

	t.Run("handles PEM certificate format", func(t *testing.T) {
		input := "-----BEGIN CERTIFICATE-----\\nMIIC...\\n-----END CERTIFICATE-----"
		expected := "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
		require.Equal(t, expected, Sanitize(input))
	})
}

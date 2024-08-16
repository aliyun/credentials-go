package utils

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getOS(t *testing.T) {
	assert.Equal(t, runtime.GOOS, getOS())
}

func TestGetHomePath(t *testing.T) {
	originGetOS := getOS
	originUserProfile := os.Getenv("USERPROFILE")
	originHome := os.Getenv("HOME")
	defer func() {
		getOS = originGetOS
		os.Setenv("USERPROFILE", originUserProfile)
		os.Setenv("HOME", originHome)
	}()

	getOS = func() string {
		return "windows"
	}
	os.Setenv("USERPROFILE", "/path/to/custom_home")

	assert.Equal(t, "/path/to/custom_home", GetHomePath())

	getOS = func() string {
		return "darwin"
	}

	os.Setenv("HOME", "/Users/jacksontian")
	assert.Equal(t, "/Users/jacksontian", GetHomePath())
}

package auth_middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/EvolutionAPI/evolution-go/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/gomessguii/logger"
)

type JIDValidationMiddleware struct{}

func NewJIDValidationMiddleware() *JIDValidationMiddleware {
	return &JIDValidationMiddleware{}
}

func (m *JIDValidationMiddleware) ValidateJIDFields(fieldNames ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.ContentType()
		if !strings.Contains(contentType, "application/json") {
			if strings.Contains(contentType, "multipart/form-data") {
				m.validateFormFields(c, fieldNames...)
				return
			}
			c.Next()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		modified := false
		for _, fieldName := range fieldNames {
			if value, exists := requestData[fieldName]; exists {
				if strValue, ok := value.(string); ok && strValue != "" {
					normalizedJID, err := utils.CreateJID(strValue)
					if err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"error": fmt.Sprintf("Invalid %s format: %s", fieldName, err.Error()),
						})
						c.Abort()
						return
					}

					if normalizedJID != strValue {
						requestData[fieldName] = normalizedJID
						modified = true
						logger.LogDebug("Normalized %s from %s to %s", fieldName, strValue, normalizedJID)
					}
				} else if strValue == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("%s is required and cannot be empty", fieldName),
					})
					c.Abort()
					return
				}
			}
		}

		if modified {
			newBody, err := json.Marshal(requestData)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
				c.Abort()
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
		}

		c.Next()
	}
}

func (m *JIDValidationMiddleware) validateFormFields(c *gin.Context, fieldNames ...string) {
	for _, fieldName := range fieldNames {
		value := c.PostForm(fieldName)
		if value != "" {
			_, err := utils.CreateJID(value)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": fmt.Sprintf("Invalid %s format: %s", fieldName, err.Error()),
				})
				c.Abort()
				return
			}
		} else if fieldName == "number" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("%s is required and cannot be empty", fieldName),
			})
			c.Abort()
			return
		}
	}
	c.Next()
}

func (m *JIDValidationMiddleware) ValidateNumberField() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.ContentType()
		if !strings.Contains(contentType, "application/json") {
			if strings.Contains(contentType, "multipart/form-data") {
				m.validateFormFields(c, "number")
				return
			}
			c.Next()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		modified := false
		if value, exists := requestData["number"]; exists {
			if arrayValue, ok := value.([]interface{}); ok {
				if len(arrayValue) == 0 {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "number array cannot be empty",
					})
					c.Abort()
					return
				}
				for i, item := range arrayValue {
					if strValue, ok := item.(string); ok && strValue != "" {
						normalizedJID, err := utils.CreateJID(strValue)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": fmt.Sprintf("Invalid number[%d] format: %s", i, err.Error()),
							})
							c.Abort()
							return
						}
						if normalizedJID != strValue {
							arrayValue[i] = normalizedJID
							modified = true
							logger.LogDebug("Normalized number[%d] from %s to %s", i, strValue, normalizedJID)
						}
					} else if strValue == "" {
						c.JSON(http.StatusBadRequest, gin.H{
							"error": fmt.Sprintf("number[%d] cannot be empty", i),
						})
						c.Abort()
						return
					}
				}
			} else if strValue, ok := value.(string); ok {
				if strValue == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "number is required and cannot be empty",
					})
					c.Abort()
					return
				}
				normalizedJID, err := utils.CreateJID(strValue)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("Invalid number format: %s", err.Error()),
					})
					c.Abort()
					return
				}
				if normalizedJID != strValue {
					requestData["number"] = normalizedJID
					modified = true
					logger.LogDebug("Normalized number from %s to %s", strValue, normalizedJID)
				}
			} else {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "number must be a string or array of strings",
				})
				c.Abort()
				return
			}
		}

		if modified {
			newBody, err := json.Marshal(requestData)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
				c.Abort()
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
		}

		c.Next()
	}
}

func (m *JIDValidationMiddleware) ValidateMultipleNumbers(fieldName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.ContentType()
		if !strings.Contains(contentType, "application/json") {
			c.Next()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		if value, exists := requestData[fieldName]; exists {
			modified := false

			if arrayValue, ok := value.([]interface{}); ok {
				for i, item := range arrayValue {
					if strValue, ok := item.(string); ok && strValue != "" {
						normalizedJID, err := utils.CreateJID(strValue)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": fmt.Sprintf("Invalid %s[%d] format: %s", fieldName, i, err.Error()),
							})
							c.Abort()
							return
						}
						if normalizedJID != strValue {
							arrayValue[i] = normalizedJID
							modified = true
						}
					}
				}
			}

			if modified {
				newBody, err := json.Marshal(requestData)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
					c.Abort()
					return
				}
				c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
			}
		}

		c.Next()
	}
}

func (m *JIDValidationMiddleware) ValidateNumberFieldWithFormatJid() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.ContentType()
		if !strings.Contains(contentType, "application/json") {
			c.Next()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		formatJid := true
		if formatJidValue, exists := requestData["formatJid"]; exists {
			if formatJidBool, ok := formatJidValue.(bool); ok {
				formatJid = formatJidBool
			}
		}

		modified := false
		if value, exists := requestData["number"]; exists {
			if arrayValue, ok := value.([]interface{}); ok {
				if len(arrayValue) == 0 {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "number array cannot be empty",
					})
					c.Abort()
					return
				}
				for i, item := range arrayValue {
					if strValue, ok := item.(string); ok && strValue != "" {
						if formatJid {
							normalizedJID, err := utils.CreateJID(strValue)
							if err != nil {
								c.JSON(http.StatusBadRequest, gin.H{
									"error": fmt.Sprintf("Invalid number[%d] format: %s", i, err.Error()),
								})
								c.Abort()
								return
							}
							if normalizedJID != strValue {
								arrayValue[i] = normalizedJID
								modified = true
								logger.LogDebug("Normalized number[%d] from %s to %s", i, strValue, normalizedJID)
							}
						}
					} else if strValue == "" {
						c.JSON(http.StatusBadRequest, gin.H{
							"error": fmt.Sprintf("number[%d] cannot be empty", i),
						})
						c.Abort()
						return
					}
				}
			} else if strValue, ok := value.(string); ok {
				if strValue == "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "number is required and cannot be empty",
					})
					c.Abort()
					return
				}
				if formatJid {
					normalizedJID, err := utils.CreateJID(strValue)
					if err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"error": fmt.Sprintf("Invalid number format: %s", err.Error()),
						})
						c.Abort()
						return
					}
					if normalizedJID != strValue {
						requestData["number"] = normalizedJID
						modified = true
						logger.LogDebug("Normalized number from %s to %s", strValue, normalizedJID)
					}
				}
			} else {
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "number must be a string or array of strings",
				})
				c.Abort()
				return
			}
		} else {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "phone number is required",
			})
			c.Abort()
			return
		}

		if modified {
			newBody, err := json.Marshal(requestData)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
				c.Abort()
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
		}

		c.Next()
	}
}

func (m *JIDValidationMiddleware) ValidateContactFields() gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.ContentType()
		if !strings.Contains(contentType, "application/json") {
			c.Next()
			return
		}

		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read request body"})
			c.Abort()
			return
		}

		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON format"})
			c.Abort()
			return
		}

		modified := false

		if value, exists := requestData["number"]; exists {
			if strValue, ok := value.(string); ok && strValue != "" {
				normalizedJID, err := utils.CreateJID(strValue)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": fmt.Sprintf("Invalid number format: %s", err.Error()),
					})
					c.Abort()
					return
				}
				if normalizedJID != strValue {
					requestData["number"] = normalizedJID
					modified = true
				}
			}
		}

		if vcardValue, exists := requestData["vcard"]; exists {
			if vcardMap, ok := vcardValue.(map[string]interface{}); ok {
				if phoneValue, phoneExists := vcardMap["phone"]; phoneExists {
					if phoneStr, ok := phoneValue.(string); ok && phoneStr != "" {
						_, err := utils.CreateJID(phoneStr)
						if err != nil {
							c.JSON(http.StatusBadRequest, gin.H{
								"error": fmt.Sprintf("Invalid vcard phone format: %s", err.Error()),
							})
							c.Abort()
							return
						}
					}
				}
			}
		}

		if modified {
			newBody, err := json.Marshal(requestData)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
				c.Abort()
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))
		}

		c.Next()
	}
}

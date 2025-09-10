package utils

import (
	"fmt"
	"os"
	"strings"
)

// генерирует ссылку на сторонний сервис.
//
// Мы завязываемся на том что domain идёт первым, а returnTo вторым в linkPattern
func GetLinkToExternalService(uuidValue string) string {
	var domain = getDomainLink()
	var returnTo = getReturnToLink(uuidValue)
	var linkPattern = getLinkFormat()

	fmt.Println("domain", domain)
	fmt.Println("returnTo", returnTo)
	fmt.Println("linkPattern", linkPattern)

	return fmt.Sprintf(linkPattern, domain, returnTo)
}

func getDomainLink() string {
	var domain, ok = os.LookupEnv("DOMAIN")

	if !ok || domain == "" {
		domain = "http://127.0.0.1:4444"
	}

	return domain
}

func getReturnToLink(uuidValue string) string {
	var returnTo, ok = os.LookupEnv("RETURN_TO_LINK")

	if !ok || returnTo == "" {
		returnTo = "http://127.0.0.1:4444/auth/returnTo"
	}

	var builder strings.Builder

	builder.WriteString(returnTo)

	// Убедимся, что в конце returnTo есть слеш, и добавим uuidValue
	if !strings.HasSuffix(returnTo, "/") {
		builder.WriteString("/")
	}

	builder.WriteString(uuidValue)

	return builder.String()
}

func getLinkFormat() string {
	var linkFormat, ok = os.LookupEnv("EXTERNAL_SERVICE_PATTERN")

	if !ok || linkFormat == "" {
		linkFormat = "http://127.0.0.1:4444?realm=%s&returnTo=%s"
	}

	return linkFormat
}

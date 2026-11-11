// Command apphub-machine-request 在目标机器生成 AppHub 授权申请码或 JSON。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/DCIMGo/apphub-sdk-go/machineidentity"
)

func main() {
	appID := flag.String("app-id", "", "AppHub application ID")
	appVersion := flag.String("app-version", "", "installed application version")
	instanceID := flag.String("instance-id", "default", "application instance ID")
	format := flag.String("format", "code", "output format: code or json")
	flag.Parse()
	if *format != "code" && *format != "json" {
		log.Fatal("output format must be code or json")
	}
	identity, err := machineidentity.Collect(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	if *format == "json" {
		request, err := identity.MarshalRequest(*appID, *appVersion, *instanceID, now)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(request))
		return
	}
	code, err := identity.MarshalRequestCode(*appID, *appVersion, *instanceID, now)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(code)
}

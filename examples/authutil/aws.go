package authutil

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func init() {
	token, err := getMetadataToken()
	if err != nil {
		log.Fatalf("Error fetching metadata token: %v", err)
	}

	publicIP, err := getPublicIP(token)
	if err != nil {
		log.Fatalf("Error fetching public IP: %v", err)
	}

	publicHost, err := getPublicHost(token)
	if err != nil {
		log.Fatalf("Error fetching public IP: %v", err)
	}

	log.Printf("public host: %s\n", publicHost)
	log.Printf("public ip: %s\n", publicIP)

	Port = ":443"
	Issuer = "https://" + publicHost
	MTLSHost = "https://" + publicIP
}

func getMetadataToken() (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("PUT", "http://169.254.169.254/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token-ttl-seconds", "21600") // Token valid for 6 hours

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get metadata token, status code: %d", resp.StatusCode)
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

// Function to get the public IP using the metadata token
func getPublicIP(token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/public-ipv4", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get public IP, status code: %d", resp.StatusCode)
	}

	ip, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(ip), nil
}

func getPublicHost(token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/public-hostname", nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("X-aws-ec2-metadata-token", token)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to get public IP, status code: %d", resp.StatusCode)
	}

	hostname, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(hostname), nil
}

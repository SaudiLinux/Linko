#!/usr/bin/env python3
"""
Test server for demonstrating cloud vulnerability detection
This server simulates various cloud misconfigurations and exposures
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class CloudTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Simulate different cloud vulnerability scenarios
        
        if self.path == '/':
            # Normal homepage
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <head><title>Cloud Test Server</title></head>
            <body>
                <h1>Cloud Vulnerability Test Server</h1>
                <p>Available test endpoints:</p>
                <ul>
                    <li><a href="/aws-credentials">AWS Credentials Exposed</a></li>
                    <li><a href="/azure-config">Azure Configuration</a></li>
                    <li><a href="/gcp-keys">Google Cloud Keys</a></li>
                    <li><a href="/terraform-state">Terraform State</a></li>
                    <li><a href="/kubernetes-config">Kubernetes Config</a></li>
                    <li><a href="/mixed-cloud">Mixed Cloud Issues</a></li>
                </ul>
            </body>
            </html>
            """)
            
        elif self.path == '/aws-credentials':
            # Simulate exposed AWS credentials
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            aws_config = {
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-west-2"
            }
            self.wfile.write(json.dumps(aws_config).encode())
            
        elif self.path == '/azure-config':
            # Simulate exposed Azure configuration
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            azure_config = {
                "azure_storage_key": "DefaultEndpointsProtocol=https;AccountName=mystorage;AccountKey=examplekey123",
                "tenant_id": "12345678-1234-1234-1234-123456789012"
            }
            self.wfile.write(json.dumps(azure_config).encode())
            
        elif self.path == '/gcp-keys':
            # Simulate exposed Google Cloud service account key
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            gcp_config = {
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n...\n-----END PRIVATE KEY-----\n",
                "gcp_service_account": "my-service-account@project.iam.gserviceaccount.com"
            }
            self.wfile.write(json.dumps(gcp_config).encode())
            
        elif self.path == '/terraform-state':
            # Simulate exposed Terraform state file
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            terraform_state = {
                "version": 4,
                "terraform_version": "1.0.0",
                "resources": [
                    {
                        "mode": "managed",
                        "type": "aws_instance",
                        "name": "example",
                        "provider": "provider[\\\"registry.terraform.io/hashicorp/aws\\\"]",
                        "instances": [
                            {
                                "schema_version": 1,
                                "attributes": {
                                    "ami": "ami-12345678",
                                    "instance_type": "t2.micro"
                                }
                            }
                        ]
                    }
                ]
            }
            self.wfile.write(json.dumps(terraform_state).encode())
            
        elif self.path == '/kubernetes-config':
            # Simulate exposed Kubernetes configuration
            self.send_response(200)
            self.send_header('Content-type', 'application/yaml')
            self.end_headers()
            kubeconfig = """
apiVersion: v1
kind: Config
current-context: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: my-user
  name: my-cluster
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMW5TNGhJV3Yr
    server: https://my-cluster.example.com
  name: my-cluster
users:
- name: my-user
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJJREFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMW5TNGhJV3Yr
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCT1FJQkFBUkFvRU1YQ2dLQ0FR
"""
            self.wfile.write(kubeconfig.encode())
            
        elif self.path == '/mixed-cloud':
            # Simulate multiple cloud issues
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            mixed_content = """
            <html>
            <head><title>Mixed Cloud Issues</title></head>
            <body>
                <h1>Cloud Infrastructure Configuration</h1>
                <script>
                // Exposed cloud configurations
                var cloud_config = {
                    "lambda_secret": "my-lambda-function-secret-key",
                    "function_secret": "azure-function-app-secret",
                    "serverless_secret": "gcp-cloud-function-secret"
                };
                
                var network_config = {
                    "security_groups": ["0.0.0.0/0"],
                    "public_subnet": true,
                    "internet_gateway": "igw-12345678"
                };
                
                var iam_config = {
                    "iam_user": "admin-user",
                    "iam_role": "administrator_access",
                    "administrator_access": true
                };
                </script>
                
                <div id="backup-info">
                    Backup Configuration:
                    backup_bucket: my-public-backup-bucket
                    snapshot_public: true
                    backup_public: enabled
                </div>
                
                <div id="logging-status">
                    Logging Status: disable_logging=true, no_audit=enabled, skip_monitoring=true
                </div>
            </body>
            </html>
            """
            self.wfile.write(mixed_content.encode())
            
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')

def run_server():
    server_address = ('localhost', 8080)
    httpd = HTTPServer(server_address, CloudTestHandler)
    print("Starting cloud test server on http://localhost:8080")
    print("Available endpoints:")
    print("  / - Main page")
    print("  /aws-credentials - AWS credentials exposed")
    print("  /azure-config - Azure configuration")
    print("  /gcp-keys - Google Cloud keys")
    print("  /terraform-state - Terraform state file")
    print("  /kubernetes-config - Kubernetes config")
    print("  /mixed-cloud - Mixed cloud issues")
    print("\nPress Ctrl+C to stop the server")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
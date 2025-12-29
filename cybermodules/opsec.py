import datetime
import os
import secrets
import subprocess
import time

from cyberapp.models.db import db_conn

try:
    import boto3
    from botocore.exceptions import ClientError
    has_aws = True
except Exception:
    boto3 = None
    ClientError = Exception
    has_aws = False

try:
    import digitalocean
    has_digitalocean = True
except Exception:
    digitalocean = None
    has_digitalocean = False


class OpSecEngine:
    """
    Infrastructure-as-Code ile IP Rotasyonu
    AWS API Gateway / Lambda / DigitalOcean Droplet'ları kullan
    FireProx mantığı
    """

    def __init__(self, scan_id):
        self.scan_id = scan_id
        self.aws_region = "us-east-1"
        self.aws_api_gateways = []
        self.do_droplets = []
        self.current_proxy = None
        self.rotation_count = 0
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.do_token = os.getenv("DIGITALOCEAN_TOKEN")

    def create_aws_api_gateway(self, target_url):
        if not has_aws or not self.aws_access_key:
            self.log_opsec("AWS credentials not found. Using direct connection.")
            return target_url

        try:
            client = boto3.client(
                'apigateway',
                region_name=self.aws_region,
                aws_access_key_id=self.aws_access_key,
                aws_secret_access_key=self.aws_secret_key,
            )

            api_response = client.create_rest_api(
                name=f"monolith-proxy-{secrets.token_hex(4)}",
                description=f"Temporary proxy for {target_url}",
                endpointConfiguration={'types': ['REGIONAL']},
            )

            api_id = api_response['id']

            resources = client.get_resources(restApiId=api_id)
            root_id = resources['items'][0]['id']

            proxy_resource = client.create_resource(
                restApiId=api_id,
                parentId=root_id,
                pathPart='{proxy+}',
            )

            client.put_method(
                restApiId=api_id,
                resourceId=proxy_resource['id'],
                httpMethod='ANY',
                type='HTTP_PROXY',
                integrationHttpMethod='POST',
            )

            client.put_integration(
                restApiId=api_id,
                resourceId=proxy_resource['id'],
                httpMethod='ANY',
                type='HTTP_PROXY',
                uri=f"{target_url}/{{proxy}}",
                integrationHttpMethod='ANY',
            )

            client.create_deployment(
                restApiId=api_id,
                stageName='scan',
            )

            proxy_url = f"https://{api_id}.execute-api.{self.aws_region}.amazonaws.com/scan"

            self.aws_api_gateways.append({
                'api_id': api_id,
                'proxy_url': proxy_url,
                'created_at': datetime.datetime.now(),
            })

            self.log_opsec(f"AWS API Gateway created: {proxy_url}")
            return proxy_url

        except ClientError as e:
            self.log_opsec(f"AWS API Gateway creation failed: {str(e)[:100]}")
            return target_url
        except Exception as e:
            self.log_opsec(f"AWS error: {str(e)[:100]}")
            return target_url

    def create_digitalocean_droplet(self, region='nyc3', size='s-1vcpu-512mb-10gb'):
        if not has_digitalocean or not self.do_token:
            self.log_opsec("DigitalOcean token not found.")
            return None

        try:
            manager = digitalocean.Manager(token=self.do_token)

            keys = manager.get_all_ssh_keys()
            key_id = keys[0].id if keys else None

            droplet = digitalocean.Droplet(
                token=self.do_token,
                name=f"monolith-proxy-{secrets.token_hex(4)}",
                region_slug=region,
                image_slug='ubuntu-22-04-x64',
                size_slug=size,
                ssh_keys=[key_id] if key_id else [],
                backups=False,
                private_networking=True,
            )

            droplet.create()

            for _ in range(60):
                droplet.reload()
                if droplet.ip_address:
                    break
                time.sleep(1)

            if droplet.ip_address:
                self.setup_proxy_on_droplet(droplet.ip_address)

                self.do_droplets.append({
                    'droplet_id': droplet.id,
                    'ip_address': droplet.ip_address,
                    'proxy_url': f"http://{droplet.ip_address}:8080",
                    'created_at': datetime.datetime.now(),
                })

                self.log_opsec(f"DigitalOcean droplet created: {droplet.ip_address}:8080")
                return droplet.ip_address

        except Exception as e:
            self.log_opsec(f"DigitalOcean droplet creation failed: {str(e)[:100]}")
            return None

    def setup_proxy_on_droplet(self, droplet_ip):
        try:
            ssh_cmd = f"""
            ssh -i ~/.ssh/id_rsa root@{droplet_ip} << 'EOF'
            apt-get update && apt-get install -y tinyproxy
            echo "Listen 8080" > /etc/tinyproxy/tinyproxy.conf
            echo "ConnectPort 443" >> /etc/tinyproxy/tinyproxy.conf
            systemctl restart tinyproxy
            EOF
            """
            subprocess.run(ssh_cmd, shell=True, timeout=30)
            self.log_opsec(f"Tinyproxy installed on {droplet_ip}")
        except Exception as e:
            self.log_opsec(f"Proxy setup failed: {str(e)[:50]}")

    def rotate_ip(self):
        all_proxies = self.aws_api_gateways + self.do_droplets

        if not all_proxies:
            return None

        self.rotation_count = (self.rotation_count + 1) % len(all_proxies)
        proxy_info = all_proxies[self.rotation_count]

        self.current_proxy = proxy_info['proxy_url']
        self.log_opsec(f"IP rotated to: {self.current_proxy}")

        return self.current_proxy

    def get_current_proxy(self):
        if not self.current_proxy:
            return self.rotate_ip()
        return self.current_proxy

    def cleanup(self):
        if has_aws and self.aws_access_key:
            try:
                client = boto3.client(
                    'apigateway',
                    region_name=self.aws_region,
                    aws_access_key_id=self.aws_access_key,
                    aws_secret_access_key=self.aws_secret_key,
                )

                for gw in self.aws_api_gateways:
                    client.delete_rest_api(restApiId=gw['api_id'])
                    self.log_opsec(f"API Gateway deleted: {gw['api_id']}")

            except Exception as e:
                self.log_opsec(f"API Gateway cleanup failed: {str(e)[:50]}")

        if has_digitalocean and self.do_token:
            try:
                manager = digitalocean.Manager(token=self.do_token)

                for droplet_info in self.do_droplets:
                    droplet = digitalocean.Droplet(
                        token=self.do_token,
                        id=droplet_info['droplet_id'],
                    )
                    droplet.destroy()
                    self.log_opsec(f"Droplet deleted: {droplet_info['droplet_id']}")

            except Exception as e:
                self.log_opsec(f"Droplet cleanup failed: {str(e)[:50]}")

    def log_opsec(self, message):
        try:
            with db_conn() as conn:
                conn.execute(
                    "INSERT INTO intel (scan_id, type, data) VALUES (?, ?, ?)",
                    (self.scan_id, "OPSEC_IP_ROTATION", message),
                )
                conn.commit()
        except Exception:
            pass


html_template = """<!DOCTYPE html>\n    <html>\n    <head>\n        <meta charset=\"UTF-8\">\n        <title>OpSec Engine</title>\n        <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\n        <style>\n            body { background: #0f0f23; color: #fff; font-family: monospace; }\n            .card { background: rgba(30, 30, 46, 0.9); border: 1px solid #00ff00; }\n            .status-active { color: #00ff00; }\n            .status-inactive { color: #888; }\n        </style>\n    </head>\n    <body>\n        <div class=\"container mt-5\">\n            <h1 class=\"text-success mb-4\">🛡️ OpSec Engine - Infrastructure as Code</h1>\n            \n            <div class=\"row mb-4\">\n                <div class=\"col-md-6\">\n                    <div class=\"card p-4 border-success\">\n                        <h3 class=\"text-warning\">AWS Integration</h3>\n                        <p><strong>Status:</strong> __AWS_STATUS__</p>\n                        <p><small>API Gateway Proxy | Lambda | Auto Cleanup</small></p>\n                        <code style=\"font-size: 11px;\">boto3 installed: __HAS_AWS__</code>\n                    </div>\n                </div>\n                <div class=\"col-md-6\">\n                    <div class=\"card p-4 border-info\">\n                        <h3 class=\"text-info\">DigitalOcean Integration</h3>\n                        <p><strong>Status:</strong> __DO_STATUS__</p>\n                        <p><small>Droplet Creation | Tinyproxy | Auto Destroy</small></p>\n                        <code style=\"font-size: 11px;\">digitalocean installed: __HAS_DO__</code>\n                    </div>\n                </div>\n            </div>\n            \n            <div class=\"row\">\n                <div class=\"col-md-12\">\n                    <div class=\"card p-3 border-secondary\">\n                        <h4 class=\"text-primary\">Recent OpSec Actions</h4>\n                        __OPSEC_HTML__\n                    </div>\n                </div>\n            </div>\n            \n            <div class=\"mt-4\">\n                <a href=\"/opsec/activate\" class=\"btn btn-lg btn-success\">Activate OpSec</a>\n            </div>\n        </div>\n    \n    <script>\n        document.getElementById('activate-opsec') && document.getElementById('activate-opsec').addEventListener('click', function(e) {\n            e.preventDefault();\n            var btn = e.target;\n            btn.disabled = true;\n            btn.innerHTML = '<i class=\"bi bi-hourglass-split\"></i> Activating...';\n            fetch('/opsec/activate', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({})})\n            .then(function(r) { return r.json(); })\n            .then(function(res) {\n                if(res.aws_proxy) {\n                    alert('AWS Proxy created: ' + res.aws_proxy);\n                } else if(res.error) {\n                    alert('Error: ' + res.error);\n                } else {\n                    alert('OpSec activated');\n                }\n            }).catch(function(e) {\n                alert('Error: ' + e)\n            }).finally(function() {\n                btn.disabled = false\n                btn.innerHTML = '<i class=\"bi bi-rocket\"></i> Activate OpSec'\n            })\n        })\n    </script>\n\n    <script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js\"></script>\n</body>\n</html>"""


def get_opsec_html(aws_status_html, do_status_html, has_aws_state, has_digitalocean_state, opsec_html):
    html = html_template.replace('__AWS_STATUS__', aws_status_html)
    html = html.replace('__DO_STATUS__', do_status_html)
    html = html.replace('__HAS_AWS__', str(has_aws_state))
    html = html.replace('__HAS_DO__', str(has_digitalocean_state))
    html = html.replace('__OPSEC_HTML__', opsec_html)
    return html

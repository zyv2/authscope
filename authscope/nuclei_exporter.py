import json
import yaml

class NucleiExporter:
    @staticmethod
    def create_jwt_template(jwt_data: dict, severity: str = "medium"):
        """Create Nuclei template for JWT testing"""
        template = {
            "id": f"jwt-{hashlib.md5(json.dumps(jwt_data).encode()).hexdigest()[:8]}",
            "info": {
                "name": "JWT Security Checks",
                "author": "AuthScope",
                "severity": severity,
                "description": "JWT vulnerability checks",
                "reference": [
                    "https://jwt.io",
                    "https://auth0.com/docs/secure/tokens/json-web-tokens"
                ]
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}"],
                    "headers": {
                        "Authorization": f"Bearer {jwt_data.get('token', '')}"
                    },
                    "matchers": {
                        "type": "word",
                        "words": ["invalid", "expired", "error"],
                        "condition": "or",
                        "part": "body"
                    }
                }
            ]
        }
        
        return yaml.dump(template, default_flow_style=False)
    
    @staticmethod
    def export_to_nuclei(tokens: list, output_file: str):
        """Export multiple tokens to Nuclei templates"""
        templates = []
        for token in tokens:
            template = NucleiExporter.create_jwt_template({"token": token})
            templates.append(template)
        
        with open(output_file, 'w') as f:
            f.write("\n---\n".join(templates))
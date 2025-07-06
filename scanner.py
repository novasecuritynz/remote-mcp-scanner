from utils.http import post_json, get_text, get_json
from utils.colors import info, success, error, warning, progress, negative, bold, green, red, yellow
from bs4 import BeautifulSoup
from urllib.parse import quote, urlencode

def run_scan(base_url, verbose=False):
    print(bold(f"Starting scan on: {base_url}"))

    # Check for OAuth well-known endpoints first
    oauth_configs = test_dynamic_oauth_url(base_url)
    
    if not oauth_configs:
        print(info("This OAuth client doesn't support dynamic OAuth registration."))
        return oauth_configs
    
    # Perform OAuth tests if configs found
    client_data = test_oauth_registration(base_url, oauth_configs)
    test_redirect_uri_validation(base_url, oauth_configs, client_data)
    test_xss_in_website_uri(base_url, oauth_configs, client_data)
    test_csrf_flow(base_url)
    
    return oauth_configs

def test_oauth_registration(base_url, oauth_configs):
    print(info("Testing OAuth dynamic client registration..."))
    
    # Look for registration_endpoint in any of the OAuth configs
    registration_endpoint = None
    for config_name, config_data in oauth_configs.items():
        if 'registration_endpoint' in config_data:
            registration_endpoint = config_data['registration_endpoint']
            print(progress(f"Found registration_endpoint in {config_name}"))
            break
    
    if not registration_endpoint:
        print(error("No registration_endpoint found in OAuth configuration"))
        return None
    
    print(progress(f"Using registration endpoint: {registration_endpoint}"))
    
    # Standard OAuth client registration payload
    payload = {
        "redirect_uris": ["http://localhost"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "Nova Security MCP Remote Scanner https://github.com/novasecuritynz/remote_mcp_scanner",
        "client_uri": "https://www.novasecurity.co.nz"
    }
    
    res = post_json(registration_endpoint, payload)
    if res:
        print(success(f"Registration response: {res.status_code}"))
        if res.status_code in [200, 201]:
            try:
                client_data = res.json()
                print(success(f"Vanilla Client registered successfully: {client_data.get('client_id', 'N/A')}"))
                return client_data
            except ValueError:
                print(error("Invalid JSON in registration response"))
                print(error(f"Response text: {res.text}"))
        else:
            print(error(f"Registration failed with status {res.status_code}"))
            try:
                error_data = res.json()
                print(error(f"Error response: {error_data}"))
                return {"error": error_data, "status_code": res.status_code}
            except ValueError:
                print(error(f"Error response (non-JSON): {res.text}"))
                return {"error": res.text, "status_code": res.status_code}
    
    return None

def test_dynamic_registration(base_url):
    print(info("Testing dynamic registration..."))
    payload = {
        "client_name": "Test Client",
        "redirect_uris": ["https://example.com/callback"],
        "website_uri": "https://example.com"
    }
    res = post_json(f"{base_url}/register", payload)
    print(success(f"Registration response: {res.status_code}"))

def test_redirect_uri_validation(base_url, oauth_configs=None, base_client_data=None):
    print(info("Testing redirect_uri validation bypass..."))
    
    # Get registration endpoint
    registration_endpoint = None
    if oauth_configs:
        for config_name, config_data in oauth_configs.items():
            if 'registration_endpoint' in config_data:
                registration_endpoint = config_data['registration_endpoint']
                break
    
    if not registration_endpoint:
        registration_endpoint = f"{base_url}/register"
    
    # Test vectors for redirect URI validation
    test_vectors = [
        # JavaScript XSS vectors
        ("javascript://example.com/%0aalert(1);//", "JavaScript schema XSS"),
        ("javascript:alert('XSS')", "Direct JavaScript execution"),
        # ("javascript://comment%0Aalert('XSS')", "JavaScript comment bypass"),
        # ("javascript:void(0);alert('XSS')", "JavaScript void bypass"),
        # ("javascript:eval('alert(1)')", "JavaScript eval execution"),
        # ("javascript://%0aalert(document.domain)", "JavaScript domain disclosure"),
        # ("javascript://example.com/%0d%0aalert('CRLF')", "CRLF injection with JavaScript"),
        # ("javascript:setTimeout('alert(1)',0)", "JavaScript setTimeout"),
        # ("javascript:/**/alert('XSS')", "JavaScript comment filter bypass"),
        # ("javascript:%61lert('XSS')", "JavaScript URL encoding"),
        
        # # Data URI XSS vectors
        # ("data:text/html,<script>alert('XSS')</script>", "Data URI XSS"),
        # ("data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", "Base64 encoded XSS"),
        # ("data:,alert('XSS')", "Minimal data URI"),
        # ("data:text/javascript,alert('XSS')", "JavaScript MIME data URI"),
        # ("data:application/javascript,alert('XSS')", "Application JavaScript data URI"),
        # ("data:text/html;charset=utf-8,<script>alert('XSS')</script>", "Charset data URI XSS"),
        
        # # VBScript vectors (IE legacy)
        # ("vbscript:msgbox('XSS')", "VBScript execution"),
        # ("vbscript:execute(\"msgbox('XSS')\")", "VBScript execute"),
        
        # # File and alternative protocols
        # ("file:///etc/passwd", "Local file access"),
        # ("ftp://evil.com/", "FTP protocol bypass"),
        # ("jar:http://evil.com!/", "JAR protocol"),
        # ("gopher://evil.com/", "Gopher protocol"),
        
        # Localhost variations
        ("http://localhost", "Basic localhost"),
        # ("http://localhost:8080", "Localhost with port"),
        # ("http://127.0.0.1", "Loopback IP"),
        # ("http://0.0.0.0", "Wildcard IP"),
        # ("http://[::1]", "IPv6 loopback"),
        
        # Domain bypass attempts
        # ("https://example.com%2Fcallback", "URL encoding bypass"),
        # ("https://example.com@evil.com/", "Authority bypass"),
        # ("https://example.com.evil.com/", "Subdomain bypass"),
        # ("https://evil.com/https://example.com", "Path confusion"),
        # ("https://example.com/../../../evil.com", "Path traversal"),
        # ("https://example.com\\@evil.com", "Backslash bypass"),
        # ("https://example.com%00.evil.com", "Null byte bypass"),
        # ("https://example.com%2e%2e%2f%2e%2e%2fevil.com", "Double URL encoding"),
        
        # # Open redirect tests
        # ("http://localhost/?redirect=https://evil.com", "Open redirect via parameter"),
        # ("http://localhost/redirect?url=javascript:alert(1)", "Parameter injection"),
        # ("http://localhost#javascript:alert(1)", "Fragment-based XSS"),
        
        # # Custom schemes and wildcards
        # ("custom-app://callback", "Custom scheme test"),
        # ("app://localhost/callback", "App scheme localhost"),
        # ("https://totally-random-domain-12345.com/callback", "Arbitrary domain test"),
        # ("*", "Wildcard test"),
        # ("", "Empty string test"),
        
        # # Advanced bypass techniques
        # ("javascript&#58;alert('XSS')", "HTML entity bypass"),
        # ("java\x00script:alert('XSS')", "Null byte injection"),
        # ("javascript\x3aalert('XSS')", "Hex encoding bypass"),
        # ("&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;", "Full HTML entity encoding")
    ]
    
    successful_bypasses = []
    xss_risks = []
    localhost_accepted = []
    arbitrary_accepted = []
    vulnerable_clients = []  # Store client data for manual testing
    
    base_payload = {
        "client_name": "Redirect URI Test Client",
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"]
    }
    
    for uri, description in test_vectors:
        test_payload = base_payload.copy()
        test_payload["redirect_uris"] = [uri]
        
        res = post_json(registration_endpoint, test_payload)
        if res and res.status_code in [200, 201]:
            successful_bypasses.append((uri, description))
            print(success(f"Accepted: {uri} ({description})"))
            
            # Store client data for manual testing
            try:
                client_info = res.json()
                client_id = client_info.get('client_id')
                if client_id:
                    vulnerable_clients.append({
                        'client_id': client_id,
                        'redirect_uri': uri,
                        'description': description,
                        'vulnerability_type': 'redirect_uri'
                    })
            except:
                pass
            
            # Categorize the bypass
            if "javascript:" in uri.lower() or "data:" in uri.lower() or "vbscript:" in uri.lower():
                xss_risks.append((uri, description))
            elif "localhost" in uri or "127.0.0.1" in uri or "0.0.0.0" in uri or "[::1]" in uri:
                localhost_accepted.append((uri, description))
            elif "totally-random-domain" in uri or uri == "*" or "custom-app:" in uri:
                arbitrary_accepted.append((uri, description))
        else:
            status = res.status_code if res else "No response"
            print(negative(f"Rejected: {uri} -> {status}"))
    
    # Print summary
    print(bold("\n=== REDIRECT URI VALIDATION SUMMARY ==="))
    
    if xss_risks:
        print(error("🚨 XSS RISKS FOUND:"))
        for uri, desc in xss_risks:
            print(error(f"  • {uri} - {desc}"))
        print(error("  → These redirect URIs can lead to XSS attacks!"))
    
    if arbitrary_accepted:
        print(warning("⚠️  ARBITRARY REDIRECT URIS ACCEPTED:"))
        for uri, desc in arbitrary_accepted:
            print(warning(f"  • {uri} - {desc}"))
        print(warning("  → Server accepts arbitrary redirect URIs - potential for abuse!"))
    
    if localhost_accepted:
        print(info("ℹ️  LOCALHOST VARIANTS ACCEPTED:"))
        for uri, desc in localhost_accepted:
            print(info(f"  • {uri} - {desc}"))
    
    # Generate manual testing URLs
    if vulnerable_clients and oauth_configs:
        authorization_endpoint = None
        for config_name, config_data in oauth_configs.items():
            if 'authorization_endpoint' in config_data:
                authorization_endpoint = config_data['authorization_endpoint']
                break
        
        if authorization_endpoint:
            print(bold("\n🔗 REDIRECT_URI XSS MANUAL TESTING:"))
            print(bold("📋 INSTRUCTIONS: Complete the full OAuth flow to test XSS:"))
            print(info("1. Click the URL below in your browser"))
            print(info("2. Complete any login/authorization steps"))  
            print(info("3. Watch for JavaScript execution during redirect"))
            print(info("4. Check browser console and network tabs for XSS"))
            print("")
            
            for client in vulnerable_clients:
                if any(scheme in client['redirect_uri'].lower() for scheme in ['javascript:', 'data:', 'vbscript:']):
                    # URL encode query parameters
                    params = {
                        'response_type': 'code',
                        'client_id': client['client_id'],
                        'redirect_uri': client['redirect_uri'],
                        'state': 'xss_test_redirect'
                    }
                    query_string = urlencode(params, quote_via=quote)
                    manual_url = f"{authorization_endpoint}?{query_string}"
                    
                    print(error(f"🚨 REDIRECT_URI XSS Test ({client['description']}):"))
                    print(error(f"   Client ID: {client['client_id']}"))
                    print(error(f"   Payload: {client['redirect_uri']}"))
                    print(error(f"   Test URL: {manual_url}"))
                    print("")
    
    if successful_bypasses:
        print(warning(f"\n📊 Total bypasses found: {len(successful_bypasses)}/{len(test_vectors)}"))
    else:
        print(success("✅ No redirect URI validation bypasses found - good security!"))
    
    return {
        "total_tests": len(test_vectors),
        "successful_bypasses": len(successful_bypasses),
        "xss_risks": xss_risks,
        "arbitrary_accepted": arbitrary_accepted,
        "localhost_accepted": localhost_accepted,
        "all_bypasses": successful_bypasses,
        "vulnerable_clients": vulnerable_clients
    }

def test_csrf_flow(base_url):
    print(warning("Manual review suggested for CSRF. Automate later with Playwright or headless browser."))

def test_xss_in_website_uri(base_url, oauth_configs=None, base_client_data=None):
    print(info("Testing website_uri for XSS vulnerabilities..."))
    
    # Get registration endpoint
    registration_endpoint = None
    if oauth_configs:
        for config_name, config_data in oauth_configs.items():
            if 'registration_endpoint' in config_data:
                registration_endpoint = config_data['registration_endpoint']
                break
    
    if not registration_endpoint:
        registration_endpoint = f"{base_url}/register"
    
    # XSS test vectors for website_uri field
    xss_test_vectors = [
        # JavaScript XSS vectors
        ("javascript://domain.com/%0aalert(1);//", "JavaScript schema XSS"),
        ("javascript:alert('XSS')", "Direct JavaScript execution"),
        # ("javascript://comment%0Aalert('XSS')", "JavaScript comment bypass"),
        # ("javascript:void(0);alert('XSS')", "JavaScript void bypass"),
        # ("javascript:eval('alert(1)')", "JavaScript eval execution"),
        # ("javascript://%0aalert(document.domain)", "JavaScript domain disclosure"),
        # ("javascript://example.com/%0d%0aalert('CRLF')", "CRLF injection with JavaScript"),
        # ("javascript://example.com/%0a%0dalert(1);//", "Line feed injection"),
        # ("javascript:setTimeout('alert(1)',0)", "JavaScript setTimeout"),
        # ("javascript:/**/alert('XSS')", "JavaScript comment filter bypass"),
        # ("javascript:%61lert('XSS')", "JavaScript URL encoding"),
        # ("javascript:window['alert']('XSS')", "JavaScript bracket notation"),
        # ("javascript:Function('alert(1)')()", "JavaScript Function constructor"),
        
        # # Data URI XSS vectors
        # ("data:text/html,<script>alert('XSS')</script>", "Data URI XSS"),
        # ("data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=", "Base64 encoded XSS"),
        # ("data:,alert('XSS')", "Minimal data URI"),
        # ("data:text/javascript,alert('XSS')", "JavaScript MIME data URI"),
        # ("data:application/javascript,alert('XSS')", "Application JavaScript data URI"),
        # ("data:text/html;charset=utf-8,<script>alert('XSS')</script>", "Charset data URI XSS"),
        # ("data:text/html,<img src=x onerror=alert('XSS')>", "Data URI with event handler"),
        # ("data:text/html,<svg onload=alert('XSS')>", "Data URI SVG XSS"),
        
        # # VBScript vectors (IE legacy)
        # ("vbscript:msgbox('XSS')", "VBScript execution"),
        # ("vbscript:execute(\"msgbox('XSS')\")", "VBScript execute"),
        
        # # Direct HTML injection
        # ("<script>alert('XSS')</script>", "Direct script injection"),
        # ("'><script>alert('XSS')</script>", "Quote breaking XSS"),
        # ("\"><script>alert('XSS')</script>", "Double quote breaking XSS"),
        # ("<img src=x onerror=alert('XSS')>", "Image event handler XSS"),
        # ("<svg onload=alert('XSS')>", "SVG event handler XSS"),
        # ("<iframe srcdoc=\"<script>alert('XSS')</script>\">", "Iframe srcdoc XSS"),
        # ("<body onload=alert('XSS')>", "Body event handler"),
        # ("<div onclick=alert('XSS')>Click", "Div click handler"),
        # ("<a href=\"javascript:alert('XSS')\">Click</a>", "Anchor JavaScript href"),
        # ("<input onfocus=alert('XSS') autofocus>", "Input autofocus XSS"),
        
        # # Advanced HTML injection
        # ("<meta http-equiv=refresh content=0;url=javascript:alert('XSS')>", "Meta redirect XSS"),
        # ("<object data=\"javascript:alert('XSS')\">", "Object data XSS"),
        # ("<embed src=\"javascript:alert('XSS')\">", "Embed src XSS"),
        # ("<form action=\"javascript:alert('XSS')\"><input type=submit>", "Form action XSS"),
        # ("<details open ontoggle=alert('XSS')>", "Details toggle XSS"),
        # ("<audio src=x onerror=alert('XSS')>", "Audio error XSS"),
        # ("<video src=x onerror=alert('XSS')>", "Video error XSS"),
        
        # # URL and entity encoding bypasses
        # ("javascript&#58;alert('XSS')", "HTML entity bypass"),
        # ("java\x00script:alert('XSS')", "Null byte injection"),
        # ("javascript\x3aalert('XSS')", "Hex encoding bypass"),
        # ("&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;", "Full HTML entity encoding"),
        # ("javas\tcript:alert('XSS')", "Tab character bypass"),
        # ("javas\rcript:alert('XSS')", "Carriage return bypass"),
        # ("javas\ncript:alert('XSS')", "Newline bypass"),
        
        # # CSS injection attempts
        # ("javascript:alert('XSS')/*", "CSS comment injection"),
        # ("expression(alert('XSS'))", "CSS expression (IE)"),
        # ("\\65 xpression(alert('XSS'))", "CSS hex encoding"),
        
        # # Template injection attempts
        # ("{{alert('XSS')}}", "Template literal injection"),
        # ("${alert('XSS')}", "Template string injection"),
        # ("#{alert('XSS')}", "Ruby template injection"),
        
        # # Protocol pollution
        # ("httpx://evil.com", "Protocol pollution"),
        # ("//evil.com", "Protocol relative URL"),
        # ("///evil.com", "Triple slash bypass"),
        
        # # Polyglot payloads
        # ("javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/*/`/*\\`/*'/*\"/**/(alert)('XSS')//'>", "Polyglot XSS"),
        # ("'\"><img src=x onerror=alert('XSS')>//", "Quote breaking polyglot"),
        
        # # Edge cases
        # ("", "Empty string test"),
        # (" ", "Space character test"),
        # ("null", "Null string test"),
        # ("undefined", "Undefined string test")
    ]
    
    base_payload = {
        "redirect_uris": ["https://example.com/callback"],
        "client_name": "XSS Test Client",
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"]
    }
    
    xss_vulnerabilities = []
    successful_injections = []
    vulnerable_website_clients = []  # Store client data for manual testing
    
    for xss_payload, description in xss_test_vectors:
        test_payload = base_payload.copy()
        test_payload["website_uri"] = xss_payload
        
        res = post_json(registration_endpoint, test_payload)
        if res:
            if res.status_code in [200, 201]:
                print(success(f"Accepted website_uri: {xss_payload[:50]}... ({description})"))
                successful_injections.append((xss_payload, description))
                
                # Store client data for manual testing
                try:
                    client_info = res.json()
                    client_id = client_info.get('client_id')
                    if client_id:
                        vulnerable_website_clients.append({
                            'client_id': client_id,
                            'website_uri': xss_payload,
                            'description': description,
                            'vulnerability_type': 'website_uri'
                        })
                except:
                    pass
                
                # Check if the payload is reflected in the response
                if xss_payload in res.text:
                    print(error(f"🚨 XSS PAYLOAD REFLECTED: {xss_payload}"))
                    xss_vulnerabilities.append((xss_payload, description, "Reflected in response"))
                
                # Check for JavaScript/data schemes which are inherently dangerous
                if any(scheme in xss_payload.lower() for scheme in ['javascript:', 'data:', 'vbscript:']):
                    xss_vulnerabilities.append((xss_payload, description, "Dangerous scheme accepted"))
                    
            else:
                print(negative(f"Rejected: {xss_payload[:50]}... -> {res.status_code}"))
        else:
            print(negative(f"No response for: {xss_payload[:50]}..."))
    
    # Print summary
    print(bold("\n=== WEBSITE_URI XSS TESTING SUMMARY ==="))
    
    if xss_vulnerabilities:
        print(error("🚨 XSS VULNERABILITIES FOUND IN WEBSITE_URI:"))
        for payload, desc, reason in xss_vulnerabilities:
            print(error(f"  • {payload}"))
            print(error(f"    └─ {desc} - {reason}"))
        print(error(f"  → {len(xss_vulnerabilities)} XSS vulnerabilities detected!"))
        print(error("  → These can lead to client-side code execution!"))
    
    if successful_injections and not xss_vulnerabilities:
        print(warning("⚠️  SUSPICIOUS WEBSITE_URI ACCEPTANCE:"))
        for payload, desc in successful_injections:
            print(warning(f"  • {payload[:100]}... ({desc})"))
        print(warning("  → Server accepts potentially dangerous website_uri values"))
    
    # Generate manual testing URLs for website_uri XSS
    if vulnerable_website_clients and oauth_configs:
        authorization_endpoint = None
        for config_name, config_data in oauth_configs.items():
            if 'authorization_endpoint' in config_data:
                authorization_endpoint = config_data['authorization_endpoint']
                break
        
        if authorization_endpoint:
            print(bold("\n🔗 WEBSITE_URI XSS MANUAL TESTING:"))
            print(bold("📋 INSTRUCTIONS: Complete the full OAuth flow to test website_uri XSS:"))
            print(info("1. Click the URL below in your browser"))
            print(info("2. Look for the website_uri payload execution on OAuth consent/info pages"))
            print(info("3. Complete any login/authorization steps"))
            print(info("4. Check for XSS execution during the entire OAuth flow"))
            print(info("5. Inspect page source for reflected malicious website_uri"))
            print("")
            
            for client in vulnerable_website_clients:
                if any(scheme in client['website_uri'].lower() for scheme in ['javascript:', 'data:', 'vbscript:']):
                    # Use a safe redirect URI for testing website_uri XSS
                    params = {
                        'response_type': 'code',
                        'client_id': client['client_id'],
                        'redirect_uri': 'https://example.com/callback',
                        'state': 'xss_test_website'
                    }
                    query_string = urlencode(params, quote_via=quote)
                    manual_url = f"{authorization_endpoint}?{query_string}"
                    
                    print(error(f"🚨 WEBSITE_URI XSS Test ({client['description']}):"))
                    print(error(f"   Client ID: {client['client_id']}"))
                    print(error(f"   Payload: {client['website_uri']}"))
                    print(error(f"   Test URL: {manual_url}"))
                    print(error(f"   → Website URI payload may execute on OAuth consent/info pages"))
                    print("")
    
    if not successful_injections:
        print(success("✅ No XSS vulnerabilities found in website_uri field - good security!"))
    
    print(info(f"📊 Total XSS tests: {len(xss_test_vectors)}, Vulnerabilities: {len(xss_vulnerabilities)}"))
    
    return {
        "total_tests": len(xss_test_vectors),
        "successful_injections": len(successful_injections),
        "xss_vulnerabilities": xss_vulnerabilities,
        "all_accepted": successful_injections,
        "vulnerable_clients": vulnerable_website_clients
    }

def test_dynamic_oauth_url(base_url):
    print(info("Looking for Dynamic OAuth Client Registration..."))
    oauth_protected_path = "/.well-known/oauth-protected-resource"
    oauth_authorization_path = "/.well-known/oauth-authorization-server"
    
    # Store valid JSON responses for later use
    oauth_configs = {}
    
    # Parse base URL to get both full path and base domain
    from urllib.parse import urlparse
    parsed_url = urlparse(base_url)
    base_domain_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    urls_to_test = [base_url]
    if base_url != base_domain_url:
        urls_to_test.append(base_domain_url)
    
    for test_url in urls_to_test:
        print(progress(f"Testing base: {test_url}"))
        
        # Check oauth-protected-resource endpoint
        full_protected_url = f"{test_url}{oauth_protected_path}"
        print(progress(f"Checking: {full_protected_url}"))
        status, json_data = get_json(full_protected_url)
        if status == 200 and json_data:
            print(success(f"Found oauth-protected-resource configuration at {test_url}"))
            oauth_configs['protected_resource'] = json_data
        else:
            print(negative(f"oauth-protected-resource not found or invalid (status: {status})"))
        
        # Check oauth-authorization-server endpoint  
        full_auth_url = f"{test_url}{oauth_authorization_path}"
        print(progress(f"Checking: {full_auth_url}"))
        status, json_data = get_json(full_auth_url)
        if status == 200 and json_data:
            print(success(f"Found oauth-authorization-server configuration at {test_url}"))
            oauth_configs['authorization_server'] = json_data
        else:
            print(negative(f"oauth-authorization-server not found or invalid (status: {status})"))
        
        # If we found configs at this URL, no need to test others
        if oauth_configs:
            break
    
    return oauth_configs

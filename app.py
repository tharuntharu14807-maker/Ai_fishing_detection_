import re
import sys
class SimplePhishingDetector:
    def __init__(self):
        """Initialize with simple detection rules."""
        self.phishing_indicators = {
            # Suspicious keywords
            'keywords': [
                'login', 'verify', 'account', 'update', 'confirm', 'secure', 
                'suspended', 'limited', 'urgent', 'winner', 'claim', 'prize'
            ],
            
            # Suspicious TLDs
            'bad_tlds': ['.tk', '.ml', '.ga', '.cf', '.click'],
            
            # Legitimate domains (whitelist)
            'trusted_domains': [
                'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
                'twitter.com', 'linkedin.com', 'microsoft.com', 'apple.com'
            ]
        }

    def check_url_length(self, url):
        """Check if URL is suspiciously long."""
        return len(url) > 75  # URLs over 75 chars are often suspicious

    def check_ip_address(self, url):
        """Check if URL uses IP address instead of domain."""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))

    def check_suspicious_keywords(self, url):
        """Count suspicious keywords in URL."""
        url_lower = url.lower()
        count = 0
        found_keywords = []
        
        for keyword in self.phishing_indicators['keywords']:
            if keyword in url_lower:
                count += 1
                found_keywords.append(keyword)
        
        return count, found_keywords

    def check_subdomains(self, url):
        """Count number of subdomains (many subdomains = suspicious)."""
        # Remove protocol
        if '://' in url:
            url = url.split('://', 1)[1]
        
        # Get domain part (before first '/')
        domain = url.split('/')[0]
        
        # Count dots (subdomains)
        dots = domain.count('.')
        return dots > 3  # More than 3 dots is suspicious

    def check_bad_tld(self, url):
        """Check for suspicious top-level domains."""
        for tld in self.phishing_indicators['bad_tlds']:
            if tld in url.lower():
                return True
        return False

    def check_trusted_domain(self, url):
        """Check if URL contains trusted domain."""
        url_lower = url.lower()
        for domain in self.phishing_indicators['trusted_domains']:
            if domain in url_lower:
                return True
        return False

    def check_https(self, url):
        """Check if URL uses HTTPS."""
        return url.lower().startswith('https://')

    def check_special_chars(self, url):
        """Check for excessive special characters."""
        special_count = len(re.findall(r'[-_~]', url))
        return special_count > 5

    def analyze_url(self, url):
        """Analyze URL and return results."""
        if not url:
            return {'error': 'URL cannot be empty'}

        # Add http if no protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        results = {
            'url': url,
            'checks': {},
            'risk_factors': [],
            'safe_factors': []
        }

        # Perform checks
        results['checks']['long_url'] = self.check_url_length(url)
        results['checks']['ip_address'] = self.check_ip_address(url)
        results['checks']['many_subdomains'] = self.check_subdomains(url)
        results['checks']['bad_tld'] = self.check_bad_tld(url)
        results['checks']['trusted_domain'] = self.check_trusted_domain(url)
        results['checks']['uses_https'] = self.check_https(url)
        results['checks']['excessive_special_chars'] = self.check_special_chars(url)
        
        keyword_count, found_keywords = self.check_suspicious_keywords(url)
        results['checks']['suspicious_keywords'] = keyword_count
        results['found_keywords'] = found_keywords

        # Count risk factors
        if results['checks']['long_url']:
            results['risk_factors'].append('URL is very long')
        
        if results['checks']['ip_address']:
            results['risk_factors'].append('Uses IP address instead of domain')
        
        if results['checks']['many_subdomains']:
            results['risk_factors'].append('Has many subdomains')
        
        if results['checks']['bad_tld']:
            results['risk_factors'].append('Uses suspicious domain extension')
        
        if results['checks']['excessive_special_chars']:
            results['risk_factors'].append('Contains many special characters')
        
        if keyword_count > 0:
            results['risk_factors'].append(f'Contains {keyword_count} suspicious keywords: {", ".join(found_keywords)}')

        # Count safe factors
        if results['checks']['trusted_domain']:
            results['safe_factors'].append('Contains trusted domain')
        
        if results['checks']['uses_https']:
            results['safe_factors'].append('Uses secure HTTPS protocol')

        # Make prediction
        risk_score = len(results['risk_factors'])
        safe_score = len(results['safe_factors'])
        
        # Simple scoring system
        if safe_score > 0 and risk_score <= 1:
            results['prediction'] = 0  # Legitimate
            results['risk_level'] = 'LOW'
            results['status'] = ' LIKELY SAFE'
        elif risk_score >= 3:
            results['prediction'] = 1  # Phishing
            results['risk_level'] = 'HIGH'
            results['status'] = ' HIGH RISK - LIKELY PHISHING'
        elif risk_score >= 2:
            results['prediction'] = 1  # Phishing
            results['risk_level'] = 'MEDIUM-HIGH'
            results['status'] = ' MEDIUM-HIGH RISK - SUSPICIOUS'
        else:
            results['prediction'] = 0  # Legitimate
            results['risk_level'] = 'MEDIUM'
            results['status'] = 'MEDIUM RISK - USE CAUTION'

        # Calculate simple probability
        total_checks = 7  # Total number of risk checks
        results['probability'] = min(risk_score / total_checks, 1.0)

        return results

def print_analysis(results):
    """Print detailed analysis results."""
    print("\n" + "="*60)
    print(" PHISHING DETECTION ANALYSIS")
    print("="*60)
    
    if 'error' in results:
        print(f" Error: {results['error']}")
        return
    
    print(f"URL: {results['url']}")
    print(f"Status: {results['status']}")
    print(f"Risk Level: {results['risk_level']}")
    print(f"Risk Score: {len(results['risk_factors'])}/7")
    
    if results['risk_factors']:
        print(f"\nRisk Factors Found ({len(results['risk_factors'])}):")
        for i, factor in enumerate(results['risk_factors'], 1):
            print(f"  {i}. {factor}")
    
    if results['safe_factors']:
        print(f"\nSafety Indicators ({len(results['safe_factors'])}):")
        for i, factor in enumerate(results['safe_factors'], 1):
            print(f"  {i}. {factor}")
    
    print(f"\nDetailed Checks:")
    print(f"  • Long URL (>75 chars): {'Yes' if results['checks']['long_url'] else 'No'}")
    print(f"  • Uses IP address: {'Yes' if results['checks']['ip_address'] else 'No'}")
    print(f"  • Many subdomains: {'Yes' if results['checks']['many_subdomains'] else 'No'}")
    print(f"  • Suspicious TLD: {'Yes' if results['checks']['bad_tld'] else 'No'}")
    print(f"  • Trusted domain: {'Yes' if results['checks']['trusted_domain'] else 'No'}")
    print(f"  • Uses HTTPS: {'Yes' if results['checks']['uses_https'] else 'No'}")
    print(f"  • Excessive special chars: {'Yes' if results['checks']['excessive_special_chars'] else 'No'}")
    print(f"  • Suspicious keywords: {results['checks']['suspicious_keywords']}")
    
    print("="*60)

def interactive_mode():
    """Run detector in interactive mode."""
    detector = SimplePhishingDetector()
    
    print("Simple Phishing Detector")
    print("Enter URLs to check (type 'quit' to exit)")
    print("-" * 40)
    
    while True:
        try:
            url = input("\nEnter URL: ").strip()
            
            if url.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if not url:
                print("Please enter a URL")
                continue
            
            results = detector.analyze_url(url)
            print_analysis(results)
            
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break

def batch_mode(urls):
    """Analyze multiple URLs."""
    detector = SimplePhishingDetector()
    
    print(f"🔍 Analyzing {len(urls)} URLs...")
    
    for i, url in enumerate(urls, 1):
        print(f"\n--- Analysis {i}/{len(urls)} ---")
        results = detector.analyze_url(url)
        print_analysis(results)

def main():
    """Main function."""
    if len(sys.argv) > 1:
        # Command line mode
        urls = sys.argv[1:]
        batch_mode(urls)
    else:
        # Interactive mode
        interactive_mode()

# Test examples
def run_examples():
    """Run with example URLs for testing."""
    detector = SimplePhishingDetector()
    
    test_urls = [
        "https://www.google.com",
        "http://paypal-security-update.tk/login",
        "https://192.168.1.1/admin",
        "http://verify.account.suspended.amazon.fake.com/update",
        "https://github.com/user/repo"
    ]
    
    print("Testing with example URLs:")
    batch_mode(test_urls)

if __name__ == "__main__":
    # Uncomment the line below to test with examples:
    # run_examples()
    
    main()

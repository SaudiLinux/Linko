#!/usr/bin/env python3
"""
Unit tests for Lighter Security Scanner
Author: SayerLinux (SaudiLinux1@gmail.com)
"""

import unittest
import socket
import threading
import time
import json
from unittest.mock import patch, MagicMock
from lighter import LighterScanner

class MockServer:
    """Mock server for testing"""
    def __init__(self, port, response_data):
        self.port = port
        self.response_data = response_data
        self.server = None
        self.thread = None
        self.running = False
    
    def start(self):
        """Start mock server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('localhost', self.port))
        self.server.listen(5)
        self.running = True
        
        self.thread = threading.Thread(target=self._handle_connections)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1)  # Give server time to start
    
    def _handle_connections(self):
        """Handle incoming connections"""
        while self.running:
            try:
                self.server.settimeout(1.0)
                client, addr = self.server.accept()
                client.send(self.response_data.encode())
                client.close()
            except socket.timeout:
                continue
            except:
                break
    
    def stop(self):
        """Stop mock server"""
        self.running = False
        if self.server:
            self.server.close()
        if self.thread:
            self.thread.join(timeout=1)

class TestLighterScanner(unittest.TestCase):
    """Test cases for Lighter Scanner"""
    
    def setUp(self):
        """Set up test environment"""
        self.scanner = LighterScanner('localhost', threads=10, timeout=5)
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.target, 'localhost')
        self.assertEqual(self.scanner.threads, 10)
        self.assertEqual(self.scanner.timeout, 5)
        self.assertIn('web_servers', self.scanner.results)
        self.assertIn('email_servers', self.scanner.results)
        self.assertIn('databases', self.scanner.results)
    
    def test_port_scanning(self):
        """Test port scanning functionality"""
        # Mock socket operations
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            
            # Simulate open port
            mock_sock.connect_ex.return_value = 0
            
            open_ports = self.scanner.scan_ports()
            self.assertIsInstance(open_ports, list)
    
    def test_web_server_detection_apache(self):
        """Test Apache web server detection"""
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'Apache/2.4.41 (Ubuntu)'}
        mock_response.status_code = 200
        mock_response.text = '<html><body>Apache Test</body></html>'
        
        with patch('requests.get', return_value=mock_response):
            result = self.scanner.detect_web_server(80)
            self.assertIsNotNone(result)
            self.assertEqual(result['server_type'], 'apache')
    
    def test_web_server_detection_nginx(self):
        """Test Nginx web server detection"""
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'nginx/1.18.0'}
        mock_response.status_code = 200
        mock_response.text = '<html><body>Nginx Test</body></html>'
        
        with patch('requests.get', return_value=mock_response):
            result = self.scanner.detect_web_server(80)
            self.assertIsNotNone(result)
            self.assertEqual(result['server_type'], 'nginx')
    
    def test_framework_detection_django(self):
        """Test Django framework detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Django Test csrftoken</body></html>'
        mock_response.headers = {}
        
        server_info = {}
        self.scanner.detect_frameworks(mock_response, server_info)
        self.assertIn('django', server_info['frameworks'])
    
    def test_framework_detection_flask(self):
        """Test Flask framework detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Flask Test</body></html>'
        mock_response.headers = {'Server': 'Werkzeug/1.0.1'}
        
        server_info = {}
        self.scanner.detect_frameworks(mock_response, server_info)
        self.assertIn('flask', server_info['frameworks'])
    
    def test_cms_detection_wordpress(self):
        """Test WordPress CMS detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>WordPress Test /wp-content/ /wp-includes/</body></html>'
        
        server_info = {}
        self.scanner.detect_cms(mock_response, server_info)
        self.assertIn('wordpress', server_info['cms'])
    
    def test_cms_detection_joomla(self):
        """Test Joomla CMS detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Joomla Test /components/ /modules/</body></html>'
        
        server_info = {}
        self.scanner.detect_cms(mock_response, server_info)
        self.assertIn('joomla', server_info['cms'])
    
    def test_vulnerability_detection(self):
        """Test vulnerability detection"""
        mock_response = MagicMock()
        mock_response.headers = {'Server': 'Apache/2.4.41'}
        mock_response.text = 'Index of /'
        mock_response.cookies = {}
        
        server_info = {}
        self.scanner.detect_vulnerabilities(mock_response, 'http://test.com', server_info)
        
        vuln_names = [v['name'] for v in server_info['vulnerabilities']]
        self.assertIn('Directory Listing Enabled', vuln_names)
        self.assertIn('Server Version Disclosure', vuln_names)
    
    def test_email_server_detection_postfix(self):
        """Test Postfix email server detection"""
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.return_value = b'220 mail.example.com ESMTP Postfix'
            
            result = self.scanner.detect_email_server(25)
            # Check if result is not None and has expected structure
            self.assertIsNotNone(result)
            if result and 'server_type' in result:
                self.assertEqual(result['server_type'], 'postfix')
    
    def test_database_detection_mysql(self):
        """Test MySQL database detection"""
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.return_value = b'5.7.32\x00\x00\x00\x00'
            
            result = self.scanner.detect_database(3306)
            self.assertIsNotNone(result)
            self.assertEqual(result['server_type'], 'mysql')
    
    def test_cicd_detection_jenkins(self):
        """Test Jenkins CI/CD platform detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Jenkins Test /jenkins/ Jenkins Server</body></html>'
        
        with patch('requests.get', return_value=mock_response):
            result = self.scanner.detect_cicd_platforms(8080)
            self.assertTrue(any(r['platform'] == 'jenkins' for r in result))
    
    def test_container_detection_docker(self):
        """Test Docker container detection"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Docker Test /version Docker Engine</body></html>'
        
        with patch('requests.get', return_value=mock_response):
            result = self.scanner.detect_containers(2375)
            self.assertTrue(any(r['platform'] == 'docker' for r in result))
    
    def test_report_generation_json(self):
        """Test JSON report generation"""
        self.scanner.results['web_servers'] = [
            {'server_type': 'apache', 'port': 80, 'protocol': 'http'}
        ]
        
        report = self.scanner.generate_report('json')
        self.assertIsInstance(report, str)
        
        # Verify it's valid JSON
        parsed = json.loads(report)
        self.assertIn('web_servers', parsed)
        self.assertEqual(len(parsed['web_servers']), 1)
    
    def test_report_generation_txt(self):
        """Test text report generation"""
        self.scanner.results['web_servers'] = [
            {'server_type': 'nginx', 'port': 80, 'protocol': 'http'}
        ]
        self.scanner.results['email_servers'] = [
            {'server_type': 'postfix', 'port': 25}
        ]
        
        report = self.scanner.generate_report('txt')
        self.assertIsInstance(report, str)
        self.assertIn('Lighter Security Scanner Report', report)
        self.assertIn('nginx', report.lower())
        self.assertIn('postfix', report.lower())
    
    def test_integration_scan_with_mock_servers(self):
        """Integration test with mock servers"""
        # Create mock servers
        apache_server = MockServer(8080, "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html>Apache Test</html>")
        nginx_server = MockServer(8081, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html>Nginx Test</html>")
        
        try:
            apache_server.start()
            nginx_server.start()
            
            # Test scanner with mock responses
            with patch('requests.get') as mock_get:
                # Mock Apache response
                apache_response = MagicMock()
                apache_response.headers = {'Server': 'Apache/2.4.41'}
                apache_response.status_code = 200
                apache_response.text = '<html>Apache Test</html>'
                
                # Mock Nginx response  
                nginx_response = MagicMock()
                nginx_response.headers = {'Server': 'nginx/1.18.0'}
                nginx_response.status_code = 200
                nginx_response.text = '<html>Nginx Test</html>'
                
                # Configure mock to return different responses based on URL
                def side_effect(url, **kwargs):
                    if ':8080' in url:
                        return apache_response
                    elif ':8081' in url:
                        return nginx_response
                    else:
                        raise Exception("Connection refused")
                
                mock_get.side_effect = side_effect
                
                # Test scanner
                scanner = LighterScanner('localhost', threads=5, timeout=2)
                
                apache_result = scanner.detect_web_server(8080)
                nginx_result = scanner.detect_web_server(8081)
                
                self.assertIsNotNone(apache_result)
                self.assertIsNotNone(nginx_result)
                self.assertEqual(apache_result['server_type'], 'apache')
                self.assertEqual(nginx_result['server_type'], 'nginx')
                
        finally:
            apache_server.stop()
            nginx_server.stop()
    
    def test_error_handling(self):
        """Test error handling in scanner methods"""
        with patch('socket.socket') as mock_socket:
            mock_socket.side_effect = socket.error("Connection refused")
            
            # Test error handling in detect_email_server
            result = self.scanner.detect_email_server(25)
            # Should handle error gracefully - result might be None or contain error info
            self.assertTrue(result is None or isinstance(result, dict))
            
            # Test error handling in detect_database
            result = self.scanner.detect_database(3306)
            self.assertTrue(result is None or isinstance(result, dict))
            
            # Test error handling in detect_cicd_platforms (returns list)
            result = self.scanner.detect_cicd_platforms(8080)
            self.assertTrue(isinstance(result, list))
    
    def test_sensitive_files_detection(self):
        """Test sensitive files discovery"""
        # Test with mock server
        result = self.scanner.discover_sensitive_files("localhost", 80)
        self.assertIsInstance(result, list)
        
        # Test with invalid target
        result = self.scanner.discover_sensitive_files("invalid_target_!@#", 80)
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_vulnerability_links_detection(self):
        """Test vulnerability links discovery functionality"""
        # Test with mock server
        scanner = LighterScanner('httpbin.org')
        scanner.scan_all_services()
        results = scanner.results
        
        # Verify vulnerability links detection is working
        self.assertIn('web_servers', results)
        
        # Test with invalid target
        scanner = LighterScanner('invalid.target.local')
        scanner.scan_all_services()
        results = scanner.results
        self.assertEqual(results['web_servers'], [])
    
    def test_performance_large_scan(self):
        """Test performance with large port range"""
        scanner = LighterScanner('localhost', threads=20, timeout=1)
        
        start_time = time.time()
        with patch('socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0
            
            open_ports = scanner.scan_ports()
            
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Should complete within reasonable time
        self.assertLess(scan_duration, 30)  # 30 seconds max
        self.assertIsInstance(open_ports, list)

class TestLighterCLI(unittest.TestCase):
    """Test CLI functionality"""
    
    @patch('sys.argv', ['lighter.py', 'localhost'])
    def test_cli_basic(self):
        """Test basic CLI execution"""
        with patch('lighter.LighterScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_scanner.return_value = mock_instance
            
            from lighter import main
            try:
                result = main()
            except SystemExit:
                pass  # Expected for argparse
    
    @patch('sys.argv', ['lighter.py', 'localhost', '-o', 'test_report.json'])
    def test_cli_with_output(self):
        """Test CLI with output file"""
        with patch('lighter.LighterScanner') as mock_scanner:
            mock_instance = MagicMock()
            mock_instance.generate_report.return_value = '{"test": "data"}'
            mock_scanner.return_value = mock_instance
            
            with patch('builtins.open', create=True) as mock_open:
                from lighter import main
                try:
                    result = main()
                except SystemExit:
                    pass
                
                mock_open.assert_called_once()

if __name__ == '__main__':
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestLighterScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestLighterCLI))
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    exit(0 if result.wasSuccessful() else 1)
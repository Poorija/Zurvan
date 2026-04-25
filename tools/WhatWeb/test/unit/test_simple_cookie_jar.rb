require 'minitest/autorun'
require_relative '../../lib/simple_cookie_jar'

class TestSimpleCookieJar < Minitest::Test
  def setup
    @jar = SimpleCookieJar.new(max_domains: 100)
  end

  def test_basic_cookie_storage
    @jar.add_cookies("session=abc123", "https://example.com")
    assert_equal "session=abc123", @jar.cookies_for_request("https://example.com")
  end

  def test_multiple_cookies_single_header
    @jar.add_cookies("session=abc123; user=john", "https://example.com")
    assert_equal "session=abc123; user=john", @jar.cookies_for_request("https://example.com")
  end

  def test_multiple_set_cookie_headers
    # Simulate multiple Set-Cookie headers joined with newlines
    @jar.add_cookies("session=abc123\nuser=john\ntheme=dark", "https://example.com")
    assert_equal "session=abc123; user=john; theme=dark", @jar.cookies_for_request("https://example.com")
  end

  def test_domain_isolation
    @jar.add_cookies("session=abc", "https://site1.com")
    @jar.add_cookies("session=xyz", "https://site2.com")
    
    assert_equal "session=abc", @jar.cookies_for_request("https://site1.com")
    assert_equal "session=xyz", @jar.cookies_for_request("https://site2.com")
  end

  def test_domain_case_insensitive
    @jar.add_cookies("session=abc", "https://EXAMPLE.COM")
    assert_equal "session=abc", @jar.cookies_for_request("https://example.com")
    assert_equal "session=abc", @jar.cookies_for_request("https://Example.Com")
  end

  def test_subdomain_isolation
    @jar.add_cookies("session=main", "https://example.com")
    @jar.add_cookies("session=sub", "https://sub.example.com")
    
    assert_equal "session=main", @jar.cookies_for_request("https://example.com")
    assert_equal "session=sub", @jar.cookies_for_request("https://sub.example.com")
  end

  def test_cookie_overwrite_same_domain
    @jar.add_cookies("session=old", "https://example.com")
    @jar.add_cookies("session=new", "https://example.com")
    
    assert_equal "session=new", @jar.cookies_for_request("https://example.com")
  end

  def test_cleanup_behavior
    # Fill beyond limit
    150.times { |i| @jar.add_cookies("test=#{i}", "https://site#{i}.com") }
    
    # Should have cleaned up to 50 domains (half of max_domains)
    assert_equal 50, @jar.stats[:domains]
  end

  def test_stats_tracking
    @jar.add_cookies("test=1", "https://site1.com")
    @jar.add_cookies("test=2", "https://site2.com")
    
    stats = @jar.stats
    assert_equal 2, stats[:domains]
    assert_equal 100, stats[:max_domains]
    assert_equal 2, stats[:requests_processed]
    assert stats[:memory_estimate_kb] > 0
  end

  def test_invalid_url_handling
    @jar.add_cookies("test=value", "not-a-url")
    assert_nil @jar.cookies_for_request("not-a-url")
    
    # Should not crash on malformed URLs
    @jar.add_cookies("test=value", "http://[invalid")
    assert_nil @jar.cookies_for_request("http://[invalid")
  end

  def test_nil_and_empty_input_handling
    @jar.add_cookies(nil, "https://example.com")
    @jar.add_cookies("", "https://example.com")
    @jar.add_cookies("test=value", nil)
    @jar.add_cookies("test=value", "")
    
    # Should not crash and should not store anything
    assert_nil @jar.cookies_for_request("https://example.com")
  end

  def test_malformed_cookie_header_handling
    # Test various malformed cookie headers
    @jar.add_cookies("no-equals-sign", "https://example.com")
    @jar.add_cookies("=empty-name", "https://example.com")
    @jar.add_cookies("valid=cookie; no-equals; another=valid", "https://example.com")
    
    # Should extract only valid cookies
    result = @jar.cookies_for_request("https://example.com")
    assert result.include?("valid=cookie")
    assert result.include?("another=valid")
    refute result.include?("no-equals-sign")
    refute result.include?("=empty-name")
  end

  def test_cookie_attributes_ignored
    # Cookies often have attributes like Path, Domain, Secure, HttpOnly
    @jar.add_cookies("session=abc123; Path=/; Domain=.example.com; Secure; HttpOnly", "https://example.com")
    
    # Should only store the name=value part
    assert_equal "session=abc123", @jar.cookies_for_request("https://example.com")
  end

  def test_thread_safety
    threads = 10.times.map do |i|
      Thread.new do
        100.times { |j| @jar.add_cookies("test=#{i}-#{j}", "https://thread#{i}-#{j}.com") }
      end
    end
    
    threads.each(&:join)
    
    # Should not crash and should have reasonable domain count
    assert @jar.stats[:domains] <= 100
    assert @jar.stats[:requests_processed] == 1000
  end

  def test_concurrent_read_write
    # Test concurrent reads and writes
    write_thread = Thread.new do
      1000.times { |i| @jar.add_cookies("test=#{i}", "https://write#{i}.com") }
    end
    
    read_thread = Thread.new do
      1000.times { |i| @jar.cookies_for_request("https://read#{i}.com") }
    end
    
    write_thread.join
    read_thread.join
    
    # Should not crash
    assert @jar.stats[:domains] <= 100
  end

  def test_emergency_cleanup
    # Create a jar with very small limit to test emergency cleanup
    small_jar = SimpleCookieJar.new(max_domains: 10)
    
    # Manually force the jar into an over-limit state to test emergency cleanup
    # Add 16 domains directly to trigger emergency cleanup (16 > 10 * 1.5 = 15)
    16.times { |i| small_jar.instance_variable_get(:@cookies)["site#{i}.com"] = "test=#{i}" }
    
    # Now add one more cookie, which should trigger emergency cleanup
    small_jar.add_cookies("test=final", "https://final.com")
    
    # Should have been reset to 0 due to emergency cleanup (clears everything including new cookie)
    assert_equal 0, small_jar.stats[:domains]
  end

  def test_url_with_path_and_query
    @jar.add_cookies("session=abc", "https://example.com/path/to/page?query=value")
    
    # Should work with different paths on same domain
    assert_equal "session=abc", @jar.cookies_for_request("https://example.com/different/path")
    assert_equal "session=abc", @jar.cookies_for_request("https://example.com")
  end

  def test_http_vs_https
    @jar.add_cookies("session=http", "http://example.com")
    @jar.add_cookies("session=https", "https://example.com")
    
    # Should treat HTTP and HTTPS as same domain
    assert_equal "session=https", @jar.cookies_for_request("http://example.com")
    assert_equal "session=https", @jar.cookies_for_request("https://example.com")
  end

  def test_port_handling
    @jar.add_cookies("session=8080", "https://example.com:8080")
    @jar.add_cookies("session=443", "https://example.com:443")
    
    # Should treat different ports as same domain
    assert_equal "session=443", @jar.cookies_for_request("https://example.com")
    assert_equal "session=443", @jar.cookies_for_request("https://example.com:8080")
  end
end

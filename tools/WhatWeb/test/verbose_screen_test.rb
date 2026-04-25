#!/usr/bin/env ruby
#
# Test script to verify verbose screen output performance
#

require 'benchmark'

class VerboseScreenTest
  def initialize
    @whatweb_path = File.expand_path('../whatweb', __dir__)
    @test_dir = __dir__
    
    create_test_targets
  end

  def create_test_targets
    # Create a small test target file
    test_targets = File.join(@test_dir, 'verbose_test_targets.txt')
    unless File.exist?(test_targets)
      File.write(test_targets, [
        'http://example.com',
        'http://httpbin.org/html',
        'http://httpbin.org/json'
      ].join("\n"))
    end
  end

  def test_verbose_screen_performance
    puts "=== Verbose Screen Output Performance Test ==="
    
    target_file = File.join(@test_dir, 'verbose_test_targets.txt')
    
    # Test different thread counts with verbose output to screen
    thread_counts = [1, 10, 25]
    results = {}
    
    thread_counts.each do |threads|
      print "Testing verbose output with #{threads} threads... "
      
      start_time = Time.now
      # Use -v for verbose output to screen, redirect to /dev/null to avoid cluttering test output
      cmd = "#{@whatweb_path} -v -t #{threads} -i #{target_file} > /dev/null"
      success = system(cmd + " 2>/dev/null")
      end_time = Time.now
      
      if success
        time = end_time - start_time
        results[threads] = time
        puts "#{time.round(2)}s"
      else
        puts "FAILED"
      end
    end
    
    puts "\n=== Verbose Screen Performance Results ==="
    results.each do |threads, time|
      speedup = results[1] ? (results[1] / time).round(2) : 'N/A'
      puts "#{threads} threads: #{time.round(2)}s (#{speedup}x speedup)"
    end
    
    # Test with output sync forced on vs off
    puts "\n=== Output Sync Comparison (25 threads) ==="
    
    print "Testing with --output-sync... "
    start_time = Time.now
    cmd = "#{@whatweb_path} -v --output-sync -t 25 -i #{target_file} > /dev/null"
    success = system(cmd + " 2>/dev/null")
    sync_time = Time.now - start_time
    puts success ? "#{sync_time.round(2)}s" : "FAILED"
    
    print "Testing without --output-sync... "
    start_time = Time.now
    cmd = "#{@whatweb_path} -v -t 25 -i #{target_file} > /dev/null"
    success = system(cmd + " 2>/dev/null")
    async_time = Time.now - start_time
    puts success ? "#{async_time.round(2)}s" : "FAILED"
    
    if sync_time && async_time
      improvement = ((sync_time - async_time) / sync_time * 100).round(1)
      puts "Performance improvement: #{improvement}% faster without sync"
    end
  end

  def run_test
    puts "Verbose Screen Output Performance Test"
    puts "====================================="
    puts "Timestamp: #{Time.now}"
    puts
    
    # Check if whatweb exists
    unless File.exist?(@whatweb_path)
      puts "ERROR: WhatWeb not found at #{@whatweb_path}"
      exit 1
    end
    
    test_verbose_screen_performance
    
    puts "\nTest completed. Check results above."
  end
end

# Run the test if this script is executed directly
if __FILE__ == $0
  test = VerboseScreenTest.new
  test.run_test
end

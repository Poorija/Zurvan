#!/usr/bin/env ruby
#
# Output optimization validation test
# Tests the new performance improvements
#

require 'benchmark'
require 'fileutils'

class OutputOptimizationTest
  def initialize
    @whatweb_path = File.expand_path('../whatweb', __dir__)
    @test_dir = __dir__
    @results_dir = File.join(@test_dir, 'optimization_results')
    FileUtils.mkdir_p(@results_dir)
    
    create_test_targets
  end

  def create_test_targets
    # Create a small test target file
    test_targets = File.join(@test_dir, 'optimization_targets.txt')
    unless File.exist?(test_targets)
      File.write(test_targets, [
        'http://example.com',
        'http://httpbin.org/html',
        'http://httpbin.org/json'
      ].join("\n"))
    end
  end

  def test_new_options
    puts "=== Testing New Command Line Options ==="
    
    target_file = File.join(@test_dir, 'optimization_targets.txt')
    
    # Test --output-sync option
    puts "Testing --output-sync option..."
    cmd = "#{@whatweb_path} --output-sync -t 5 --log-brief=/dev/null -i #{target_file}"
    success = system(cmd + " 2>/dev/null")
    puts success ? "✓ --output-sync works" : "✗ --output-sync failed"
    
    # Test --output-buffer-size option
    puts "Testing --output-buffer-size option..."
    cmd = "#{@whatweb_path} --output-buffer-size=10 -t 5 --log-brief=/dev/null -i #{target_file}"
    success = system(cmd + " 2>/dev/null")
    puts success ? "✓ --output-buffer-size works" : "✗ --output-buffer-size failed"
    
    # Test help text includes new options
    puts "Testing help text includes new options..."
    help_output = `#{@whatweb_path} --help 2>&1`
    has_sync = help_output.include?('--output-sync')
    has_buffer = help_output.include?('--output-buffer-size')
    puts has_sync && has_buffer ? "✓ Help text updated" : "✗ Help text missing new options"
  end

  def test_performance_comparison
    puts "\n=== Performance Comparison Test ==="
    
    target_file = File.join(@test_dir, 'optimization_targets.txt')
    
    # Test with different thread counts to verify smart defaults
    thread_counts = [1, 10, 25]
    results = {}
    
    thread_counts.each do |threads|
      print "Testing #{threads} threads... "
      
      start_time = Time.now
      cmd = "#{@whatweb_path} -t #{threads} --log-brief=/dev/null -i #{target_file}"
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
    
    puts "\n=== Performance Results ==="
    results.each do |threads, time|
      puts "#{threads} threads: #{time.round(2)}s"
    end
  end

  def test_mutex_functionality
    puts "\n=== Mutex Functionality Test ==="
    
    # Test that output is still correct with high thread count
    target_file = File.join(@test_dir, 'optimization_targets.txt')
    output_file = File.join(@results_dir, 'mutex_test_output.txt')
    
    puts "Testing output consistency with 20 threads..."
    cmd = "#{@whatweb_path} -t 20 --log-brief=#{output_file} -i #{target_file}"
    success = system(cmd + " 2>/dev/null")
    
    if success && File.exist?(output_file)
      lines = File.readlines(output_file)
      puts "✓ Generated #{lines.length} output lines"
      
      # Check for any obvious corruption (partial lines, etc.)
      corrupted_lines = lines.select { |line| line.strip.empty? || line.length < 10 }
      if corrupted_lines.empty?
        puts "✓ No obviously corrupted output lines"
      else
        puts "✗ Found #{corrupted_lines.length} potentially corrupted lines"
      end
      
      File.delete(output_file)
    else
      puts "✗ Mutex test failed"
    end
  end

  def test_profiling_infrastructure
    puts "\n=== Profiling Infrastructure Test ==="
    
    target_file = File.join(@test_dir, 'optimization_targets.txt')
    profile_file = File.join(@results_dir, 'test_profile.txt')
    
    puts "Testing profiling with WHATWEB_PROFILE environment variable..."
    
    env = {
      'WHATWEB_PROFILE' => '1',
      'WHATWEB_PROFILE_FILE' => profile_file
    }
    
    cmd = "#{@whatweb_path} -t 5 --log-brief=/dev/null -i #{target_file}"
    success = system(env, cmd + " 2>/dev/null")
    
    if success
      if File.exist?(profile_file)
        puts "✓ Profile file created"
        profile_size = File.size(profile_file)
        puts "✓ Profile file size: #{profile_size} bytes"
        File.delete(profile_file) if profile_size > 0
      else
        puts "✗ Profile file not created (ruby-prof may not be installed)"
      end
    else
      puts "✗ Profiling test failed"
    end
  end

  def run_all_tests
    puts "WhatWeb Output Optimization Test Suite"
    puts "======================================"
    puts "Timestamp: #{Time.now}"
    puts
    
    # Check if whatweb exists
    unless File.exist?(@whatweb_path)
      puts "ERROR: WhatWeb not found at #{@whatweb_path}"
      exit 1
    end
    
    test_new_options
    test_performance_comparison
    test_mutex_functionality
    test_profiling_infrastructure
    
    puts "\n=== Test Summary ==="
    puts "All optimization tests completed."
    puts "Check output above for any failures marked with ✗"
  end
end

# Run the tests if this script is executed directly
if __FILE__ == $0
  test = OutputOptimizationTest.new
  test.run_all_tests
end

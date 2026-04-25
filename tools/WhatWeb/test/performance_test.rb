#!/usr/bin/env ruby
#
# Performance test script for WhatWeb output optimization
# Phase 1: Baseline measurement and profiling
#

require 'benchmark'
require 'fileutils'

class WhatWebPerformanceTest
  def initialize
    @whatweb_path = File.expand_path('../whatweb', __dir__)
    @test_dir = __dir__
    @results_dir = File.join(@test_dir, 'performance_results')
    FileUtils.mkdir_p(@results_dir)
    
    # Create test target files if they don't exist
    create_test_targets
  end

  def create_test_targets
    # Small target list for quick tests
    small_targets = File.join(@test_dir, 'small_targets.txt')
    unless File.exist?(small_targets)
      File.write(small_targets, [
        'http://example.com',
        'http://httpbin.org/html',
        'http://httpbin.org/json',
        'http://httpbin.org/xml',
        'http://httpbin.org/redirect/2'
      ].join("\n"))
    end

    # Medium target list for realistic tests
    medium_targets = File.join(@test_dir, 'medium_targets.txt')
    unless File.exist?(medium_targets)
      targets = []
      # Add some real websites for testing
      base_sites = [
        'example.com', 'httpbin.org', 'github.com', 'stackoverflow.com',
        'reddit.com', 'wikipedia.org', 'google.com', 'youtube.com',
        'amazon.com', 'twitter.com'
      ]
      
      base_sites.each do |site|
        targets << "http://#{site}"
        targets << "https://#{site}"
      end
      
      File.write(medium_targets, targets.join("\n"))
    end
  end

  def run_whatweb_test(threads, target_file, output_format = 'brief')
    log_file = "/tmp/whatweb_test_#{threads}t_#{output_format}.log"
    
    cmd = case output_format
          when 'brief'
            "#{@whatweb_path} -t #{threads} --log-brief=#{log_file} -i #{target_file}"
          when 'verbose'
            "#{@whatweb_path} -t #{threads} --log-verbose=#{log_file} -i #{target_file}"
          else
            "#{@whatweb_path} -t #{threads} --log-brief=/dev/null -i #{target_file}"
          end

    start_time = Time.now
    success = system(cmd + " 2>/dev/null")
    end_time = Time.now
    
    # Clean up log file
    File.delete(log_file) if File.exist?(log_file)
    
    if success
      end_time - start_time
    else
      nil
    end
  end

  def benchmark_thread_scaling
    puts "=== Thread Scaling Benchmark ==="
    puts "Testing with small target list (5 targets)"
    
    target_file = File.join(@test_dir, 'small_targets.txt')
    thread_counts = [1, 2, 5, 10, 20]
    
    results = {}
    
    thread_counts.each do |threads|
      print "Testing #{threads} threads... "
      
      # Run multiple times and take average
      times = []
      3.times do
        time = run_whatweb_test(threads, target_file, 'brief')
        times << time if time
      end
      
      if times.any?
        avg_time = times.sum / times.length
        results[threads] = avg_time
        puts "#{avg_time.round(2)}s (avg of #{times.length} runs)"
      else
        puts "FAILED"
      end
    end
    
    puts "\n=== Results Summary ==="
    results.each do |threads, time|
      speedup = results[1] ? (results[1] / time).round(2) : 'N/A'
      puts "#{threads} threads: #{time.round(2)}s (#{speedup}x speedup)"
    end
    
    results
  end

  def benchmark_output_formats
    puts "\n=== Output Format Benchmark ==="
    puts "Testing different output formats with 10 threads"
    
    target_file = File.join(@test_dir, 'small_targets.txt')
    threads = 10
    formats = ['brief', 'verbose', 'stdout']
    
    results = {}
    
    formats.each do |format|
      print "Testing #{format} format... "
      
      times = []
      3.times do
        time = run_whatweb_test(threads, target_file, format)
        times << time if time
      end
      
      if times.any?
        avg_time = times.sum / times.length
        results[format] = avg_time
        puts "#{avg_time.round(2)}s"
      else
        puts "FAILED"
      end
    end
    
    puts "\n=== Output Format Results ==="
    results.each do |format, time|
      puts "#{format}: #{time.round(2)}s"
    end
    
    results
  end

  def profile_with_ruby_prof
    puts "\n=== Ruby Profiling ==="
    
    target_file = File.join(@test_dir, 'small_targets.txt')
    profile_file = File.join(@results_dir, "profile_#{Time.now.to_i}.txt")
    
    puts "Running profiled test (this may take longer)..."
    
    env = {
      'WHATWEB_PROFILE' => '1',
      'WHATWEB_PROFILE_FILE' => profile_file
    }
    
    cmd = "#{@whatweb_path} -t 10 --log-brief=/dev/null -i #{target_file}"
    
    start_time = Time.now
    success = system(env, cmd + " 2>/dev/null")
    end_time = Time.now
    
    if success && File.exist?(profile_file)
      puts "Profile completed in #{(end_time - start_time).round(2)}s"
      puts "Profile saved to: #{profile_file}"
      
      # Show top 10 time consumers
      puts "\n=== Top 10 Time Consumers ==="
      profile_content = File.read(profile_file)
      lines = profile_content.split("\n")
      
      # Find the start of the flat profile
      start_idx = lines.find_index { |line| line.include?('%self') }
      if start_idx
        data_lines = lines[(start_idx + 1)..(start_idx + 10)]
        data_lines.each { |line| puts line if line.strip.length > 0 }
      end
    else
      puts "Profiling failed or ruby-prof not available"
    end
  end

  def run_all_tests
    puts "WhatWeb Performance Test Suite"
    puts "=============================="
    puts "Timestamp: #{Time.now}"
    puts "WhatWeb path: #{@whatweb_path}"
    puts
    
    # Check if whatweb exists
    unless File.exist?(@whatweb_path)
      puts "ERROR: WhatWeb not found at #{@whatweb_path}"
      exit 1
    end
    
    # Run all benchmark tests
    thread_results = benchmark_thread_scaling
    format_results = benchmark_output_formats
    profile_with_ruby_prof
    
    # Save results to file
    results_file = File.join(@results_dir, "benchmark_#{Time.now.to_i}.txt")
    File.open(results_file, 'w') do |f|
      f.puts "WhatWeb Performance Benchmark Results"
      f.puts "====================================="
      f.puts "Timestamp: #{Time.now}"
      f.puts
      
      f.puts "Thread Scaling Results:"
      thread_results.each do |threads, time|
        speedup = thread_results[1] ? (thread_results[1] / time).round(2) : 'N/A'
        f.puts "  #{threads} threads: #{time.round(2)}s (#{speedup}x speedup)"
      end
      f.puts
      
      f.puts "Output Format Results:"
      format_results.each do |format, time|
        f.puts "  #{format}: #{time.round(2)}s"
      end
    end
    
    puts "\nResults saved to: #{results_file}"
  end
end

# Run the tests if this script is executed directly
if __FILE__ == $0
  test = WhatWebPerformanceTest.new
  test.run_all_tests
end

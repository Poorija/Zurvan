# Copyright 2009 to 2025 Andrew Horton and Brendan Coles
#
# This file is part of WhatWeb.
#
# WhatWeb is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# at your option) any later version.
#
# WhatWeb is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with WhatWeb.  If not, see <http://www.gnu.org/licenses/>.

class Logging
  include Helper

  # if no f, output to STDOUT,
  # if f is a filename then open it, if f is a file use it
  def initialize(f = STDOUT, sync: nil)
    f = STDOUT if f == '-'
    @f = f if f.class == IO || f.class == File
    @f = File.open(f, 'a') if f.class == String
    
    # Make sync configurable with smart defaults
    # Default to sync for low thread counts, async for high thread counts
    if sync.nil?
      @f.sync = ($THREADS && $THREADS <= 5) ? true : false
    else
      @f.sync = sync
    end
    
    # Per-instance mutex for thread-safe output
    @mutex = Mutex.new
    
    # Output buffering for performance
    @buffer = []
    @buffer_size = $OUTPUT_BUFFER_SIZE || 1
    @last_flush = Time.now
    
    # Ensure buffer size is at least 1
    @buffer_size = 1 if @buffer_size < 1
  end

  def close
    flush_buffer # Ensure all buffered output is written
    @f.close unless @f.class == IO
  end

  # Thread-safe output method using per-instance mutex
  def synchronized_write(&block)
    @mutex.synchronize(&block)
  end
  
  # Buffered output method for improved performance
  def buffered_write(content)
    @mutex.synchronize do
      @buffer << content
      
      # Flush buffer if it's full, in sync mode, or buffer is getting stale
      should_flush = @buffer.size >= @buffer_size || 
                     @f.sync || 
                     (Time.now - @last_flush > 5.0 && !@buffer.empty?)
      
      if should_flush
        flush_buffer_unsafe
      end
    end
  end
  
  # Force flush the buffer (thread-safe)
  def flush_buffer
    @mutex.synchronize do
      flush_buffer_unsafe
    end
  end
  
  private
  
  # Flush buffer without mutex (must be called within synchronized block)
  def flush_buffer_unsafe
    return if @buffer.empty?
    
    # Join all buffered content with newlines and write as one block
    combined_output = @buffer.join("\n")
    @f.puts combined_output
    
    @buffer.clear
    @last_flush = Time.now
  end

  # perform sort, uniq and join on each plugin result
  def suj(plugin_results)
    suj = {}
    [:certainty, :version, :os, :string, :account, :model, :firmware, :module, :filepath].map do |thissymbol|
      t = plugin_results.map { |x| x[thissymbol] unless x[thissymbol].class == Regexp }.flatten.compact.sort.uniq.join(',')
      suj[thissymbol] = t
    end
    suj[:certainty] = plugin_results.map { |x| x[:certainty] }.flatten.compact.sort.last.to_i # this is different, it's a number
    suj
  end

  # sort and uniq but no join. just for one plugin result
  def sortuniq(p)
    su = {}
    [:name, :certainty, :version, :os, :string, :account, :model, :firmware, :module, :filepath].map do |thissymbol|
      next if p[thissymbol].class == Regexp
      t = p[thissymbol]
      t = t.flatten.compact.sort.uniq if t.is_a?(Array)
      su[thissymbol] = t unless t.nil?
    end
    # certainty is different, it's a number
    su[:certainty] = p[:certainty].to_i
    su
  end
end


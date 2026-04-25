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

require_relative 'colour'

#
# Message handling functions for consistent output throughout WhatWeb
# Provides thread-safe, color-coded messaging with proper severity levels
#

#
# Display error messages
#
def error(s)
  return if $NO_ERRORS

  $semaphore.reentrant_synchronize do
    # TODO: make use_color smart, so it detects a tty
    STDERR.puts((($use_colour == 'auto') || ($use_colour == 'always')) ? red(s) : s)
    # REMOVED: STDERR.flush for better performance
    $LOG_ERRORS.out(s) if $LOG_ERRORS
  end
end

#
# Display warning messages
#
def warning(s)
  return if $NO_ERRORS || $QUIET

  $semaphore.reentrant_synchronize do
    STDERR.puts((($use_colour == 'auto') || ($use_colour == 'always')) ? yellow(s) : s)
    # REMOVED: STDERR.flush for better performance
    $LOG_ERRORS.out("WARNING: #{s}") if $LOG_ERRORS
  end
end

#
# Display notice messages (less severe than warnings)
#
def notice(s)
  return if $QUIET

  $semaphore.reentrant_synchronize do
    STDERR.puts((($use_colour == 'auto') || ($use_colour == 'always')) ? blue(s) : s)
    # REMOVED: STDERR.flush for better performance
  end
end

#
# Display debug messages (only in verbose debug mode)
#
def debug(s)
  return unless $verbose && $verbose > 2

  $semaphore.reentrant_synchronize do
    STDERR.puts((($use_colour == 'auto') || ($use_colour == 'always')) ? grey("[DEBUG] #{s}") : "[DEBUG] #{s}")
    # REMOVED: STDERR.flush for better performance
  end
end

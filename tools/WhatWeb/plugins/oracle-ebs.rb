##
# This file is part of WhatWeb and may be subject to
# redistribution and commercial restrictions. Please see the WhatWeb
# web site for more information on licensing and terms of use.
# https://morningstarsecurity.com/research/whatweb
#
Plugin.define do
	name "Oracle-EBS"
	authors [
		"Francesco Pavanello <frapava98@gmail.com>", # 2025-10-08
	]
	version "0.1"
	description "Oracle E-Business Suite supports today’s evolving business models, drives productivity, and meets the demands of the modern mobile user."
	website "https://www.oracle.com/applications/ebusiness/"

	# Dorks #
    dorks [
        'intitle:"E-Business Suite Home Page Redirect"'
    ]

	# This is the matches array.
	# Each match is treated independently.

	# Matches #
	matches [

		# Title
		{ :text => "<TITLE>E-Business Suite Home Page Redirect</TITLE>", :certainty => 90  },

		# Match meta refresh redirect
		{ :regexp => /<meta[^>]+http-equiv=["']?refresh["']?[^>]+URL=[^'"]*\/OA_HTML\/[^'"]+/i, :certainty => 85 },

		# Match direct link or presence of OA_HTML in page
        { :regexp => /\/OA_HTML\/[^\s'"]+/, :certainty => 70 },

        # Match Location header
        { :search=>"headers[location]", :regexp => /\/OA_HTML\//, :certainty => 95 },

        # Match redirect via JavaScript
        { :regexp => /document\.location\.replace\(['"]http[^'"]*\/OA_HTML\/[^'"]+['"]\)/, :certainty => 90 },

	]

end
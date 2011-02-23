
##
# $Id: registry.rb 11789 2011-02-22 02:02:04Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'test',
				'Description'   => %q{ This module will test registry stuff },
				'License'       => MSF_LICENSE,
				'Author'        => [ 'kernelsmith'],
				'Version'       => '$Revision: 11789 $',
				'Platform'      => [ 'windows' ]
			))
		register_options(
		[
				OptString.new("KEY" , [true, "Registry key to test", "HKLM\\Software\\Microsoft\\Active Setup"]),
				OptString.new("VALUE" , [true, "Registry value to test", "DisableRepair"]),
			], self.class)

	end

	def run
		print_status("Running against session #{datastore["SESSION"]}")
		print_status("Session type is #{session.type}")

		print_status()
		print_status("TESTING:  registry_getvalinfo for key:#{datastore['KEY']}, val:#{datastore['VALUE']}")
		results = registry_getvalinfo(datastore['KEY'], datastore['VALUE'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("TESTING:  registry_getvaldata for key:#{datastore['KEY']}, val:#{datastore['VALUE']}")
		results = registry_getvaldata(datastore['KEY'], datastore['VALUE'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_createkey for key:#{datastore['KEY']}\\test")
		results = registry_createkey("#{datastore['KEY']}\\test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_setvaldata for key:#{datastore['KEY']}\\test, val:test, data:test, type:REG_SZ")
		results = registry_setvaldata("#{datastore['KEY']}\\test", "test", "test", "REG_SZ")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("Running registry_getvalinfo for freshly created key:#{datastore['KEY']}\\test, val:test")
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_deleteval for key:#{datastore['KEY']}\\test, val:test")
		results = registry_deleteval("#{datastore['KEY']}\\test", "test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_deletekey")
		results = registry_deletekey("#{datastore['KEY']}\\test")
		print_error("reported failure") if results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("Running registry_getvalinfo for deleted key:#{datastore['KEY']}\\test, val:test")
		print_status("NOTE: this should return an error hash where :error is cannot find file...")
		results = registry_getvalinfo("#{datastore['KEY']}\\test", "test")
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		if (results[:error] =~ /SYSTEM CANNOT FIND/i)
			print_status("Delete worked correctly")
		elsif (results == nil)
			print_error("reported failure, the previous deletekey did not work")
		else
			print_error("the previous deletekey might not have worked, I expected an error here!")
		end

		print_status()
		print_status("TESTING:  registry_enumkeys")
		results = registry_enumkeys(datastore['KEY'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")

		print_status()
		print_status("TESTING:  registry_enumvals")
		results = registry_enumvals(datastore['KEY'])
		print_error("reported failure") unless results
		print_status("RESULTS:  #{results.class} #{results.inspect}")
		
		print_status()
		print_status("Testing Complete!")

	end

end



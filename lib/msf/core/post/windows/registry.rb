
require 'msf/core/post/windows/cli_parse'

module Msf
class Post

module Registry

	include Msf::Post::Windows::CliParse

	#
	# Create the given registry key
	#
	def registry_createkey(key)
		if session_has_registry_ext
			meterpreter_registry_createkey(key)
		else
			shell_registry_createkey(key)
		end
	end

	#
	# Deletes a registry value given the key and value name
	#
	# returns true if succesful
	#
	def registry_deleteval(key, valname)
		if session_has_registry_ext
			meterpreter_registry_deleteval(key, valname)
		else
			shell_registry_deleteval(key, valname)
		end
	end

	#
	# Delete a given registry key
	#
	# returns true if succesful
	#
	def registry_deletekey(key)
		if session_has_registry_ext
			meterpreter_registry_deletekey(key)
		else
			shell_registry_deletekey(key)
		end
	end

	#
	# Return an array of subkeys for the given registry key
	#
	def registry_enumkeys(key)
		if session_has_registry_ext
			meterpreter_registry_enumkeys(key)
		else
			shell_registry_enumkeys(key)
		end
	end

	#
	# Return an array of value names for the given registry key
	#
	def registry_enumvals(key)
		if session_has_registry_ext
			meterpreter_registry_enumvals(key)
		else
			shell_registry_enumvals(key)
		end
	end

	#
	# Return the data of a given registry key and value
	#
	def registry_getvaldata(key, valname)
		if session_has_registry_ext
			meterpreter_registry_getvaldata(key, valname)
		else
			shell_registry_getvaldata(key, valname)
		end
	end

	#
	# Return the data and type of a given registry key and value
	#
	#
	def registry_getvalinfo(key,valname)
		if session_has_registry_ext
			meterpreter_registry_getvalinfo(key, valname)
		else
			shell_registry_getvalinfo(key, valname)
		end
	end

	#
	# Sets the data for a given value and type of data on the target registry
	#
	# returns true if succesful
	#
	def registry_setvaldata(key, valname, data, type)
		if session_has_registry_ext
			meterpreter_registry_setvaldata(key, valname, data, type)
		else
			shell_registry_setvaldata(key, valname, data, type)
		end
	end
	
	#
	# Checks to see if a given key value exists.  Returns Boolean
	#
	#
	def registry_value_exist?(key,valname)
		if session_has_registry_ext
			meterpreter_registry_value_exist?(key,valname)
		else
			shell_registry_value_exist?(key,valname)
		end
	end
	
	#
	# Checks to see if a given key exists.  Returns Boolean
	#
	#
	def registry_key_exist?(key)
		if session_has_registry_ext
			meterpreter_registry_key_exist?(key)
		else
			shell_registry_key_exist?(key)
		end
	end

	#
	# Normalize the supplied full registry key string so the root key is sane.  For
	# instance, passing "HKLM\Software\Dog" will return 'HKEY_LOCAL_MACHINE\Software\Dog'
	#
	def normalize_key(key)
		keys = split_key(key)
		if (keys[0] =~ /HKLM|HKEY_LOCAL_MACHINE/)
			keys[0] = 'HKEY_LOCAL_MACHINE'
		elsif (keys[0] =~ /HKCU|HKEY_CURRENT_USER/)
			keys[0] = 'HKEY_CURRENT_USER'
		elsif (keys[0] =~ /HKU|HKEY_USERS/)
			keys[0] = 'HKEY_USERS'
		elsif (keys[0] =~ /HKCR|HKEY_CLASSES_ROOT/)
			keys[0] = 'HKEY_CLASSES_ROOT'
		elsif (keys[0] =~ /HKCC|HKEY_CURRENT_CONFIG/)
			keys[0] = 'HKEY_CURRENT_CONFIG'
		elsif (keys[0] =~ /HKPD|HKEY_PERFORMANCE_DATA/)
			keys[0] = 'HKEY_PERFORMANCE_DATA'
		elsif (keys[0] =~ /HKDD|HKEY_DYN_DATA/)
			keys[0] = 'HKEY_DYN_DATA'
		else
			raise ArgumentError, "Cannot normalize unknown key: #{key}"
		end
		return keys.join("\\")
	end

protected

	#
	# Determines whether the session can use meterpreter registry methods
	#
	def session_has_registry_ext
		begin
			return !!(session.sys and session.sys.registry)
		rescue NoMethodError
			return false
		end
	end

	##
	# Native Meterpreter-specific registry manipulation methods
	##
	############################################################
	
##
#
# Registry Permissions
#
##
#KEY_QUERY_VALUE          = 0x00000001
#KEY_SET_VALUE            = 0x00000002
#KEY_CREATE_SUB_KEY       = 0x00000004
#KEY_ENUMERATE_SUB_KEYS   = 0x00000008
#KEY_NOTIFY               = 0x00000010
#KEY_CREATE_LINK          = 0x00000020
#KEY_READ                 = (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE |KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY) & ~SYNCHRONIZE
#KEY_WRITE                = (STANDARD_RIGHTS_WRITE | KEY_SET_VALUE |KEY_CREATE_SUB_KEY) & ~SYNCHRONIZE
#KEY_EXECUTE              = KEY_READ
#KEY_ALL_ACCESS           = (STANDARD_RIGHTS_ALL | KEY_QUERY_VALUE |......

	
	def meterpreter_registry_value_exist?(key,valname) 
		begin
			a = self.meterpreter_registry_getvalinfo(key, valname)
			return true if !!(a["Data"] or a["Type"])
		rescue NoMethodError
			return false
		end 
	end
	
	def meterpreter_registry_key_exist?(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			return true if open_key
		rescue Rex::Post::Meterpreter::RequestError  # other errors?
			return false
		ensure open_key.close if open_key
		end
		return false
	end

	def meterpreter_registry_createkey(key)  #sets
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.create_key(root_key, base_key)
			open_key.close if open_key
			return nil
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error creating registry key #{e.to_s}")
		end
	end

	def meterpreter_registry_deleteval(key, valname)  #sets
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.delete_value(valname)
			open_key.close if open_key
			return nil
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error deleting registry value #{e.to_s}")
		end
	end

	def meterpreter_registry_deletekey(key)  #sets
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			deleted = session.sys.registry.delete_key(root_key, base_key)
			return nil if deleted
			raise Rex::Post::Meterpreter::RequestError.new(__method__,deleted,nil)
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error deleting registry key #{e.to_s}")
		end
	end

	def meterpreter_registry_enumkeys(key)  #gets
		subkeys = []
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			return nil if !open_key
			keys = open_key.enum_key
			keys.each { |subkey|
				subkeys << subkey
			}
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		ensure
			open_key.close if open_key
		end
		return subkeys
	end

	def meterpreter_registry_enumvals(key)  #gets
		values = []
		begin
			vals = {}
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			return nil if !open_key
			vals = open_key.enum_value
			vals.each { |val|
				values <<  val.name
			}
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		ensure
			open_key.close if open_key
		end
		return values
	end

	def meterpreter_registry_getvaldata(key, valname)  #gets
		value = nil
		begin
			h = self.meterpreter_registry_getvalinfo(key,valname)
			value = h["Data"] if h
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		end
		return value
	end

	def meterpreter_registry_getvalinfo(key, valname)  #gets
		value = {}
		key = normalize_key(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			return nil if !open_key
			v = open_key.query_value(valname)
			value["Data"] = v.data
			value["Type"] = v.type
		rescue Rex::Post::Meterpreter::RequestError => e
			return nil
		ensure
			open_key.close if open_key
		end
		return value
	end

	def meterpreter_registry_setvaldata(key, valname, data, type)  #sets
		key = normalize_key(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.set_value(valname, session.sys.registry.type2str(type), data)
			return nil
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error("Error setting the registry value for #{key} #{valname}.  #{e.to_s}")
		ensure
			open_key.close if open_key
		end
	end
	
	################   '+._.+'-Shell Versions-'+._.+'   #############
	
	##
	# Generic registry manipulation methods based on reg.exe
	##
	
	#REG_NONE                 = 0	#REG_DWORD_LITTLE_ENDIAN  = 4
	#REG_SZ                   = 1	#REG_DWORD_BIG_ENDIAN     = 5
	#REG_EXPAND_SZ            = 2	#REG_LINK                 = 6
	#REG_BINARY               = 3	#REG_MULTI_SZ             = 7
	#REG_DWORD                = 4
	
	#sets:  returns nil on success, exception on fail
	#gets:  returns something on success, nil on fail & exception for unparsable results

	def shell_registry_value_exist?(key,valname)
		v = self.shell_registry_getvaldata(key,valname)
		return true if (v and !v.empty?)
		return false
	end
	
	def shell_registry_key_exist?(key)
		v = self.shell_registry_enumkeys(key)
		return true if v
		return false
	end

	def shell_registry_createkey(key)  #sets
		key = normalize_key(key)
		begin
			# REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
			cmd = "cmd.exe /c reg add \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				return nil
			elsif results =~ /^Error:/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error creating key #{key}:  #{eh[:error]}",eh[:errval],cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_registry_deleteval(key, valname)  #sets
		key = normalize_key(key)
		begin
			# REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
			cmd = "cmd.exe /c reg delete \"#{key}\" /v \"#{valname}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				return nil
			elsif results =~ /^Error:/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error deleting value #{key}:  #{eh[:error]}",eh[:errval],cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_registry_deletekey(key)  #sets
		key = normalize_key(key)
		begin
			# REG DELETE KeyName [/v ValueName | /ve | /va] [/f]
			cmd = "cmd.exe /c reg delete \"#{key}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				return nil
			elsif results =~ /^Error:/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error deleting key #{key}:  #{eh[:error]}",eh[:errval],cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
		end
	end

	def shell_registry_enumkeys(key)  #gets
		key = normalize_key(key)
		subkeys = []
		reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|' 
		reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR' 
		begin
			bslashes = key.count('\\')
			cmd = "cmd.exe /c reg query \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ Regexp.new(Regexp.escape(key)) #if the supplied key is in the output
				results.each_line do |line|
					# now let's keep the ones that have a count = bslashes+1 cuz reg query is
					# always recursive.  Feels like there's a smarter way to do this but...
					if (line.count('\\') == bslashes+1 && !line.ends_with?('\\'))
						#then it's a first level subkey
						subkeys << line.split('\\').last.chomp # take & chomp the last item only
					end
				end
				return subkeys
			elsif results =~ /^Error:/
				return nil
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
	end

	def shell_registry_enumvals(key)  #gets
		key = normalize_key(key)
		values = []
		reg_data_types = 'REG_SZ|REG_MULTI_SZ|REG_DWORD_BIG_ENDIAN|REG_DWORD|REG_BINARY|' 
		reg_data_types << 'REG_DWORD_LITTLE_ENDIAN|REG_NONE|REG_EXPAND_SZ|REG_LINK|REG_FULL_RESOURCE_DESCRIPTOR'
		begin
			# REG QUERY KeyName [/v ValueName | /ve] [/s]
			cmd = "cmd.exe /c reg query \"#{key}\""
			results = session.shell_command_token_win32(cmd)
			if values = results.scan(/^ +.*[#{reg_data_types}].*/)
				# yanked the lines with legit REG value types like REG_SZ
				# now let's parse out the names (first field basically)
				values.collect! do |line|
					t = line.split(' ')[0].chomp #chomp for good measure
					# check if reg returned "<NO NAME>", which splits to "<NO", if so nil instead
					t = nil if t == "<NO"
					t
				end
				return values
			elsif results =~ /^Error:/
				return nil
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
	end

	def shell_registry_getvaldata(key,valname)  #gets
		begin
			a = shell_registry_getvalinfo(key,valname)
			return a["Data"] if a
			return nil
		end
	end

	def shell_registry_getvalinfo(key, valname)  #gets
		key = normalize_key(key)
		info = {}
		begin
			# REG QUERY KeyName [/v ValueName | /ve] [/s]
			cmd = "cmd.exe /c reg query \"#{key}\" /v \"#{valname}\""
			results = session.shell_command_token_win32(cmd)
			if match_arr = /^ +#{valname}.*/i.match(results)
				# pull out the interesting line (the one with the value name in it)
				# and split it with ' ' yielding [valname,REGvaltype,REGdata]
				split_arr = match_arr[0].split(' ')
				info["Type"] = split_arr[1]
				info["Data"] = split_arr[2]
				return info
			elsif results =~ /^Error:/
				return nil
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
		return value
	end

	def shell_registry_setvaldata(key, valname, data, type)  #sets
		key = normalize_key(key)
		begin
			# REG ADD KeyName [/v ValueName | /ve] [/t Type] [/s Separator] [/d Data] [/f]
			# /f to overwrite w/o prompt
			cmd = "cmd.exe /c reg add \"#{key}\" /v \"#{valname}\" /t \"#{type}\" /d \"#{data}\" /f"
			results = session.shell_command_token_win32(cmd)
			if results =~ /The operation completed successfully/
				return nil
			elsif results =~ /^Error:/
				eh = win_parse_error(results)
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Error setting val data #{key}:  #{eh[:error]}",eh[:errval],cmd)
			else
				raise Msf::Post::Windows::CliParse::ParseError.new(
					__method__,"Unparsable error:  #{results}",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::ParseError => e
			print_error(e.to_s)
			return nil
		end
	end

	#
	# Split the supplied full registry key string into its root key and base key.  For
	# instance, passing "HKLM\Software\Dog" will return [ 'HKEY_LOCAL_MACHINE',
	# 'Software\Dog' ]
	#
	def split_key(str)
		if (str =~ /^(.+?)\\(.*)$/)
			[ $1, $2 ]
		else
			[ str, nil ]
		end
	end

end
end
end

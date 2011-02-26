
require 'msf/core/post/windows/cli_parse'

module Msf
class Post

module WindowsServices

	include Msf::Post::Windows::CliParse
	include ::Msf::Post::Registry
	
	NOTIMP = "This method has not been implemented yet"
	
	def service_list
		if session_has_services_depend?
			meterpreter_service_list
		else
			shell_service_list
		end
	end
	
	def service_list_running
		if session_has_services_depend?
			#meterpreter_service_list_running
			NOTIMP
		else
			shell_service_list_running
		end
	end
	
	def service_info(name)
		if session_has_services_depend?
			meterpreter_service_info(name)
		else
			shell_service_info(name)
		end
	end

	def service_change_startup(name,mode)
		if session_has_services_depend?
			meterpreter_service_change_startup(name,mode)
		else
			shell_service_change_startup(name,mode)
		end
	end

	def service_create(name, display_name, executable_on_host,startup=2)
		if session_has_services_depend?
			meterpreter_service_create(name, display_name, executable_on_host,startup)
		else
			shell_service_create(name, display_name, executable_on_host,startup)
		end
	end
	
	def service_start(name)
		if session_has_services_depend?
			meterpreter_service_start(name)
		else
			shell_service_start(name)
		end
	end
	
	def service_stop(name)
		if session_has_services_depend?
			meterpreter_service_stop(name)
		else
			shell_service_stop(name)
		end
	end
	
	def service_delete(name)
		if session_has_services_depend?
			meterpreter_service_delete(name)
		else
			shell_service_delete(name)
		end
	end
	
	def service_query_config(name)
		if session_has_services_depend?
			#meterpreter_query_config(name)
			NOTIMP
		else
			shell_service_query_config(name)
		end
		
	end
	
	def service_query_ex(name)
		if session_has_services_depend?
			#meterpreter_service_query_ex(name)
			NOTIMP
		else
			shell_service_query_ex(name)
		end	
	end
	
	def service_query_state(name)
		if session_has_services_depend?
			#meterpreter_service_query_state(name)
			NOTIMP
		else
			shell_service_query_state(name)
		end	
	end
	
	#
	# Ensures mode is sane, like what sc.exe wants to see, e.g. 2 or "AUTO_START" etc returns "auto"
	# If the second argument it true, integers are returned instead of strings  
	#
	def normalize_mode(mode,i=false)
		mode = mode.to_s # someone could theoretically pass in a 2 instead of "2"
		# accepted boot|system|auto|demand|disabled
		if mode =~ /(0|BOOT)/i
			mode = i ? 0 : 'boot' # mode is 'boot', unless i is true, then it's 0
		elsif mode =~ /(1|SYSTEM)/i
			mode = i ? 1 : 'system'
		elsif mode =~ /(2|AUTO)/i
			mode = i ? 2 : 'auto'
		elsif mode =~ /(3|DEMAND|MANUAL)/i
			mode = i ? 3 : 'demand'
		elsif mode =~ /(4|DISABLED)/i
			mode = i ? 4 : 'disabled'
		end
		return mode		
	end
	
	protected
	#
	# Determines whether the session can use meterpreter services methods
	#
	def session_has_services_depend?
		return false if session.type == "shell" # shell is bad enough, otherwise check dependencies
		begin
			return true if (session.sys.registry and session.railgun)
		rescue NoMethodError
			return false
		end
	end
	
	##
	# Native Meterpreter-specific windows service manipulation methods
	##
	
	#
	# List all Windows Services present. Returns an Array containing the names
	# of the services, whether they are running or not.
	# TODO:  On failure return error hash?
	#
	def meterpreter_service_list
		serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		threadnum = 0
		a =[]
		services = []
		meterpreter_registry_enumkeys(serviceskey).each do |s|
			if threadnum < 10
				a.push(::Thread.new(s) { |sk|
						begin
							srvtype = registry_getvaldata("#{serviceskey}\\#{sk}","Type").to_s
							if srvtype =~ /32|16/
								services << sk
							end
						rescue
						end
					})
				threadnum += 1
			else
				sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
				threadnum = 0
			end
		end
		return services
	end

	#
	# Get Windows Service information. 
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.
	#
	def meterpreter_service_info(name)
		# add rescue?
		service = {}
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
		srvstart = registry_getvaldata(servicekey,"Start").to_i
		service["Startup"] = normalize_mode(srvstart)
		service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
		service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
		return service
	end

	#
	# Changes a given service startup mode, name must be provided and the mode.
	#
	# Mode is a string with either auto, manual or disable, or corresponding
	# integer (see normalize_mode). The name of the service is case sensitive.
	#
	def meterpreter_service_change_startup(name,mode)
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		mode = normalize_mode(mode,true).to_s # the string version of the int, e.g. "2"
		begin
			registry_setvaldata(servicekey,"Start",mode,"REG_DWORD")
			return nil
		rescue::Exception => e
			return win_parse_error("ERROR:#{e}") # return an error_hash	
		end
	end

	#
	# Create a service that runs it's own process.
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup mode as an integer of 2 for Auto, 3 for
	# Manual or 4 for Disable, but strings will converted when possible using normalize_mode.
	# Default is Auto.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_create(name, display_name, executable_on_host,mode=2)
		mode = normalize_mode(mode,true)
		adv = client.railgun.get_dll('advapi32')
		manag = adv.OpenSCManagerA(nil,nil,0x13)
		if(manag["return"] != 0)
			# SC_MANAGER_CREATE_SERVICE = 0x0002
			newservice = adv.CreateServiceA(manag["return"],name,display_name,
				0x0010,0X00000010,mode,0,executable_on_host,nil,nil,nil,nil,nil)
			adv.CloseServiceHandle(newservice["return"])
			adv.CloseServiceHandle(manag["return"])
			#SERVICE_START=0x0010  SERVICE_WIN32_OWN_PROCESS= 0X00000010
			#SERVICE_AUTO_START = 2 SERVICE_ERROR_IGNORE = 0
			if newservice["GetLastError"] == 0
				return nil
			elsif newservice["GetLastError"] == 1072
				#return 1
				return {:errval => 1072 , :error => 'The specified service has been marked for deletion'}
			else
				return {:errval => 9999 , :error => "#{newservice.pretty_inspect}"}
			end
		else
			raise "Could not open Service Control Manager, Access Denied"
		end
	end

	#
	# Start a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_start(name)
		adv = client.railgun.get_dll('advapi32')
		manag = adv.OpenSCManagerA(nil,nil,1)
		if(manag["return"] == 0)
			raise "Could not open Service Control Manager, Access Denied"
		end
		#open with  SERVICE_START (0x0010)
		servhandleret = adv.OpenServiceA(manag["return"],name,0x10)
		if(servhandleret["return"] == 0)
			adv.CloseServiceHandle(manag["return"])
			raise "Could not Open Service, Access Denied"
		end
		retval = adv.StartServiceA(servhandleret["return"],0,nil)
		adv.CloseServiceHandle(servhandleret["return"])
		adv.CloseServiceHandle(manag["return"])
		if retval["GetLastError"] == 0
			return nil
		elsif retval["GetLastError"] == 1056
			#return 1
			return {:errval => 1056 , :error => 'An instance of the service is already running.'}
		elsif retval["GetLastError"] == 1058
			#return 2
			return {:errval => 1058 , :error => 'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.'}
		end
	end

	#
	# Stop a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_stop(name)
		adv = client.railgun.get_dll('advapi32')
		manag = adv.OpenSCManagerA(nil,nil,1)
		if(manag["return"] == 0)
			raise "Could not open Service Control Manager, Access Denied"
		end
		#open with  SERVICE_STOP (0x0020)
		servhandleret = adv.OpenServiceA(manag["return"],name,0x30)
		if(servhandleret["return"] == 0)
			adv.CloseServiceHandle(manag["return"])
			raise "Could not Open Service, Access Denied"
		end
		retval = adv.ControlService(servhandleret["return"],1,56)
		adv.CloseServiceHandle(servhandleret["return"])
		adv.CloseServiceHandle(manag["return"])
		if retval["GetLastError"] == 0
			return nil
		elsif retval["GetLastError"] == 1062
			#return 1
			return {:errval => 1062 ,:error => 'The service has not been started.'}
		elsif retval["GetLastError"] == 1052
			#return 2
			return {:errval => 1052 ,:error => 'The requested control is not valid for this service.'}
		end
	end

	#
	# Delete a service by deleting the key in the registry.
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_delete(name)
		begin
			basekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
			if registry_enumkeys(basekey).index(name)
				servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
				registry_deletekey(servicekey)
				return nil
			else
				return win_parse_error("ERROR:Could not find #{name} as a registered service") # return an error_hash
			end
		rescue::Exception => e
			return win_parse_error("ERROR:#{e}") # return an error_hash
		end
	end
	
	### shell versions ###
	
	#
	# List all Windows Services present.  Returns an Array containing the names
	# of the services, whether they are running or not.
	# On failure returns an error hash
	#
	def shell_service_list
		#SERVICE_NAME: Winmgmt
		#DISPLAY_NAME: Windows Management Instrumentation
        	# <...etc...>
		#
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service state= all"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						services << h[:service_name]
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return services
	end
	
	#
	# List all running Windows Services.  Returns an Array containing the names
	# of the running
	# On failure returns an error hash
	#
	def shell_service_list_running
		#SERVICE_NAME: Winmgmt
		#DISPLAY_NAME: Windows Management Instrumentation
        	# <...etc...>
		#
		services = []
		begin
			cmd = "cmd.exe /c sc query type= service"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME:/
				results.each_line do |line| 
					if line =~ /SERVICE_NAME:/
						h = win_parse_results(line)
						services << h[:service_name]
					end 
				end
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return services
	end
	
	#
	# Get Windows Service config information. 
	#
	# Info returned stuffed into a hash with all info that sc.exe qc <service_name> will cough up
	# Service name is case sensitive.
	# Hash keys match the keys returned by sc.exe qc <service_name>, but downcased and symbolized
	# e.g returns {
	# :service_name => "winmgmt",
	# :type => "20 WIN32_SHARE_PROCESS",
	# :start_type => "2 AUTO_START",
	# <...>
	# :dependencies => "RPCSS,OTHER",
	# :service_start_name => "LocalSystem" }
	#
	# On failure returns an error hash
	# etc.  see sc qc /? for more info
	#
	def shell_service_query_config(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc qc #{name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				#[SC] QueryServiceConfig SUCCESS
				#
				#SERVICE_NAME: winmgmt
				#        TYPE               : 20  WIN32_SHARE_PROCESS
				#        START_TYPE         : 2   AUTO_START
				#        ERROR_CONTROL      : 0   IGNORE
				#        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs
				#        <...>
				#        DISPLAY_NAME       : Windows Management Instrumentation
				#        DEPENDENCIES       : RPCSS
				#        		    : OTHER
				#        SERVICE_START_NAME : LocalSystem
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# then syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe qc")
			end
		end
		return service
	end
	
	#
	# Get Windows Service information. 
	#
	# Information returned in a hash with display name, startup mode and
	# command executed by the service. Service name is case sensitive.  Hash
	# keys are Name, Start, Command and Credentials.  Here for compatibility with meterp version
	#
	# On failure returns an error hash
	#
	def shell_service_info(name)
		service = {}
		begin
			h = shell_service_query_config(name)
			return h if h[:error] # if there was an error w/ the config query, return the error_hash
			service['Name'] = h[:service_name]
			service["Startup"] = normalize_mode(h[:start_type])
			service['Command'] = h[:binary_path_name]
			service['Credentials'] = h[:service_start_name]
		end
		return service
	end

	#
	# Get Extended Windows Service information. 
	#
	# Info returned stuffed into a hash with all info that sc.exe queryex <service_name> will cough up
	# Service name is case sensitive.
	# Hash keys match the keys returned by sc.exe qc <service_name>
	# e.g returns {
	# :service_name => "winmgmt",
	# :type => "20 WIN32_SHARE_PROCESS",
	# :state => "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN",
	# <...>
	# :pid = > "1088",
	# :flags => nil}
	#
	# On failure returns an error hash
	# etc.  see sc queryex /? for more info
	#
	def shell_service_query_ex(name)
		service = {}
		begin
			cmd = "cmd.exe /c sc queryex #{name.chomp}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SERVICE_NAME/ # NOTE: you can't use /SUCCESS/ here
				#SERVICE_NAME: winmgmt
				#        TYPE               : 20  WIN32_SHARE_PROCESS
				#        STATE              : 4  RUNNING
				#                                (STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN)
				#        WIN32_EXIT_CODE    : 0  (0x0)
				#        SERVICE_EXIT_CODE  : 0  (0x0)
				#        CHECKPOINT         : 0x0
				#        WAIT_HINT          : 0x0
				#        PID                : 1088
				#        FLAGS              :
				# 
				service = win_parse_results(results)
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
		return service
	end
	
	#
	# Get Windows Service state only. 
	#
	# returns a string with state info such as "4 RUNNING,STOPPABLE,PAUSABLE,ACCEPTS_SHUTDOWN"
	# could normalize it to just "RUNNING" if desired, but not currently
	# On failure returns error hash
	#
	
	def shell_service_query_state(name)
		begin
			h = service_query_ex(name)
			return h if h[:error] # if there was an error with the query, return the error_hash
			return h[:state] # otherwise return the state
		end
		return nil
	end

	#
	# Changes a given service startup mode, name and mode must be provided.
	#
	# Mode is an int or string with either 2/auto, 3/manual or 4/disable for the
	# corresponding setting. The name of the service is case sensitive.
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	#sc <server> config [service name] start= <boot|system|auto|demand|disabled|delayed-auto>
	def shell_service_change_startup(name,mode)
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc config #{name} start= #{mode}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")
			end
		end
	end

	#
	# Create a service that runs it's own process.
	#
	# It takes as values the service name as string, the display name as
	# string, the path of the executable on the host that will execute at
	# startup as string and the startup type as an int or string of 2/Auto,
	# 3/Manual, or 4/disable, default is Auto.
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	# TODO: convert to take a hash so a variable number of options can be provided?
	#
	def shell_service_create(name, display_name = "Server Service", executable_on_host = "", mode = "auto")
		#  sc create [service name] [binPath= ] <option1> <option2>...
		begin
			mode = normalize_mode(mode)
			cmd = "cmd.exe /c sc create #{name} binPath= \"#{executable_on_host}\" " +
				"start= #{mode} DisplayName= \"#{display_name}\""
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe") 
			end
		end
	end

	#
	# Start a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def shell_service_start(name)
		begin
			cmd = "cmd.exe /c sc start #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /(SUCCESS|START_PENDING)/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
	end

	#
	# Stop a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def shell_service_stop(name)
		begin
			cmd = "cmd.exe /c sc stop #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif results =~ /(^Error:.*|FAILED.*:)/
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
	end

	#
	# Delete a service
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def shell_service_delete(name)
		begin
			cmd = "cmd.exe /c sc delete #{name}"
			results = session.shell_command_token_win32(cmd)
			if results =~ /SUCCESS/
				return nil
			elsif match_arr = /^Error:.*|FAILED.*:/.match(results)
				return win_parse_error(results) # return an error_hash
			elsif results =~ /SYNTAX:/
				# Syntax error
				return win_parse_error("ERROR:Syntax Error, cmd was #{cmd}")
			else
				return win_parse_error("ERROR:Unknown error running sc.exe")  
			end
		end
	end
	
end

end
end

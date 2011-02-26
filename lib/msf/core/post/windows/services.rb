
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
		begin
			return !!(session.sys.registry and session.railgun)
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
	# TODO:  additional exception handling here?
	#
	def meterpreter_service_list
		serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
		threadnum = 0
		a =[]
		services = []
		begin
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
		rescue Exception => e
			print_error(e.to_s)
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
		service = {}
		servicekey = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\#{name.chomp}"
		begin
			service["Name"] = registry_getvaldata(servicekey,"DisplayName").to_s
			srvstart = registry_getvaldata(servicekey,"Start").to_i
			service["Startup"] = normalize_mode(srvstart)
			service["Command"] = registry_getvaldata(servicekey,"ImagePath").to_s
			service["Credentials"] = registry_getvaldata(servicekey,"ObjectName").to_s
		rescue Exception => e
			print_error(e.to_s)
		end
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
			print_error(e.to_s)
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
		begin
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
					raise Rex::Post::Meterpreter::RequestError.new(__method__,'The specified service has been marked for deletion',newservice["GetLastError"])
				else
					raise Rex::Post::Meterpreter::RequestError.new(__method__,"Railgun Hash:  #{newservice.pretty_inspect}",newservice["GetLastError"])
				end
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error(e.to_s)
		end
	end

	#
	# Start a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_start(name)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_START (0x0010)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x10)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.StartServiceA(servhandleret["return"],0,nil)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1056
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'An instance of the service is already running.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1058
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.',retval["GetLastError"])
			else
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service cannot be started, because of an unknown error',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error(e.to_s)
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless (manag.nil? or manag["return"] == 0)
			adv.CloseServiceHandle(servhandleret["return"]) unless (servhandleret.nil? or
			servhandleret["return"] == 0)
		end
	end

	#
	# Stop a service.
	#
	# Returns nil if success, otherwise an error hash {:errval => int,:error => 'Error message'}
	#
	def meterpreter_service_stop(name)
		adv = client.railgun.get_dll('advapi32')
		begin
			manag = adv.OpenSCManagerA(nil,nil,1)
			if(manag["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not open Service Control Manager, Access Denied",manag["GetLastError"])
			end
			#open with  SERVICE_STOP (0x0020)
			servhandleret = adv.OpenServiceA(manag["return"],name,0x30)
			if(servhandleret["return"] == 0)
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not Open Service, Access Denied",servhandleret["GetLastError"])
			end
			retval = adv.ControlService(servhandleret["return"],1,56)
			if retval["GetLastError"] == 0
				return nil
			elsif retval["GetLastError"] == 1062
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The service has not been started.',retval["GetLastError"])
			elsif retval["GetLastError"] == 1052
				raise Rex::Post::Meterpreter::RequestError.new(__method__,'The requested control is not valid for this service.',retval["GetLastError"])
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error(e.to_s)
		ensure 
			adv.CloseServiceHandle(manag["return"]) unless (manag.nil? or manag["return"] == 0)
			adv.CloseServiceHandle(servhandleret["return"]) unless (servhandleret.nil? or
			servhandleret["return"] == 0)
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
				raise Rex::Post::Meterpreter::RequestError.new(__method__,"Could not find #{name} as a registered service.",nil)
			end
		rescue::Exception => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
			service['Name'] = h[:service_name]
			service["Startup"] = normalize_mode(h[:start_type])
			service['Command'] = h[:binary_path_name]
			service['Credentials'] = h[:service_start_name]
		rescue Exception => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
			return h[:state] # return the state
		rescue Exception => e
			print_error(e.to_s)
		end
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
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
			elsif results =~ /(^Error:.*|FAILED.*:)/
				win_parse_error(results,cmd,__method__) # raises error
			elsif results =~ /SYNTAX:/
				# Syntax error
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Syntax error",nil,cmd)
			else
				raise Msf::Post::Windows::CliParse::RequestError.new(__method__,"Unparsable error",nil,cmd)
			end
		rescue Msf::Post::Windows::CliParse::RequestError => e
			print_error(e.to_s)
		end
	end
	
end

end
end

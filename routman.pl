#!/usr/bin/perl -s

##
# Routman - Remote Router Manager
#
# Requirements: Data::Dumper, Net::Telnet, Net::Ping, Net::IP, Time::Piece
#
# Copyright (c) 2013 CYBER GATES company (http://www.cybergates.org)
#
# Routman is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, version 3 of the License, or
# (at your option) any later version.
#
# Routman is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Routman. If not, see <http://www.gnu.org/licenses/>.
#
# @category Administration
# @category Security
# @version 1.0
# @author Samvel Gevorgyan <samvel@cybergates.org>
# @license http://www.gnu.org/licenses/lgpl.html LGPL
# @link http://www.cybergates.org
##

# Load required modules
#use warnings;
use Data::Dumper;
use Net::Telnet;
use Net::Ping;
use Net::IP;
use Time::Piece;

# Default parameters
my $defaultusr = 'admin';
my $defaultpwd = 'admin';
my $masterpwd = 'admin';
my $time  = time;
my $now = localtime->strftime('%Y-%m-%d %H:%M:%S');
my $i : shared;
$i = 1;

# Check required parameters
if (!$ip && !$range) {
  print "\n[ HELP ]";
  print "\nOptions:";
  print "\n[+] -ip: Scan a single IP address. (e.g.: 127.0.0.1)";
  print "\n[+] -range: Scan an IP range. (e.g.: 127.0.0.1-127.0.0.254)";
  print "\n[+] -run(Optional): Run a command. (e.g.: show all)";
  print "\n[+] -log(Optional): Save the output in a file. (e.g.: log.txt)";
  print "\nExamples:";
  print "\n[+] router_remote_admin.pl -ip=\"192.168.1.1\"";
  print "\n[+] router_remote_admin.pl -range=\"192.168.1.1-192.168.1.254\"";
  print "\n[+] router_remote_admin.pl -ip=\"192.168.1.1\" -run=\"ifconfig\" -log=\"example.log\"";
  print "\n";
  exit;
}

# Define custom functions
# Display the cpecified message in the screen and/or log into the log file
sub message
{
  my ($message) = @_;
  print $message."\n";
  if ($log ne "") {
      print LOG $message."\n";
  }
}

# Open log file for 
if ($log ne "") { open (LOG, ">>$log"); }

if ($ip ne "") {
  message "[!] Scanning a single IP address: $ip";
  message "[i] Date: $now";
  
  # Send a ping request to see if the host is reachable
  $ping = Net::Ping->new("tcp", 2);
  # Try connecting to the www port instead of the echo port
  $ping->port_number(scalar(getservbyname("http", "tcp")));

  if (!$ping->ping($ip)) {
      print "[$i] $ip | Offline.";
    } else {
      $telnet = new Net::Telnet (timeout=>10,errmode=>'return');
      $telnet->open("$ip");
      $prompt = $telnet->waitfor(-match=>'/login: ?$/i',-errmode=>'return');
      if ($prompt) { $telnet->print("$defaultusr"); }
      $prompt = $telnet->waitfor(-match=>'/password: ?$/i',-errmode=>'return');
      if ($prompt)  { $telnet->print("$defaultpwd"); }
      @logout = $telnet->waitfor(-match=>'/password: ?$/i',-errmode=>'return');
      if (@logout) {
          message "[$i] $ip | Unable to login.";
        } else {
          $telnet->waitfor('/$/i');
          @resetpwd = $telnet->cmd("sys password $masterpwd");
          if (!@resetpwd) {
            message "[$i] $ip | Unable to change the device password.";
          } else {
              message "[$i] $ip | The default password has been successfully changed.";
          }
          if ($run ne "") {
            @cmd = $telnet->cmd("$run");
            open (DUMP, ">>$ip.txt");
            print DUMP "#>$run\n";
            print DUMP "# ----------$now---------- #\n";
            print DUMP "@cmd\n";
            print DUMP "# -------------------------- #\n";
            close (DUMP);
          }
        }
    }
  undef($ping);
  #exit;
}
if ($range ne "") {
  message "[!] Scanning an IP range: $range";
  message "[i] Date: $now\n";
  my $ip = new Net::IP ("$range");
  
  # Send a ping request to see if the host is reachable
  $ping = Net::Ping->new("tcp", 2);
  # Try connecting to the www port instead of the echo port
  $ping->port_number(scalar(getservbyname("http", "tcp")));
  
  # Connect to each of the modems
  do {
    if (!$ping->ping($ip->ip())) {
      message "[$i] ".$ip->ip()." | Offline.";
    } else {
      $telnet = new Net::Telnet (timeout=>10,errmode=>"return");
      $telnet->open($ip->ip());
      $prompt = $telnet->waitfor(-match=>'/login: ?$/i',-errmode=>'return');
      if ($prompt) { $telnet->print("$defaultusr"); }
      $prompt = $telnet->waitfor(-match=>'/password: ?$/i',-errmode=>'return');
      if ($prompt)  { $telnet->print("$defaultpwd"); }
      @logout = $telnet->waitfor(-match=>'/password: ?$/i',-errmode=>'return');
      if (@logout) {
          message "[$i] ".$ip->ip()." | Unable to login.";
        } else {
          $telnet->waitfor('/$/i');
          @resetpwd = $telnet->cmd("sys password $masterpwd");
          if (!@resetpwd) {
            message "[$i] ".$ip->ip()." | Unable to change the device password.";
          } else {
              message "[$i] ".$ip->ip()." | The default password has been successfully changed.";
          }
          if ($run ne "") {
            @cmd = $telnet->cmd("$run");
            open (DUMP, ">>".$ip->ip().".txt");
            print DUMP "#>$run\n";
            print DUMP "# ----------$now---------- #\n";
            print DUMP "@cmd\n";
            print DUMP "# -------------------------- #\n";
            close (DUMP);
          }
        }
    }
    ++$i;
  } while (++$ip);
  undef($ping);
  #exit;
}

$time = time-$time;
if($time => 60){$t = 'min';$time = int ($time / 60). '';}else{$t = 'sec';}
message "\n[i] Total time: $time $t\n";

# Close the log file
if ($log) { close (LOG); }
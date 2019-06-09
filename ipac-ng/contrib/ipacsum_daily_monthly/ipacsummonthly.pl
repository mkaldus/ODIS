#!/usr/bin/perl -w

use strict;
use DateTime;
use MIME::Lite;
use File::Spec;
use Sys::Hostname::FQDN qw(short);

my $csvpath = '/var/lib/ipac/csv';	# Path to store CSV files
my $sender = 'root';			# E-mail sender address
my $recipient = 'root';			# E-mail recipient(s) address. Set it to empty string to disable mailung.

my $dt = DateTime->now(time_zone  => 'local')->truncate( to => 'month' );
$dt->subtract( months => 1 ); # The beginning of previous month
my $dtt = $dt->strftime('%m/%Y');
mkdir $csvpath;
my $fn = 'Monthly-' . $dt->strftime('%Y%m') . '.csv';
my $fnpath = File::Spec->catfile( $csvpath, $fn );
my ($scriptvol, $scriptdir);
($scriptvol, $scriptdir, ) = File::Spec->splitpath(__FILE__);
my $ipacsummonth = File::Spec->catpath($scriptvol, $scriptdir, 'ipacsummonth.pl' );
`$ipacsummonth $dtt $fnpath`;
if ($sender) {
	if ($recipient) {
		if (-e $fnpath) {
			my $msg = MIME::Lite->new(
        			From     => $sender,
        			To       => $recipient,
		        	Subject  => short() . ": Monthly traffic statistic - $dtt",
                		Type     => 'multipart/mixed'
		    	);

			$msg->attach(
				Type 	 => 'text/plain; charset="UTF-8"',
				Encoding => '8bit',
				Data     => 'See monthly traffic statistic file in attachment.'
			);

			$msg->attach(
        			Type     => 'application/octet-stream',
        			Encoding => 'base64',
        			Path     => $fnpath,
				Disposition => 'attachment'
			);

			$msg->send;
		}
	}
}


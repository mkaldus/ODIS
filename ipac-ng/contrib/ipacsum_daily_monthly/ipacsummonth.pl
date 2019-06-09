#!/usr/bin/perl


use strict;
use DateTime;

my @data=();
my %columns;
my @dates=();
my $outfile=$ARGV[1];
my $year;
my $month;

if(!$outfile) {
	&print_usage();
	exit(1);
}


if($ARGV[0]!~/(\d{2})\/(\d{4})/) {
	&print_usage();
	exit(1);
}
else {
	$year=$2;
	$month=$1;
}

my $i;
my $j=0;

my $dt = DateTime->new(   year   => $year,
                          month  => $month,
                          time_zone  => 'local'
                        );
my $dt1 = $dt->clone;

while ($month == $dt->month) {

	$dt1->add( days => 1 );
	my $t1=$dt->strftime('%Y%m%d');
	my $t2=$dt1->strftime('%Y%m%d');
	my @output = `/usr/sbin/ipacsum -x -s $t1 -e $t2 2>/dev/null`;
	
	if($#output>=3) {
		for $i(3 .. $#output) {
			
			$output[$i]=~/\s*(.*?)\s*:\s*(\d*)/;
			$columns{$1}=1;
			$data[$j]{$1}=$2;
		}
	}
	else {
	
		$data[$j]={};
		
	}
	$dates[$j]=$dt->dmy('/');
	$dt->add( days => 1 );
	$j++;
}

open(OUT,">$outfile") or print "Could not open $outfile\n";
my @col= sort keys %columns;
my $outline='Date';
for $i(0 .. $#col) {

	$outline .= ';' . $col[$i];	

}

print OUT "$outline\n";

for $j(0 .. $#data) {

	$outline=$dates[$j];

	for $i(0 .. $#col) {

		$outline .= ';' . $data[$j]{$col[$i]} ;
	}
	print OUT "$outline\n";

}

close OUT;

 sub print_usage {
	print "\n==============================\n";
	print " ipacsummonth.pl - 2007-02-12\n";
	print "==============================\n\n";
	print "Creates CSV file with statistic for given month, one line per day.\n\n";
	print "Usage:\n\n";
	print "ipacsummonth.pl MM/YYYY outfile.csv\n\n";
}

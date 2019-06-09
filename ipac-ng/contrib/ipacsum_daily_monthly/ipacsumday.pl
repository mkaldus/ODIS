#!/usr/bin/perl


use strict;
use DateTime;

my @data=();
my %columns;
my @dates=();
my $outfile=$ARGV[1];
my $year;
my $month;
my $day;

if(!$outfile) {
	&print_usage();
	exit(1);
}


if($ARGV[0]!~/(\d{2})\/(\d{2})\/(\d{4})/) {
	&print_usage();
	exit(1);
}
else {
	$year=$3;
	$month=$2;
	$day=$1;
}

my $i;
my $j=0;

my $dt = DateTime->new(   year   => $year,
                          month  => $month,
                          day  => $day,
                          time_zone  => 'local'
                        );
my $dt1 = $dt->clone;

while ($day == $dt->day) {

	$dt1->add( hours => 1 );
	my $t1=$dt->strftime('%Y%m%d%H');
	my $t2=$dt1->strftime('%Y%m%d%H');
	my @output = `ipacsum -x -s $t1 -e $t2 2>/dev/null`;
	
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
	$dates[$j]=$dt->strftime('%d/%m/%y %R') . $dt1->strftime('-%R') ;
	$dt->add( hours => 1 );
	$j++;
}

open(OUT,">$outfile") or print "Could not open $outfile\n";
my @col= sort keys %columns;
my $outline='Date Time';
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
	print " ipacsumday.pl - 2007-02-15\n";
	print "==============================\n\n";
	print "Creates CSV file with statistic for given day, one line per hour.\n\n";
	print "Usage:\n\n";
	print "ipacsumday.pl DD/MM/YYYY outfile.csv\n\n";
}
 

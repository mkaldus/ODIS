#!/usr/bin/perl

##################################################
# written by Matthias Lendholt (Berlin, Germany)
# last changed on 20041107
##################################################

# This script collects all data of /var/lib/ipac and creates an csv file for 
# further processing. I wrote it to create a diagram with all flows in one 
# image (ipacsum creates one image per flow).
# Since I used it to measure values in a short time, this script only works
# correctly if the interval between two measurments is not larger than 60s.
# (You can correct this quite easily I think...) 
# The output is generated in a csv file (well, semicolon separated file) 
# named out.ccv in your actual working directory. 
# The script opens all files of the mentioned directory and assumes that 
# the order is correct. It calculates the interval from the file names 
# and as a result you will get kilo byte / second. If you don't want this, 
# just delete the "/1024" somewhere below.
# Finally, the result is in XXXX,YY format not XXXXX.YY ... German format :)

use strict;

my @data=(); # collects all data
my %columns; # collects all column names
my $last=undef;
my $count=0;
open(OUT,">out.csv") or print "Could not open out.csv\n";
opendir(DIR,"/var/lib/ipac") or print "Can not open directory /var/lib/ipac.\n";
while (defined(my $file=readdir(DIR))){
	next if $file=~/^\.\.?$/;
	my $check=0;
	my @names=();
	my @values=();
	my $diff=1;
	if (defined $last){	
		# just check seconds, no check if more than one minute has gone
		my $a=$last;
		my $b=$file;
		$a=~s/^.*?(\d\d)$/$1/;
		$b=~s/^.*?(\d\d)$/$1/;
		if ($a>$b){
			$diff=60-$a+$b;
		}else{
			$diff=$b-$a;
		}
	}
	open(TEMP, "</var/lib/ipac/$file") or print "Could not open $file.\n";
	while (<TEMP>){
        	chomp;
        	if (/^#-#-#-#-#/){
        		$check=1;
        		next;
        	}
        	unless ($check){
        		$columns{$_}=1;
        		push @names,$_;
        	}else{
        		/^\d+ (\d+)$/;
			my $temp=$1/$diff;
			$temp=$temp/1024;
			$temp=~s/\./,/;
        		push @values,$temp;
        	}
	}
	for (my $j=0;$j<$diff;$j++){
		for (my $i=0;$i<@names;$i++){
			$data[$count]->{$names[$i]}=$values[$i];
		}
		$count++;
		#print "$count \n";
	}
	$last=$file;
}
closedir(DIR);
my @cols=();
for my $column(keys %columns){
	push @cols,$column;
}
open(OUT,">out.csv") or die "Could not open out.csv\n";
print OUT "TIMESTAMP";
for my $column(@cols){
	print OUT ";$column";
}
print OUT "\n";
for (my $row=0;$row<@data;$row++){
	print OUT $row;
	for my $column(@cols){
		if (defined $data[$row]->{$column}){
			print OUT ";".$data[$row]->{$column};
		}else{
			print OUT ";0";
		}
	}
	print OUT "\n";
}
close (OUT);

=pod

=head1 NAME

Net::IP::RangeCompare - Perl extension for IP Range Comparisons

=cut

package Net::IP::RangeCompare;

use strict;
use warnings;
use Data::Dumper;
use Scalar::Util qw(blessed);
use Carp qw(croak);
use vars qw($error $VERSION @ISA @EXPORT_OK %EXPORT_TAGS);
$VERSION=3.019;
use Scalar::Util qw(looks_like_number);
use overload
        '""' => \&notation
  ,'fallback' => 1;

use constant key_start_ip =>0;
use constant key_end_ip =>1;
use constant key_generated=>2;
use constant key_missing=>3;
use constant key_data=>4;
use constant ALL_BITS=>0xffffffff;
use constant MAX_CIDR=>32;


=head1 SYNOPSIS

  use Net::IP::RangeCompare;
  my $obj=Net::IP::RangeCompare::Simple->new;

  $obj->add_range('Tom','10.0.0.2 - 10.0.0.11');
  $obj->add_range('Tom','10.0.0.32 - 10.0.0.66');
  $obj->add_range('Tom','11/32');

  $obj->add_range('Sally','10.0.0.7 - 10.0.0.12');
  $obj->add_range('Sally','172.16/255.255.255');

  $obj->add_range('Harry','192.168.2');
  $obj->add_range('Harry','10.0.0.128/30');

  $obj->compare_ranges; # optional

        while(my ($common,%row)=$obj->get_row) {
                print "\nCommon Range: ",$common,"\n";
                my $tom=$row{Tom};
                my $sally=$row{Sally};
                my $harry=$row{Harry};
                print "Tom: ",$tom
                        ,' '
                        ,($tom->missing ? 'not used' : 'in use')
                        ,"\n";

                print "Sally: ",$sally
                        ,' '
                        , ($sally->missing ? 'not used' : 'in use')
                        ,"\n";

                print "Harry: ",$harry,
                        ' '
                        ,($harry->missing ? 'not used' : 'in use')
                        ,"\n";
        }


  Output: 

  Common Range: 10.0.0.2 - 10.0.0.6
  Tom: 10.0.0.2 - 10.0.0.11 in use
  Sally: 10.0.0.2 - 10.0.0.6 not used
  Harry: 10.0.0.2 - 10.0.0.127 not used

  Common Range: 10.0.0.7 - 10.0.0.11
  Tom: 10.0.0.2 - 10.0.0.11 in use
  Sally: 10.0.0.7 - 10.0.0.12 in use
  Harry: 10.0.0.2 - 10.0.0.127 not used

  Common Range: 10.0.0.12 - 10.0.0.12
  Tom: 10.0.0.12 - 10.0.0.31 not used
  Sally: 10.0.0.7 - 10.0.0.12 in use
  Harry: 10.0.0.2 - 10.0.0.127 not used

  Common Range: 10.0.0.32 - 10.0.0.66
  Tom: 10.0.0.32 - 10.0.0.66 in use
  Sally: 10.0.0.13 - 172.15.255.255 not used
  Harry: 10.0.0.2 - 10.0.0.127 not used

  Common Range: 10.0.0.128 - 10.0.0.131
  Tom: 10.0.0.67 - 10.255.255.255 not used
  Sally: 10.0.0.13 - 172.15.255.255 not used
  Harry: 10.0.0.128 - 10.0.0.131 in use

  Common Range: 11.0.0.0 - 11.0.0.0
  Tom: 11.0.0.0 - 11.0.0.0 in use
  Sally: 10.0.0.13 - 172.15.255.255 not used
  Harry: 10.0.0.132 - 192.168.1.255 not used

  Common Range: 172.16.0.0 - 172.16.0.255
  Tom: 11.0.0.1 - 192.168.2.0 not used
  Sally: 172.16.0.0 - 172.16.0.255 in use
  Harry: 10.0.0.132 - 192.168.1.255 not used

  Common Range: 172.16.1.0 - 192.168.1.255
  Tom: 11.0.0.1 - 192.168.2.0 not used
  Sally: 172.16.1.0 - 192.168.2.0 not used
  Harry: 10.0.0.132 - 192.168.1.255 not used

  Common Range: 192.168.2.0 - 192.168.2.0
  Tom: 11.0.0.1 - 192.168.2.0 not used
  Sally: 172.16.1.0 - 192.168.2.0 not used
  Harry: 192.168.2.0 - 192.168.2.0 in use

=head1 DESCRIPTION

Fast scalable ip range aggregation and summary tool kit.  Find intersections across multiple lists of IP ranges, fast. 

Although similar in functionality to Net::CIDR::Compare, Net::Netmask and NetAddr::IP, Net::IP::RangeCompare is a completely range driven ip management and evaluation tool allowing more flexibility and scalability when dealing with the somewhat organic nature of IP-Ranges.

If you have a large number of ipv4 ranges and need to inventory lists of ranges for intersections, this is the Module for you!

=cut


require Exporter;
@ISA=qw(Exporter);

@EXPORT_OK=qw(
  hostmask
  cidr_to_int
  ip_to_int
  int_to_ip
  size_from_mask
  base_int
  broadcast_int
  cmp_int
  sort_quad
  sort_notations
  add_one
  sub_one

  sort_ranges 
  sort_largest_first_int_first
  sort_smallest_last_int_first
  sort_largest_last_int_first 
  sort_smallest_first_int_first

  get_overlapping_range
  get_common_range

  consolidate_ranges
  range_start_end_fill
  fill_missing_ranges
  range_compare
  compare_row
  range_compare_force_cidr
  );

%EXPORT_TAGS = (
  ALL=>\@EXPORT_OK
  ,HELPER=>[qw(
    hostmask
    cidr_to_int
    ip_to_int
    int_to_ip
    sort_quad
  size_from_mask
  base_int
  broadcast_int
  cmp_int
  sort_notations
  add_one
  sub_one
  )]
  ,SORT=>[qw(
    sort_ranges 
    sort_largest_first_int_first
    sort_smallest_last_int_first
    sort_largest_last_int_first 
    sort_smallest_first_int_first
  )]
  ,OVERLAP=>[qw(
    get_overlapping_range
    get_common_range
  )]
  ,PROCESS=>[qw(
    consolidate_ranges
    range_start_end_fill
    fill_missing_ranges
    range_compare
    compare_row
    range_compare_force_cidr
  )]
);

=head2 Export list

Net::IP::RangeCompare does not export anything by default.  The functions listed in this section can be imported by using the standard import syntax.

Import example:

  use Net::IP::RangeCompare qw(consolidate_ranges sort_ranges);

To import all functions:

  use Net::IP::RangeCompare qw(:ALL);

Helper functions  :HELPER

  use Net::IP::RangeCompare qw(:HELPER);

  Imports the following:

          hostmask
          ip_to_int
          int_to_ip
          cidr_to_int
	  size_from_mask 
	  base_int 
	  broadcast_int 
	  cmp_int
	  sort_quad
	  sort_notations
  	  add_one
          sub_one

Overlap functions :OVERLAP

  use Net::IP::RangeCompare qw(:OVERLAP);

  Imports the following:

          get_common_range
          get_overlapping_range

Sort Functions :SORT

  use Net::IP::RangeCompare qw(:SORT);

  Imports the following:

          sort_ranges
          sort_largest_first_int_first
          sort_smallest_last_int_first
          sort_largest_last_int_first
          sort_smallest_first_int_first

Range processing functions :PROCESS

  use Net::IP::RangeCompare qw(:PROCESS);

  Imports the following:

          consolidate_ranges
          fill_missing_ranges
          range_start_end_fill
          range_compare
          compare_row
	  range_compare_force_cidr

=head2 OO Methods

This section defines the OO interfaces.

=over 4

=item * my $obj=Net::IP::RangeCompare->parse_new_range('10/32');

Creates a new Net::IP::RangeCompare object.

  Examples:
  $obj=Net::IP::RangeCompare->parse_new_range('10');
  $obj=Net::IP::RangeCompare->parse_new_range('10.0.0.0 - 10.0.0.0');
  $obj=Net::IP::RangeCompare->parse_new_range('10/32');
  $obj=Net::IP::RangeCompare->parse_new_range('10/255.255.255');
  $obj=Net::IP::RangeCompare->parse_new_range('10.0.0.0','10.0.0.0');

  All of the above will parse the same range: 
    10.0.0.0 - 10.0.0.0
  Notes:
    When using a list syntax: start and end range are
    assumed.  Using 2 arguments will not work as 
    expected when the list consists of ip and cidr.
  Example:
    $obj=Net::IP::RangeCompare->parse_new_range('10.0.0.0',32);
    Returns: 10.0.0.0 - 32.0.0.0

    $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0'
      ,'255.255.255.255
    );
    Returns: 10.0.0.0 - 32.0.0.0

    If you wish to create an object from cidr boundaries
    pass the argument as a single string.
  Example:
    $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0'.'/'.32
    );
    Returns: 10.0.0.0 - 10.0.0.0
  Example: 
    $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0'
      .'/'
      .'255.255.255.255
    );
    Returns: 10.0.0.0 - 10.0.0.0

=cut

sub parse_new_range {
  my ($s,@sources)=@_;
  my $source;
  if($#sources==0) {
    $source=$sources[0];
  } else {
    my ($ip,$mask)=@sources;
    $source=join ' - ',$ip,$mask;
    return $s->new_from_range($source);
  }

  if(ref($source)) {
    # may be an existing oo object
    my $class=blessed($source);
    if($class) {
      return $source if $class eq (caller)[0];
      $source=join '',$source;
    } else {
      $error="reference passed for parsing";
      return undef;
    }
  }
  return $s->new_from_cidr($source) if $source=~ /\//;
  return $s->new_from_range($source) if $source=~ /-/;
  return $s->new_from_ip($source);

}

=item * my $obj=Net::IP::RangeCompare->new(0,1);

Creates a new Net::IP::RangeCompare object from 2 integers.  See: Net::IP::RangeCompare->parse_new_range for a more useful OO constructor.

=cut

sub new {
  my ($package,$key_start_ip,$key_end_ip,$generated,$missing)=@_;

  unless(defined($key_start_ip) and defined($key_end_ip)) {
    $error="Start and End Ip need to be defined";
    return undef;
  }
  unless(
    looks_like_number($key_start_ip) 
    and 
    looks_like_number($key_end_ip)
    ) {
    
    $error="First or last ip do not look like numbers";
    return undef;
  }
  if($key_start_ip>$key_end_ip) {
    $error="Start ip needs to be less than or equal to End Ip";
    return undef;
  }
  bless [$key_start_ip,$key_end_ip,$generated,$missing],$package;
}

##########################################################
#
# OO Stubs

=item * my $int=$obj->first_int;

Returns the integer that represents the start of the ip range

=cut

sub first_int () { $_[0]->[key_start_ip] }

=item * my $int=$obj->last_int;

Returns the integer that represents the end of the ip range

=cut

sub last_int () { $_[0]->[key_end_ip] }

=item * my $first_ip=$obj->first_ip;

Returns the first ip in the range.

=cut

sub first_ip () { int_to_ip($_[0]->[key_start_ip]) }

=item * my $last_ip=$obj->last_ip;

Returns the last ip in the range;

=cut

sub last_ip () { int_to_ip($_[0]->[key_end_ip]) }

=item * if($obj->missing) { .. do something } else { .. do something else }

If the value is true, this range is a filler representing an ip range that was not found.

=cut

sub missing () {$_[0]->[key_missing] }

=item * if($obj->generated) { .. do something } else { .. do something else }

If the value is true, this range was created internally by one of the following functions: fill_missing_ranges, range_start_end_fill, consolidate_ranges.  

When a range is $obj->generated but not $obj->missing it represents a collection of overlapping ranges.

=cut

sub generated () {$_[0]->[key_generated] }

=item * my $last_error=$obj->error;

Returns the last error

=cut

sub error () { $error }

##########################################################
#

=item * my $total_ips=$obj->size;

Returns the total number of ipv4 addresses in this range.

=cut

sub size () {
  my ($s)=@_;
  return 1+$s->last_int - $s->first_int;
}

##########################################################
#

=item * $obj->data->{some_tag}=$some_data; # sets the data

=item * my $some_data=$obj->data->{some_tag}; # gets the data

Returns an anonymous hash that can be used to tag this block with your data.  

=cut

sub data () {
  my ($s)=@_;

  # always return the data ref if it exists
  return $s->[key_data] if ref($s->[key_data]);

  $s->[key_data]={};

  $s->[key_data]
}

##########################################################
#

=item * my $notation=$obj->notation;

Returns the ip range in the standard "x.x.x.x - x.x.x.x" notation.

Simply calling the Net::IP::RangeCompare object in a string context will return the same output as using the $obj->notation Method.
Example:

  my $obj=Net::IP::RangeCompare->parse_new_range('10.0.0.1/255');
  print $obj,"\n";
  print $obj->notation,"\n";

  Output:

  10.0.0.0 - 10.255.255.255
  10.0.0.0 - 10.255.255.255

=cut

sub notation {
  my ($s)=@_;

  join ' - '
    ,int_to_ip($s->first_int)
    ,int_to_ip($s->last_int)
}

############################################
#

=item * my $cidr_notation=$obj->get_cidr_notation;

Returns string representing all the cidrs in a given range.

  Example a:

    $obj=Net::IP::RangeCompare->parse_new_range('10/32');
    print $obj->get_cidr_notation,"\n"

    Output:
    10.0.0.0/32


  Example b:
    $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0 10.0.0.4'
    );
    print $obj->get_cidr_notation,"\n"

    Output:
    10.0.0.0/30, 10.0.0.4/32

=cut

sub get_cidr_notation () {
  my ($s)=@_;
  my $n=$s;
  my $return_ref=[];
  my ($range,$cidr);
  while($n) {
    ($range,$cidr,$n)=$n->get_first_cidr;
    push @$return_ref,$cidr;
  }
  join(', ',@$return_ref);

}

##########################################################
#

=item * if($obj->overlap('10/32') { }

Returns true if the 2 ranges overlap.  Strings are auto converted to Net::IP::RangeCompare Objects on the fly.

=cut

sub overlap ($) {
  my ($range_a,$range_b)=@_;
  my $class=blessed $range_a;
  $range_b=$class->parse_new_range($range_b);

  # return true if range_b's start range is contained by range_a
  return 1 if 
      #$range_a->first_int <=$range_b->first_int 
      $range_a->cmp_first_int($range_b)!=1
        &&
      #$range_a->last_int >=$range_b->first_int;
      $range_a->cmp_last_int($range_b)!=-1;

  # return true if range_b's end range is contained by range_a
  return 1 if 
      #$range_a->first_int <=$range_b->last_int 
      cmp_int($range_a->first_int,$range_b->last_int )!=1
        &&
      #$range_a->last_int >=$range_b->last_int;
      cmp_int($range_a->last_int,$range_b->last_int)!=-1;

  return 1 if 
      #$range_b->first_int <=$range_a->first_int 
      $range_b->cmp_first_int($range_a)!=1
        &&
      #$range_b->last_int >=$range_a->first_int;
      $range_b->cmp_last_int($range_a)!=-1;

  # return true if range_b's end range is contained by range_a
  return 1 if 
      #$range_b->first_int <=$range_a->last_int 
      cmp_int($range_b->first_int,$range_a->last_int )!=1
        &&
      #$range_b->last_int >=$range_a->last_int;
      cmp_int($range_b->last_int,$range_a->last_int)!=-1;

  # return undef by default
  undef
}

=item * my $int=$obj->next_first_int;

Fetches the starting integer for the next range;

=cut

sub next_first_int () { add_one($_[0]->last_int)  }

=item * my $int=$obj->previous_last_int;

Returns an integer representing the first interger of the pervious range.

=cut

sub previous_last_int () { sub_one($_[0]->first_int)  }

=item * my ($range,$cidr_nota,$next)=$obj->get_first_cidr;

Iterator function:

  Returns the following
  $range
    First range on a cidr boundary in $obj
  $cidr_ntoa
    String containing the cidr format
  $next
    Next Range to process, undef when complete

Example:

    my $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0 - 10.0.0.4'
    );
    my ($first,$cidr_note,$next)=$obj->get_first_cidr;

Example:

    # this gets every range
    my $obj=Net::IP::RangeCompare->parse_new_range(
      '10.0.0.0 - 10.0.0.4'
    );
    my ($first,$cidr,$next);
    $next=$obj;
    while($next) {
      ($first,$cidr,$next)=$next->get_first_cidr;
      print "Range Notation: ",$first,"\n";
      print "Cidr Notation : ",$cidr,"\n";
    }

    Output:
    Range Notation: 10.0.0.0 - 10.0.0.3
    Cidr Notation : 10.0.0.0/30
    Range Notation: 10.0.0.4 - 10.0.0.4
    Cidr Notation : 10.0.0.4/32

=cut

sub get_first_cidr () {
  my ($s)=@_;
  my $class=blessed $s;
  my $first_cidr;
  my $output_cidr;
  for(my $cidr=MAX_CIDR;$cidr>-1;--$cidr) {
    $output_cidr=MAX_CIDR - $cidr;
    my $mask=cidr_to_int($output_cidr);

    my $hostmask=hostmask($mask);
    my $size=size_from_mask($mask);

    next if $s->mod_first_int($size);


    my $last_int=$s->first_int + $hostmask;
    next if cmp_int($last_int,$s->last_int)==1;

    $first_cidr=$class->new($s->first_int,$last_int);

    last;
  }
  my $cidr_string=join('/',int_to_ip($first_cidr->first_int),$output_cidr);

  if($first_cidr->cmp_last_int($s)==0) {
    return ( $first_cidr ,$cidr_string);
  } else {
    return ( 
      $first_cidr 
      ,$cidr_string
      ,$class->new(
        $first_cidr->next_first_int
        ,$s->last_int
      )
    );
  }

}

=item * if($obj->is_cidr) { do something }

This function can be used to check if a range represents a single cidr.

=cut

sub is_cidr () {
  my ($s)=@_;
  my ($range,$cidr,$next)=$s->get_first_cidr;
  my $is_cidr=defined($next) ? 0 : 1;
  $is_cidr
}

=item * if($obj->is_range) { do something }

This function can be used to check if a range contains multiple cidrs.

=cut

sub is_range () {
  my ($s)=@_;
  my ($range,$cidr,$next)=$s->get_first_cidr;
  my $is_range=defined($next) ? 1 : 0;
  $is_range
}

=item * my $ipv4=$obj->nth(0);

Returns the nth ipv4 address in the range.  Returns undef if the ip is out of the range.

Example:

  my $obj=Net::IP::RangeCompare->parse_new_range('10/24');
  my $base=$obj->nth(0);
  my $broadcast=$obj->nth(255);

  print $base,"\n";
  print $broadcast,"\n";

  Output
  10.0.0.0
  10.0.0.255

=cut

sub nth ($) {
	my ($s,$offset)=@_;
	my $int=$s->first_int + $offset;
	return undef if cmp_int($int,$s->last_int)==1;
	int_to_ip($int);
}

=item * my @list=$obj->base_list_int;

Returns each start address as an integer for every cidr boundry.

=item * my @list=$obj->base_list_ip;

Returns each start address as an ipv4 quad for every cidr boundry.

=item * my @list=$obj->broadcast_list_ip;

Returns each end address as an ipv4 quad for every cidr boundry.

=item * my @list=$obj->broadcast_list_int;

Returns each end address as an integer for every cidr boundry.

=cut

sub _internal_ip_list_func ($) {
  my ($s,$mode)=@_;
  my $next=$s;
  my @list;
  my $ip;
  while($next) {
    ($ip,undef,$next)=$next->get_first_cidr;
    if($mode eq 'first_int') {
      push @list,$ip->first_int;
    } elsif($mode eq 'first_ip') {
      push @list,$ip->first_ip;
    } elsif($mode eq 'last_ip') {
      push @list,$ip->last_ip;
    } elsif($mode eq 'last_int') {
      push @list,$ip->last_int;
    }
  }
  @list;
}

sub base_list_int () { $_[0]->_internal_ip_list_func('first_int') }
sub base_list_ip () { $_[0]->_internal_ip_list_func('first_ip') }
sub broadcast_list_int () { $_[0]->_internal_ip_list_func('last_int') }
sub broadcast_list_ip () { $_[0]->_internal_ip_list_func('last_ip') }

###########################################
#

=item * my $sub=$obj->enumerate(1-32);

=item * my $sub=$obj->enumerate;

Returns an anonymous subroutine that can be used to iterate through the entire range.  The iterator can be used to safely walk any range even 0/0.  Each iteration of $sub returns a new Net::IP::RangeCompare object or undef on completion.

The default cidr to iterate by is "32".


Example:

  my $obj=Net::IP::RangeCompare->parse_new_range('10/30');
  my $sub=$obj->enumerate;
  while(my $range=$sub->()) {
    print $range,"\n"
  }
  Output:
  10.0.0.0 - 10.0.0.0
  10.0.0.1 - 10.0.0.1
  10.0.0.2 - 10.0.0.2
  10.0.0.3 - 10.0.0.3

  $sub=$obj->enumerate(31);
  while(my $range=$sub->()) {
    print $range,"\n"
  }
  Output:
  10.0.0.0 - 10.0.0.1
  10.0.0.2 - 10.0.0.3

=cut

sub enumerate {
  my ($s,$cidr)=@_;
  $cidr=MAX_CIDR unless $cidr;
  my $mask=cidr_to_int($cidr);
  my $hostmask=hostmask($mask);
  my $n=$s;
  my $class=blessed $s;
  sub {
    return undef unless $n;
    #my $cidr_end=($n->first_int & $mask) + $hostmask;
    my $cidr_end=broadcast_int($n->first_int , $mask);
    my $return_ref;
    if(cmp_int($cidr_end,$n->last_int)!=-1) {
      $return_ref=$n;
      $n=undef;
    } else {
      $return_ref=$class->new(
        $n->first_int
        ,$cidr_end
      );
      $n=$class->new(
        $return_ref->next_first_int
        ,$n->last_int
      );
    }
    $return_ref;
  }
}

=item * my $sub=$obj->enumerate_size;

=item * my $sub=$obj->enumerate_size(2);

Returns an anonymous subruteen that can be used to walk the current range in ingrements of x ips.  Default value is 1.

Example:

  my $obj=Net::IP::RangeCompare->parse_new_range('10.0.0.0 - 10.0.0.6');

  my $sub=$obj->enumerate_size;

  print "Inc by 1\n";
  while(my $range=$sub->()) {
    print $range,"\n";
  }

  print "Inc by 3\n";
  $sub=$obj->enumerate_size(3);
  while(my $range=$sub->()) {
    print $range,"\n";
  }

  Output:
  Inc by 1
  10.0.0.0 - 10.0.0.1
  10.0.0.2 - 10.0.0.3
  10.0.0.4 - 10.0.0.5
  10.0.0.6 - 10.0.0.6

  Inc by 3
  10.0.0.0 - 10.0.0.3
  10.0.0.4 - 10.0.0.6


=cut

sub enumerate_size {
  my ($s,$inc)=@_;
  my $class=blessed $s;
  $inc=1 unless $inc;
  my $done;
  sub {
    return undef if $done;
    my $first=$s->first_int;
    my $next=$first + $inc;
    my $last;
    if(cmp_int($s->last_int,$next)!=-1) {
      $last=$next;
    } else {
      $last=$s->last_int;
    }
    my $new_range=$class->new($first,$last);
    $done=1 if $s->cmp_last_int($new_range)==0;
    $s=$class->new($new_range->next_first_int,$s->last_int);
    $new_range;
  }
}

=item * if($obj_a->cmp_first_int($obj_b)==0) { }

This function compares the first integer of 2 Net::IP::RangeCompare objects.

Returns

  0  if $obj_a->first_int==$obj_b->last_int
  -1 if $obj_a->first_int<$obj_b->first_int
  1  if $obj_a->first_int>$obj_b->first_int

=cut

sub cmp_first_int($) {
  my ($s,$cmp)=@_;
  cmp_int($s->first_int,$cmp->first_int)
}

=item * if($obj_a->cmp_last_int($obj_b)==0) { }


This function compares the last integer of 2 Net::IP::RangeCompare objects.

Returns

  0  if $obj_a->last_int==$obj_b->last_int
  -1 if $obj_a->last_int<$obj_b->last_int
  1  if $obj_a->last_int>$obj_b->last_int

=cut

sub cmp_last_int($) {
  my ($s,$cmp)=@_;
  cmp_int($s->last_int,$cmp->last_int)
}

=item * if($obj->contiguous_check($obj_next)) { do something }

Returns true if $obj_next dirrectly follows $obj

=cut

sub contiguous_check ($) {
  my ($cmp_a,$cmp_b)=@_;
  cmp_int($cmp_a->next_first_int,$cmp_b->first_int)==0
}

=item * my $mod=$obj->mod_first_int($x);

Returns the modulus if the first integer and $x.

=cut

sub mod_first_int ($) { $_[0]->first_int % $_[1] }

=item * my $cmp=$obj_a->cmp_ranges($obj_b);

Compares 2 Net::IP::RangeCompare objects

  Returns 0 if both ranges have the same first_int and last_int
  Returns -1 if $obj_a->first_int starts before $obj_b->first_int
    or if $obj_a and $obj_b have the same first_int
       and $obj_a ends before $obj_b
  Returns 1 if $obj_a->first_int starts after $obj_b->first_int
    or if $obj_a and $obj_b have the same first_int
       and $obj_a ends after $obj_b

=cut

sub cmp_ranges ($) {
  my ($range_a,$range_b)=@_;
  return 0 if 
    $range_a->cmp_first_int($range_b)==0
    and
    $range_a->cmp_last_int($range_b)==0;

  $range_a->cmp_first_int($range_b)
  ||
  $range_a->cmp_last_int($range_b)

}

###########################################
#

=pod

=back

=head2 Helper functions

=over 4

=item * my $integer=ip_to_int('0.0.0.0');

Converts an ipv4 address to an integer usable by perl

=cut

sub ip_to_int ($) { unpack('N',pack('C4',split(/\./,$_[0]))) }

###########################################
#

=item * my $ipv4=int_to_ip(11);

Converts integers to ipv4 notation

=cut

sub int_to_ip ($) { join '.',unpack('C4',(pack('N',$_[0]))) }


###########################################
#

=item * my $hostmask=hostmask($netmask);

Given a netmask (as an integer) returns the corresponding hostmask.

=cut

sub hostmask ($) { ALL_BITS & (~(ALL_BITS & $_[0])) }

=item * my $int=add_one($var);

Returns $var incremented by 1

=cut

sub add_one($) { $_[0] + 1 }

=item * my $int=sub_one($var);

Returns $var decremented by 1

=cut

sub sub_one ($) { $_[0] -1 }

=item * my $size=size_from_mask($mask);

Given a netmask ( as an integer ) returns the size of the network.

=cut

sub size_from_mask ($) { 1 + hostmask($_[0] ) }

=item * item my $base=base_int($ip_int,$mask_int);

Returns the base address of an ip as an integer given the proper mask as an integer.

=cut

sub base_int ($$) { $_[0] & $_[1] }

=item * my $broadcast=broadcast_int($ip_int,$ip_mask);

Returns the broadcast address as an integer given the proper mask and ip as integers.

=cut

sub broadcast_int ($$) { base_int($_[0],$_[1]) + hostmask($_[1]) }

###########################################
#

=item * my $netmask=cidr_to_int(32);

Given a cidr(0 - 32) return the netmask as an integer.

=cut

sub cidr_to_int ($) {
  my ($cidr)=@_;
  my $shift=MAX_CIDR -$cidr;
  return undef if $cidr>MAX_CIDR or $cidr<0;
  return 0 if $shift==MAX_CIDR;
  ALL_BITS & (ALL_BITS << $shift)
}

=item * my $reult=cmp_int(1,2);

Returns the same thing as: 1 <=> 2

=cut

sub cmp_int ($$) { $_[0] <=> $_[1] }

=item * my @sorted_quads=sort sort_quad qw(10.0.0.1 10.0.0.10);

Sorts ipv4 quad strings in ascending order

=cut

sub sort_quad ($$) {
  my ($ip_a,$ip_b)=@_;
  cmp_int(ip_to_int($ip_a),ip_to_int($ip_b))
}

=item * my @sorted=sort sort_notations qw(10/24 10/22 9/8 );

Sorts ip notations in ascending order.  Carp::croak is called if a ranged cannot be parsed.

Example:

  my @sorted=sort sort_notations qw(10/24 10/22 9/8  8-11 );
  print join("\n",@sorted),"\n";

  Output:

  8-11
  9/8
  10/24
  10/22

=cut

sub sort_notations ($$) {
  my ($n_a,$n_b)=map { Net::IP::RangeCompare->parse_new_range($_) } @_;
  croak 'cannot parse notation a or b' 
    unless 2==grep { defined($_) } ($n_a,$n_b);

  $n_a->cmp_ranges($n_b);
}

############################################
#

=pod

=back

=head2 Overlap functions

This section documents the functions used to find and compute range overlaps.

=over 4

=item * my $obj=get_common_range([$range_a,$range_b]);

Returns an Net::IP::RangeCompare object representing the smallest common overlapping range.  Returns undef if no overlapping range is found.

=cut

sub get_common_range ($) {
  my ($ranges)=@_;
  croak 'empty range reference' if $#$ranges==-1;
  my ($first_int)=sort sort_largest_first_int_first @$ranges;
  my ($last_int)=sort sort_smallest_last_int_first @$ranges;

  my $class=blessed $ranges->[0];
  $class->new(
    $first_int->first_int
    ,$last_int->last_int
  );
}

###########################################
#

=item * my $obj=get_overlapping_range([$range_a,$range_b,$range_c]);

Returns an Net::IP::RangeCompare object that overlaps with the provided ranges

=cut

sub get_overlapping_range ($) {
  my ($ranges)=@_;
  croak 'list ref is empty' unless $#{$ranges}!=-1;
  my ($first_int)=sort sort_smallest_first_int_first @$ranges;
  my ($last_int)=sort sort_largest_last_int_first @$ranges;
  my $class=blessed($ranges->[0]);
  my $obj=$class->new($first_int->first_int,$last_int->last_int);
  $obj->[key_generated]=1;
  $obj;
}

=pod

=back

=head2 Sort Functions

This section describes the order in wich each function sorts a list of Net::IP::RangeCompare objects.

All functions in this section use the following syntax modle

Example: 
  my @list=sort sort_largest_last_int_first @netiprangecomapre_objects;

=over 4

=item * my @list=sort sort_largest_last_int_first @list;

Sorts by $obj->last_int in descending order

=item * my @list=sort sort_smallest_first_int_first @list;

Sorts by $obj->first_int in ascending order

=item * my @list=sort sort_smallest_last_int_first @list;

Sorts by $obj->last_int in ascending order

=item * my @list=sort sort_largest_first_int_first @list;

Sorts by $obj->first_int in descending order

  sort_ranges
    Sorts by 
      $obj->first_int in ascending order
      or
      $obj->last_int in descending order

=back

=cut

sub sort_ranges ($$) {
  my ($range_a,$range_b)=@_;

  # smallest start
  $range_a->cmp_first_int($range_b)
  ||
  # largest end
  $range_b->cmp_last_int($range_a);

}

sub sort_largest_last_int_first ($$) {
  my ($range_a,$range_b)=@_;
  $range_b->cmp_last_int($range_a)
}

sub sort_smallest_first_int_first ($$) {
  my ($range_a,$range_b)=@_;
  $range_a->cmp_first_int($range_b)
}

sub sort_smallest_last_int_first ($$) {
  my ($range_a,$range_b)=@_;
  $range_a->cmp_last_int($range_b)
  
}

sub sort_largest_first_int_first ($$) {
  my ($range_a,$range_b)=@_;
  $range_b->cmp_first_int($range_a)
}

############################################
#
sub new_from_ip ($) {
  my ($s,$ip)=@_;
  unless(defined($ip)) {
    $error='ip not defined';
    return undef;
  }
  $s->new(
    ip_to_int($ip)
    ,ip_to_int($ip)
  );
}

############################################
#
sub new_from_range ($) {
  my ($s,$range)=@_;
  unless(defined($range)) {
    $error='range not defined';
    return undef;
  }

  # lop off start and end spaces
  $range=~ s/(^\s+|\s+$)//g;

  unless($range=~ /
      ^\d{1,3}(\.\d{1,3}){0,3}
      \s*-\s*
      \d{1,3}(\.\d{1,3}){0,3}$
    /x) {
    $error="not a valid range notation format";
    return undef;
  }
  my ($start,$end)=split /\s*-\s*/,$range;
  $s->new( ip_to_int($start) ,ip_to_int($end));
  
}

sub new_from_cidr ($) {
  my ($s,$notation)=@_;
  $notation=~ s/(^\s+|\s+$)//g;
  unless($notation=~ /
      ^\d{1,3}(\.\d{1,3}){0,3}
      \s*\/\s*
      \d{1,3}(\.\d{1,3}){0,3}$
    /x) {
    $error="not a valid cidr notation format";
    return undef;
  }

  my ($ip,$mask)=split /\s*\/\s*/,$notation;
  my $ip_int=ip_to_int($ip);
  my $mask_int;

  if($mask=~ /\./) {
    # we know its quad notation
    $mask_int=ip_to_int($mask);
  } elsif(cmp_int($mask,0)!=-1 && cmp_int($mask,MAX_CIDR)!=1) {
    $mask_int=cidr_to_int($mask);
  } else {
    $mask_int=ip_to_int($mask);
  }
  my $first_int=base_int($ip_int , $mask_int);
  my $last_int=broadcast_int( $first_int,$mask_int);


  $s->new($first_int,$last_int);
}

###########################################
#

=head2 Net::IP::RangeCompare list processing functions

This section covers how to use the list and list of lists processing functions that do the actual comparison work.

=over 4

=cut

###########################################
#

=item * my $list_ref=consolidate_ranges(\@list_of_netiprangeobjects);

Given a list reference of Net::IP::RangeCompare Objects: Returns a consolidated list reference representing the input ranges.  The list input reference is depleted during the consolidation process.  If you want to keep the original list of ranges, make a copy of the list before passing it to consolidate_ranges.

Example:

  my $list=[];
  push @$list,Net::IP::RangeCompare->parse_new_range('10/32');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/32');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/30');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/24');
  push @$list,Net::IP::RangeCompare->parse_new_range('8/24');

  my $list=consolidate_ranges($list);

  while(my $range=shift @$list) {
    print $range,"\n";
  }

  OUTPUT
  8.0.0.0 - 8.0.0.255
  10.0.0.0 - 10.0.0.255

=cut

sub consolidate_ranges ($) {
  my ($ranges)=@_;
  @$ranges=sort sort_ranges @$ranges;
  my $cmp=shift @$ranges;
  my $return_ref=[];
  while( my $next=shift @$ranges) {
    if($cmp->overlap($next)) {
      my $overlap=$cmp->cmp_ranges($next)==0 ? 
        $cmp
	  :
        get_overlapping_range([$cmp,$next]);
      $cmp=$overlap;

    } else {
      push @$return_ref,$cmp;
      $cmp=$next;
    }
  
  }
  push @$return_ref,$cmp;

  $return_ref;
}


###########################################
#
# my $ranges=fill_missing_ranges([$range_a,$range_b,$range_c]);

=item * my $ranges=fill_missing_ranges(\@consolidated_list);

=item * my $ranges=fill_missing_ranges(\@list,consolidate_ranges=>1);

=item * my $ranges=fill_missing_ranges(\@list,consolidate_ranges=>0);

Given a consolidated list of Net::IP::RangeCompare objects, it returns a contiguous list reference of ranges.  All ranges generated by the fill_missing_ranges are $obj->missing==true and $obj->generated==true.

Optional argument(s)

  consolidate_ranges=>0||1
    Default value 1 
      Performs a consolidate_ranges on each list
    Disalble consolidation 0
      Skips the consolidate_ranges call

Example:

  my $list=[];
  push @$list,Net::IP::RangeCompare->parse_new_range('10/32');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/32');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/30');
  push @$list,Net::IP::RangeCompare->parse_new_range('10/24');
  push @$list,Net::IP::RangeCompare->parse_new_range('8/24');

  $list=fill_missing_ranges($list);

  while(my $range=shift @$list) {
    print $range,"\n";
  }

  OUTPUT
  8.0.0.0 - 8.0.0.255
  8.0.1.0 - 9.255.255.255
  10.0.0.0 - 10.0.0.255

=cut

sub fill_missing_ranges {
  my ($ranges,%args)=@_;
  %args=(consolidate_ranges=>0,%args);
  
  croak 'argument is not an array reference' unless
    ref($ranges) and ref($ranges) eq 'ARRAY';
  croak 'empty list reference' if $#$ranges==-1;
  my $class=blessed $ranges->[0];

  # first we have to consolidate the ranges
  $ranges=consolidate_ranges($ranges) if $args{consolidate_ranges};
  my $return_ref=[];

  my $cmp=shift @$ranges;
  while(my $next=shift @$ranges) {
    push @$return_ref,$cmp;
    unless($cmp->contiguous_check($next)) {
      my $missing=$class->new(
        $cmp->next_first_int
        ,$next->previous_last_int);
      $missing->[key_missing]=1;
      push @$return_ref,$missing;
    }
    $cmp=$next;
  }

  push @$return_ref,$cmp;

  $return_ref;
}

############################################
#

=item * my $list=range_start_end_fill([$list_a,$list_b]);

Given a list of lists of Net::IP::RangeCompare objects returns a list of list objects with the same start and end ranges.

Example:

  my $list_a=[];
  my $list_b=[];

  push @$list_a,Net::IP::RangeCompare->parse_new_range('10/24');
  push @$list_a,Net::IP::RangeCompare->parse_new_range('10/25');
  push @$list_a,Net::IP::RangeCompare->parse_new_range('11/24');

  push @$list_b,Net::IP::RangeCompare->parse_new_range('7/24');
  push @$list_b,Net::IP::RangeCompare->parse_new_range('8/24');

  #to prevent strange results always consolidate first
  $list_a=consolidate_ranges($list_a);
  $list_b=consolidate_ranges($list_b);

  my $list_of_lists=range_start_end_fill([$list_a,$list_b]);
  my @name=qw(a b);
  foreach my $list (@$list_of_lists) {
    my $name=shift @name;
    print '$list_',$name,"\n";
    foreach my $range (@$list) {
        print $range,"\n";
    }
  }

Output:

  $list_a
  7.0.0.0 - 9.255.255.255
  10.0.0.0 - 10.0.0.255
  11.0.0.0 - 11.0.0.255
  $list_b
  7.0.0.0 - 7.0.0.255
  8.0.0.0 - 8.0.0.255
  8.0.1.0 - 11.0.0.255


Notes:

  To prevent strange results make sure each list is 
  consolidated first.

=cut

sub range_start_end_fill ($) {
  my ($ranges)=@_;

  croak 'argument is not an array reference' unless
    ref($ranges) and ref($ranges) eq 'ARRAY';
  croak 'empty array reference' if $#$ranges==-1;
  my $class=blessed $ranges->[0]->[0];

  my ($first_int)=sort sort_smallest_first_int_first
    map { $_->[0] } @$ranges;
    $first_int=$first_int->first_int;
  my ($last_int)=sort sort_largest_last_int_first
    map { $_->[$#{$_}] } @$ranges;
    $last_int=$last_int->last_int;
  
  foreach my $ref (@$ranges) {
    my $first_range=$ref->[0];
    my $last_range=$ref->[$#{$ref}];

    if(cmp_int($first_range->first_int,$first_int)!=0) {
      my $new_range=$class->new(
          $first_int
          ,$first_range->previous_last_int
      );
      unshift @$ref,$new_range;
      $new_range->[key_missing]=1;
      $new_range->[key_generated]=1;
    }

    if(cmp_int($last_range->last_int,$last_int)!=0) {
      my $new_range=$class->new(
        $last_range->next_first_int
        ,$last_int
      );
      push @$ref,$new_range;
      $new_range->[key_missing]=1;
      $new_range->[key_generated]=1;
    }
  }


  $ranges;
}

############################################
#

=item * my $sub=range_compare([$list_a,$list_b,$list_c]);

=item * my $sub=range_compare([$list_a,$list_b,$list_c],consolidate_ranges=>1);

=item * my $sub=range_compare([$list_a,$list_b,$list_c],consolidate_ranges=>0);

Compares a list of lists of Net::IP::RangeCompare objects

Optional argument(s)

  consolidate_ranges=>0||1
    Default value 1 
      Performs a consolidate_ranges on each list
    Disalble consolidation 0
      Skips the consolidate_ranges call

Example:

  my $list_a=[];
  my $list_b=[];
  my $list_c=[];

  push @$list_a, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.0 - 10.0.0.1'
    );
  push @$list_a, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.2 - 10.0.0.5'
    );


  push @$list_b, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.0 - 10.0.0.1'
    );
  push @$list_b, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.3 - 10.0.0.4'
    );
  push @$list_b, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.4 - 10.0.0.5'
    );

  push @$list_c, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.0 - 10.0.0.1'
    );
  push @$list_c, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.3 - 10.0.0.3'
    );
  push @$list_c, Net::IP::RangeCompare->parse_new_range(
    '10.0.0.4 - 10.0.0.5'
    );

  my $sub=range_compare([  $list_a,$list_b,$list_c] );

  while(my ($common,$range_a,$range_b,$range_c)=$sub->()) {
    print "\nCommon Range: ",$common,"\n";
    print 'a: ',$range_a
      ,' '
      ,($range_a->missing ? 'not used' : 'in use')
      ,"\n";
    print 'b: ',$range_b
      ,' '
      ,($range_b->missing ? 'not used' : 'in use')
      ,"\n";
    print 'c: ',$range_c
      ,' '
      ,($range_c->missing ? 'not used' : 'in use')
      ,"\n";
  }

  Output:

  Common Range: 10.0.0.0 - 10.0.0.1
  a: 10.0.0.0 - 10.0.0.1 in use
  b: 10.0.0.0 - 10.0.0.1 in use
  c: 10.0.0.0 - 10.0.0.1 in use

  Common Range: 10.0.0.2 - 10.0.0.2
  a: 10.0.0.2 - 10.0.0.5 in use
  b: 10.0.0.2 - 10.0.0.2 not used
  c: 10.0.0.2 - 10.0.0.2 not used

  Common Range: 10.0.0.3 - 10.0.0.3
  a: 10.0.0.2 - 10.0.0.5 in use
  b: 10.0.0.3 - 10.0.0.5 in use
  c: 10.0.0.3 - 10.0.0.3 in use

  Common Range: 10.0.0.4 - 10.0.0.5
  a: 10.0.0.2 - 10.0.0.5 in use
  b: 10.0.0.3 - 10.0.0.5 in use
  c: 10.0.0.4 - 10.0.0.5 in use

=cut

sub range_compare {
  my ($list_of_ranges,%args)=@_;

  %args=(consolidate_ranges=>1,%args);

  if($args{consolidate_ranges}) {
    my $ref=[];
    while(my $ranges=shift @$list_of_ranges) {
      $ranges=consolidate_ranges($ranges);
      push @$ref,$ranges;
    }
    $list_of_ranges=$ref;
  }
  my ($row,$column_ids);
  my $next=1;
  sub {
    return () unless $next;
    ($row,$column_ids,$next)=compare_row($list_of_ranges,$row,$column_ids);
    return (get_common_range($row),@$row);

  };
}

=item * my $sub=range_compare_force_cidr(\@ranges,%args);

=item * my $sub=range_compare_force_cidr(\@ranges);

This is just a wrapper for range_compare, that returns the common ranges on cidr boundries, along with the cidr notation.

Example:

  my $ranges=[
    [
      map { $package_name->new(@{$_}[0,1]) }
        [0,8]
    ]

    ,[
      map { $package_name->new(@{$_}[0,1]) }
        [0,1]
        ,[3,4]
        ,[4,5]
    ]

    ,[
      map { $package_name->new(@{$_}[0,1]) }
        [0,1]
        ,[3,3]
        ,[4,5]
    ]
  ];

  my $sub=range_compare_force_cidr($ranges);
  while(my ($common,$cidr,@cols)=$sub->()) {
        print $common,', ',$cidr,"\n";
        print join(', ',@cols),"\n\n";
        last if --$max<=0;
        ++$count;
  }

  Output

  0.0.0.0 - 0.0.0.1, 0.0.0.0/31
  0.0.0.0 - 0.0.0.8, 0.0.0.0 - 0.0.0.1, 0.0.0.0 - 0.0.0.1

  0.0.0.2 - 0.0.0.2, 0.0.0.2/32
  0.0.0.0 - 0.0.0.8, 0.0.0.2 - 0.0.0.2, 0.0.0.2 - 0.0.0.2

  0.0.0.3 - 0.0.0.3, 0.0.0.3/32
  0.0.0.0 - 0.0.0.8, 0.0.0.3 - 0.0.0.5, 0.0.0.3 - 0.0.0.3

  0.0.0.4 - 0.0.0.5, 0.0.0.4/31
  0.0.0.0 - 0.0.0.8, 0.0.0.3 - 0.0.0.5, 0.0.0.4 - 0.0.0.5

  0.0.0.6 - 0.0.0.7, 0.0.0.6/31
  0.0.0.0 - 0.0.0.8, 0.0.0.6 - 0.0.0.8, 0.0.0.6 - 0.0.0.8

  0.0.0.8 - 0.0.0.8, 0.0.0.8/32
  0.0.0.0 - 0.0.0.8, 0.0.0.6 - 0.0.0.8, 0.0.0.6 - 0.0.0.8

=cut

sub range_compare_force_cidr {
  my $sub=range_compare(@_);

  my ($common,@row)=$sub->();
  my ($cidr,$notation,$next)=$common->get_first_cidr;
  sub {
    return () unless @row;
    my @return_row=($cidr,$notation,@row);
    if($next) {
      ($cidr,$notation,$next)=$next->get_first_cidr;
    } else {
      ($common,@row)=$sub->();
      if(@row) {
        ($cidr,$notation,$next)=$common->get_first_cidr 
      } else {
        $next=undef;
      }
    }
    @return_row
  }
}
###########################################
#
# my ($row,$cols,$next,$missing)=compare_row($data,undef,undef);

=item * ($row,$cols,$next,$missing)=compare_row($data,undef,undef);

=item * ($row,$cols,$next,$missing)=compare_row($data,$row,$cols);

This function is used to iterate over a list of consolidated Net::IP::RangeCompare Objects. see: "range_compare" for a more practical iterator method.

Example:

  my $ranges=[
    [
      map { Net::IP::RangeCompare->parse_new_range(@{$_}[0,1]) }
        [qw(10.0.0 10.0.0.1)]
        ,[qw(10.0.0.2 10.0.0.5)]
    ]

    ,[
      map { Net::IP::RangeCompare->parse_new_range(@{$_}[0,1]) }
        [qw(10.0.0.0 10.0.0.1)]
        ,[qw(10.0.0.3 10.0.0.4)]
        ,[qw(10.0.0.4 10.0.0.5)]
    ]

    ,[
      map { Net::IP::RangeCompare->parse_new_range(@{$_}[0,1]) }
        [qw(10.0.0.0 10.0.0.1)]
        ,[qw(10.0.0.3 10.0.0.3)]
        ,[qw(10.0.0.4 10.0.0.5)]
    ]
  ];

  my $data=[];
  # consolidate ranges -- prevents odd results
  while(my $list=shift @$ranges) {
    push @$data,consolidate_ranges($list);
  }
  my ($row,$cols,$next);
  while(1) {
    ($row,$cols,$next)=compare_row($data,$row,$cols);
    print join(', ',@$row),"\n";
    last unless $next;
  }
  OUTPUT:
  10.0.0.0 - 10.0.0.1, 10.0.0.0 - 10.0.0.1, 10.0.0.0 - 10.0.0.1
  10.0.0.2 - 10.0.0.5, 10.0.0.2 - 10.0.0.2, 10.0.0.2 - 10.0.0.2
  10.0.0.2 - 10.0.0.5, 10.0.0.3 - 10.0.0.5, 10.0.0.3 - 10.0.0.3
  10.0.0.2 - 10.0.0.5, 10.0.0.3 - 10.0.0.5, 10.0.0.4 - 10.0.0.5

=cut

sub compare_row {
  my ($data,$row,$cols)=@_;

  # if we don't have our column list then we need to build it
  unless(defined($cols)) {

    my $next=0;
    $cols=[];
    $row=[];
    my $class=blessed $data->[0]->[0];

    my @list=map { $_->[0] } @$data;
    my ($first)=sort sort_smallest_first_int_first @list;

    for(my $id=0;$id<=$#$data;++$id) {
      my $range=$data->[$id]->[0];
      if($range->cmp_first_int($first)==0) {
        push @$row,$range;
        $cols->[$id]=0;
        ++$next if $#{$data->[$id]}>0;
      } else {
        $cols->[$id]=-1;
        push @$row,$class->new(
         $first->first_int
         ,$range->previous_last_int
         ,1
         ,1
       );
       ++$next;
      }
    }
    return $row,$cols,$next;
  }
  my $class=blessed $row->[0];
  my ($last)=sort sort_smallest_last_int_first @$row;
  my ($end)=sort sort_largest_last_int_first 
    map { $_->[$#$_] } @$data;
  my $total=1 + ($#$data);
  my $ok=$total;
  my $missing_count=0;
  for(my $id=0;$id<=$#$data;++$id) {
    my $range=$row->[$id];
    my $current=$cols->[$id];
    my $next=1 + $current;
    if($#{$data->[$id]} < $next) {
    	$next=undef;
    }
     
    if($last->cmp_last_int($range)==0) {
      if(defined($next)) {
       my $next_range=$data->[$id]->[$next];
       if($range->contiguous_check($next_range)) {
        $cols->[$id]=$next;
	$row->[$id]=$next_range;
       } else {
        $row->[$id]=$class->new(
	  $range->next_first_int
	  ,$next_range->previous_last_int
	  ,1
	  ,1
	 );
       }
      } else {
	$row->[$id]=$class->new(
	 $range->next_first_int
	 ,$end->last_int
	 ,1
	 ,1
        );
      }
    }
    ++$missing_count if $row->[$id]->missing;
  }
  # use recursion to skip all missing rows
  compare_row($data,$row,$cols) if $missing_count==$total;
  for(my $id=0;$id<$total;++$id) {
  	# reduce our ok umber by every row maxed
  	--$ok if $cols->[$id]==$#{$data->[$id]};
	# we may have reached the end of our list, but that may
	# not be final row
	++$ok unless $row->[$id]->cmp_last_int($end)==0;
  }

  #print $ok,"\n";
  $row,$cols,$ok
}

=pod

=back

=cut

############################################
#
# End of the package
1;

############################################
#
# Helper package
package Net::IP::RangeCompare::Simple;

=head1 Net::IP::RangeCompare::Simple

Helper Class that wraps the features of Net::IP::RangeCompare into a single easy to use OO instance.

=over 4

=cut

use strict;
use warnings;
use Carp qw(croak);
use constant key_sources=>0;
use constant key_columns=>1;
use constant key_compare=>2;
use constant key_changed=>3;

############################################
#

=item * my $obj=Net::IP::RangeCompare::Simple->new;

Creates new instance of Net::IP::RangeCompare::Simple->new;

=cut

sub new  {
  my ($class)=@_;
  my $ref=[];
  $ref->[key_sources]={};
  $ref->[key_changed]={};
  $ref->[key_columns]=[];
  $ref->[key_compare]=undef;

  bless $ref,$class;
}


############################################
#

=item * $obj->add_range(key,range);

Adds a new "range" to the "key". The command will croak if the key is undef or the range cannot be parsed.

Example:

  $obj->add_range('Tom','10.0.0.2 - 10.0.0.11');

=cut

sub add_range ($$) {
  my ($s,$key,$range)=@_;
  croak "Key is not defined" unless defined($key);
  croak "Range is not defined" unless defined($range);

  my $obj=Net::IP::RangeCompare->parse_new_range($range);
  croak "Could not parse: $range" unless $obj;

  my $list;

  if(exists $s->[key_sources]->{$key}) {
    $list=$s->[key_sources]->{$key};
  } else {
    $s->[key_sources]->{$key}=[];
    $list=$s->[key_sources]->{$key};
  }
  push @$list,$obj;
  $s->[key_changed]->{$key}=1;
  $obj
}

############################################
#

=item * my $list_ref=$obj->get_ranges_by_key(key);

Given a key, return the list reference.  Returns undef if the key does not exist. Carp::croak is called if the key is undef.

=cut

sub get_ranges_by_key ($) {
  my ($s,$key)=@_;
  croak "key was not defined" unless defined($key);

  return [@{$s->[key_sources]->{$key}}]
    if exists $s->[key_sources]->{$key};
  
  return undef;
}

############################################
#

=item * $obj->compare_ranges;

=item * $obj->compare_ranges(key,key,key);

Used to initialize or re-initialize the compare process. When called with a key or a list of keys: The compare process excludes those columns.

Example:

  Given ranges from: Tom, Sally, Harry, Bob

  $obj->compare_ranges(qw(Bob Sally));

  The resulting %row from $obj->get_row would only contain keys 
  for Tom and Harry.

Notes:
  If %row would be empty during $obj->get_row function call will 
  croak.

=cut

sub compare_ranges {
  my ($s,@keys)=@_;
  my %exclude=map { ($_,1) } @keys;
  croak "no ranges defined" unless keys %{$s->[key_sources]};
  
  my $columns=$s->[key_columns];
  @$columns=();
  my $compare_ref=[];
  while(my ($key,$ranges)=each %{$s->[key_sources]}) {
    next if exists $exclude{$key};
    push @$columns,$key;
    $s->[key_sources]->{$key}=Net::IP::RangeCompare::consolidate_ranges($ranges)
     if $s->[key_changed]->{$key};
    $s->[key_changed]->{$key}=0;
    push @$compare_ref,$s->[key_sources]->{$key};

  }
  croak "no ranges defined" if $#$columns==-1;

  $s->[key_compare]=Net::IP::RangeCompare::range_compare(
    $compare_ref
    ,consolidate_ranges=>0
  );

  1
}


############################################
#

=item * while(my ($common,%row)=$obj->get_row) { do something }

Returns the current row of the compare process.

  $common
    Represents the common range between all of the
    source ranges in the current row.

  %row
    Represents the consolidated range from the 
    relative source "key".

Notes:

  This function will croak if no ranges have been
  added to the Net::IP::RangeCompare::Simple object.

=cut

sub get_row () {
  my ($s)=@_;

  croak "no ranges defined" unless keys %{$s->[key_sources]};

  #make sure we have something to compare
  $s->compare_ranges
    unless  $s->[key_compare];
  my %row;
  my (@cols)=$s->[key_compare]->();
  return () unless @cols;
  my $common;

  ($common,@row{@{$s->[key_columns]}})=@cols;

  $common,%row

}

############################################
#

=item * my @keys=$s->get_keys;

Returns the list of keys in this instance.

=cut

sub get_keys () {
  keys %{$_[0]->[key_sources]}
}

############################################
#
# End of the package
1;

__END__

=pod

=back

=head1 AUTHOR

Michael Shipper 

=head1 COPYRIGHT

Copyright 2010 Michael Shipper.  All rights reserved.

This library is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=head1 SEE ALSO

Net::Netmask NetAddr::IP Carp Net::CIDR::Compare

=cut



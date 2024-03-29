use ExtUtils::MakeMaker;
require 5.6.0;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
    'NAME'	=> 'Net::SMS::12Move',
    'VERSION_FROM' => 'lib/Net/SMS/12Move.pm',
    'AUTHOR' => 'Craig Manley (c.manley@cpan.org)',
    'ABSTRACT' => 'Send free mobile terminated SMS messages thru www.12move.nl.',
    'PREREQ_PM'	=> {'LWP::UserAgent' => 1.77,
                    'HTTP::Request::Common' => 1.19}, # e.g., Module::Name => 1.1
    'dist' => {COMPRESS => 'gzip -9f', SUFFIX => 'gz'}
);
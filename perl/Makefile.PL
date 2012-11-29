use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my $libs = "" . `pkg-config --libs liblzma`;
chomp $libs;
WriteMakefile(
    'NAME'		=> 'deltarpm',
    'OPTIMIZE'		=> '-Wno-declaration-after-statement -Wall',
    'VERSION_FROM'	=> 'deltarpm.pm',
    'OBJECT'		=> 'deltarpm.o ../readdeltarpm.o ../rpmhead.o ../util.o ../md5.o ../cfile.o',
    'LIBS'		=> $libs,
    'DEFINE'		=> '-DPACKAGE_NAME=\"deltarpm\"', 
    'INC'		=> "-I.. `pkg-config --cflags rpm`", # -I.. for deltarpm
    'XSPROTOARG'        => '-noprototypes',
    'TYPEMAPS'  => [ '../perlobject.map' ],
);

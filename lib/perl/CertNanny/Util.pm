#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#
#
# DBCA::Util
#
# 2002-11-11 Martin Bartosch; Cynops GmbH <m.bartosch@cynops.de>
#

package CertNanny::Util;

use base qw(Exporter);
use strict;

use IO::File;
use File::Glob qw(:globally :nocase);
use File::Spec;
use File::Temp;
use FindBin qw($Bin $Script $RealBin $RealScript);

use Time::Local;
use Time::HiRes qw(gettimeofday);

use MIME::Base64;
use English;

use Data::Dumper;

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;

@EXPORT = qw(runCommand isoDateToEpoch epochToIsoDate expandStr mangle
             printableIsoDate readFile writeFile createSelfSign getCertDigest
             getCertFormat getCertInfoHash getCSRInfoHash parseCertData 
             getTmpFile forgetTmpFile wipe staticEngine encodeBMPString writeOpenSSLConfig 
             getDefaultOpenSSLConfig backoffTime getMacAddresses 
             fetchFileList callOpenSSL os_type is_os_type setVariable
             unsetVariable osq dumpCertInfoHash getDigests getCiphers Exit);    # Symbols to autoexport (:DEFAULT tag)

# This variable stores arbitrary data like created temporary files
my $INSTANCE;
my %variable;


sub getInstance() {
  $INSTANCE ||= (shift)->new(@_);

  # If Configuration is not present, we are still in initialisation phase
  if (!defined $INSTANCE->{CONFIG}) {
    shift;
    my %args = (@_);
    $INSTANCE->{CONFIG} = $args{CONFIG};
  }
  return $INSTANCE;
}


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self  = {};
    my %args  = (@_);    # argument pair list

    bless $self, $class;
    $INSTANCE = $self;
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  my $self = shift;

  return unless (exists $self->{TMPFILE});

  foreach my $file (@{$self->{TMPFILE}}) {CertNanny::Util->wipe(FILE => $file, SECURE => 1)}
} ## end sub DESTROY


sub setVariable {
  my $self    = (shift)->getInstance();
  my %args   = (NAME  => '',
                VALUE => '',
                @_);
  $variable{$args{'NAME'}} = $args{'VALUE'} if ($args{'NAME'} ne '');
  return 1;
}


sub unsetVariable {
  my $self    = (shift)->getInstance();
  my %args   = (NAME  => '',
                @_);
  delete $variable{$args{'NAME'}} if ($args{'NAME'} ne '');
  return 1;
}


sub hidePin {
  my $self    = (shift)->getInstance();
  my @cmd = @_;
  
  for (my $ii = 0; $ii < $#cmd; $ii++) {
    $cmd[$ii + 1] = "*HIDDEN*" if ($cmd[$ii] =~ /(-pw|-target_pw|-storepass|-keypass|-srcstorepass|-deststorepass|-srckeypass|-destkeypass)/);
    $cmd[$ii] =~ s/Login=\S+/Login=*HIDDEN*/;
  }
  my $command = join(' ', @cmd);
  
  return $command;
}


sub osq {
  my $self = (shift)->getInstance();
  my $str  = shift;
  
  my $command;
  if ($OSNAME eq "MSWin32") {
     $str =~ s/^"||"$//g;
     $command = qq("$str");
   } else {
     $str =~ s/^'||'$//g;
     $command = "'$str'";
   }
  return $command;
}


sub mangle {
  my $self = (shift)->getInstance();
  my %args = (VALUE  => undef,
              MANGLE => 'PLAIN',
              @_);
              
  my $value  = $args{VALUE};
  my $mangle = $args{MANGLE};
  
  return if !defined $value;

  if ($value ne '') {
    # mangle only if value is not "", otherwise File::Spec converts "" into "\", which doesn't make much sense ...
    return File::Spec->catfile(File::Spec->canonpath($value)) if ($mangle eq "FILE");
    return uc($value)                                         if ($mangle eq "UC");
    return lc($value)                                         if ($mangle eq "LC");
    return ucfirst($value)                                    if ($mangle eq "UCFIRST");
    return undef                                              if ($mangle eq "CMD" && !-x $value);
    return $value;    # don't know how to handle this mangle option
  } ## end if ($value ne '')
  return $value;
}


sub Exit {
  my $self = (shift)->getInstance();
  my %args = (RC  => 0,
              ERR => '',
              MSG => '',
              @_);                 # argument pair list

  if ($args{ERR} ne '') {
    $args{MSG} = $args{ERR} if !$args{MSG};
    CertNanny::Logging->Err('STR', $args{MSG});
  }
  
  if ($args{RC}) {
    CertNanny::Logging->error('MSG', $args{MSG}) if ($args{MSG});
  } else {
    CertNanny::Logging->info('MSG', $args{MSG}) if ($args{MSG});
  }

  CertNanny::Logging->info('MSG', "CertNanny ended with rc: <$args{RC}>");

  exit $args{RC};
}


sub runCommand {
  my $self    = (shift)->getInstance();
  my $cmd     = shift;

  my %args = (HIDEPWD => 0,
              @_);                 # argument pair list
               
  my ($result, @cmdarr, $logCmd, $tmpFile, @stdoutArr, @stderrArr);

  if (ref($cmd) eq 'ARRAY') {
    @cmdarr = @$cmd;
  } else {
    push(@cmdarr, $cmd);
  }
  $logCmd = $args{HIDEPWD} ? $self->hidePin(@cmdarr) : join(' ' , @cmdarr);

  CertNanny::Logging->debug('MSG', "Execute: <$logCmd>");

  if ($tmpFile = CertNanny::Util->getTmpFile()) {push(@cmdarr, "2>$tmpFile")}

  open my $PROGRAM, join(' ' , @cmdarr) . "|" or die "could not execute <$logCmd>";
  @stdoutArr = do {
    <$PROGRAM>;
  };
  close($PROGRAM);
  $result->{RC} = $? >> 8;
  $result->{STDOUT} = \@stdoutArr;

  if ($tmpFile) {
    if (open(FILE, "<", $tmpFile)) {
      @stderrArr = <FILE>;
      close(FILE);
    }
    $self->forgetTmpFile('FILE', $tmpFile);
  }
  $result->{STDERR} = \@stderrArr;

  return $result;
} ## end sub runCommand


sub isoDateToEpoch {
  # convert ISO date to Unix timestamp (seconds since the Epoch)
  # arg: ISO date (YYYYMMDDHHMMSS)
  # return: Epoch (seconds) or undef on error
  my $self = (shift)->getInstance();
  my $isodate     = shift;
  my $isLocalTime = shift;

  return unless defined $isodate;

  if (my ($year, $mon, $mday, $hours, $min, $sec) = ($isodate =~ /^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$/)) {
    $mon  -= 1;
    $year -= 1900;
    return (defined($isLocalTime)) ? timelocal($sec, $min, $hours, $mday, $mon, $year) : timegm($sec, $min, $hours, $mday, $mon, $year);
  }

  return;
} ## end sub isoDateToEpoch


sub epochToIsoDate {
  # convert Unix Epoch to ISO Date
  # arg: Epoch seconds , use localtime flag
  # return: ISO Date (YYYYMMDDHHMMSS)
  my $self = (shift)->getInstance();
  my $epoch       = shift || time;
  my $isLocalTime = shift;

  my ($seconds, $minutes, $hours, $day_of_month, $month, $year, $wday, $yday, $isdst);
  if (defined($isLocalTime)) {
    ($seconds, $minutes, $hours, $day_of_month, $month, $year, $wday, $yday, $isdst) = localtime($epoch);
    CertNanny::Logging->debug('MSG', "Localtime daylightsaving $isdst");
  } else {
    ($seconds, $minutes, $hours, $day_of_month, $month, $year, $wday, $yday, $isdst) = gmtime($epoch);
  }
  return sprintf("%04d%02d%02d%02d%02d%02d", $year + 1900, $month + 1, $day_of_month, $hours, $minutes, $seconds);
} ## end sub epochToIsoDate


sub expandStr {
  #################################################################
  # Expands a string by replacing placeholders with values
  # Input: Hash array containing the inputstring and userdefined 
  #        values to be replaced
  #  INPUT             : Inputstring
  #  __<replacename>__ : <replacevalue>
  #
  # Custom replace values may contain a sprintf format string
  #
  # The following varibles are predefined and must not be used
  # as custom variables:
  #  __YEAR__          : Year        4-digit
  #  __YY__            : Year        2-digit
  #  __MONTH__         : Monthnumber 2-digit
  #  __DAY__           : daynumber   2-digit
  #  __HOUR__          : Hour        2-digit 24h-format
  #  __MINUTE__        : Minute      3-digit
  #  __SECOND__        : Second      2-digit
  #  __TS4__           : Timestamp format JJJJMMTT_hhmmss
  #  __TS2__           : Timestamp format JJMMTT_hhmmss
  #
  #  __PID__           : Prozess-Id
  #  __PRG__           : Program name
  #  __PRGEXT__        : Program name with extension
  #  __EXT__           : Program name extension only
  #
  #  __\##__           : Char(##)
  #
  #  __ENV(var)__      : Environment variable var
  #  __EXEC(prg)__     : Output of program prg
  #
  #  __BIN__           : $Bin
  #  __SCRIPT__        : $Script
  #  __REALBIN__       : $Bin $RealBin
  #  __REALSCRIPT__    : $RealScript
  #

  my $self   = (shift)->getInstance();
  my %args   = (@_);
  
  my $input  = $args{INPUT} || '';
  
  # Replace HEX values, Environment Variables and Program Outputs
  $input =~ s:__\\x([0-9A-Fa-f]{2})__:chr hex $1:ge;
  $input =~ s:__ENV\(([^\)]*?)\)__:$ENV{$1}:g;
  $input =~ s:__EXEC\(([^\)]*?)\)__:`$1`:ge;

  # Replace date, time, etc.
  my ($n, $s, $m, $h, $D, $M, $Y, $WD, $YD, $isdst);
  $n = substr( (gettimeofday)[1], 0, 4 );
  ($s, $m, $h, $D, $M, $Y, $WD, $YD, $isdst) = localtime(time);
  $M++;
  my $YY = $Y - 100;
  $Y += 1900;

  $M  = sprintf('%02d', $M);
  $D  = sprintf('%02d', $D);
  $WD = sprintf('%01d', $WD);
  $YD = sprintf('%03d', $YD);
  $h  = sprintf('%02d', $h);
  $m  = sprintf('%02d', $m);
  $s  = sprintf('%02d', $s);
  $n  = sprintf('%04d', $n);
  
  $args{'__YEAR__'}   = $Y                           if (!exists($args{'__YEAR__'}));
  $args{'__YY__'}     = $YY                          if (!exists($args{'__YY__'}));
  $args{'__MONTH__'}  = $M                           if (!exists($args{'__MONTH__'}));
  $args{'__DAY__'}    = $D                           if (!exists($args{'__DAY__'}));
  $args{'__WDAY__'}   = $WD                          if (!exists($args{'__WDAY__'}));
  $args{'__YDAY__'}   = $YD                          if (!exists($args{'__YDAY__'}));
  $args{'__HOUR__'}   = $h                           if (!exists($args{'__HOUR__'}));
  $args{'__MINUTE__'} = $m                           if (!exists($args{'__MINUTE__'}));
  $args{'__SECOND__'} = $s                           if (!exists($args{'__SECOND__'}));
  $args{'__NANO__'}   = $n                           if (!exists($args{'__NANO__'}));
  $args{'__TS4__'}    = "${Y}${M}${D}_${h}${m}${s}"  if (!exists($args{'__TS4__'}));
  $args{'__TS2__'}    = "${YY}${M}${D}_${h}${m}${s}" if (!exists($args{'__TS2__'}));

  # Replace Process ID
  $args{'__PID__'} = $$ if (!exists($args{'__PID__'}));

  # Replace Programm Name
  my ($name, $ext) = split(/\./, $Script);
  $args{'__PRG__'}    = $name   if (!exists($args{'__PRG__'}));
  $args{'__PRGEXT__'} = $Script if (!exists($args{'__PRGEXT__'}));
  $args{'__EXT__'}    = $ext    if (!exists($args{'__EXT__'}));

  $args{'__BIN__'}        = $Bin        if (!exists($args{'__BIN__'}));
  $args{'__SCRIPT__'}     = $Script     if (!exists($args{'__SCRIPT__'}));
  $args{'__REALBIN__'}    = $RealBin    if (!exists($args{'__REALBIN__'}));
  $args{'__REALSCRIPT__'} = $RealScript if (!exists($args{'__REALSCRIPT__'}));
  
  # add global variables
  while (my ($key, $value) = each %variable) {
    $args{"__${key}__"} = $value if (!exists($args{"__${key}__"}));
  }
  
  # replace values passed to this function
  while (my ($key, $value) = each %args) {
    if ($key =~ /^__.*__$/) {
      $value ||= "";
      $key =~ s/^__|__$//g;
      while ($input =~ /__($key)(%[^\$]+)?__/g) {
        if ($2) {
          $value = sprintf($2, $value);
          $input =~ s:__$1$2__:$value:;
        } else {
          $input =~ s:__$1__:$value:;
        }
      }
    }
  }
  
  # delete unresolved placeholders
  $input =~ s/__(?:(?!__).)*__//g;
  
  # alternativ date compatible time/date placeholders
  $input =~ s:%y:$YY:g;
  $input =~ s:%Y:$Y:g;
  $input =~ s:%m:$M:g;
  $input =~ s:%d:$D:g;
  $input =~ s:%H:$h:g;
  $input =~ s:%M:$m:g;
  $input =~ s:%S:$s:g;

  return $input;
} ## end sub expandStr


sub printableIsoDate {
  # return a printable represantation of a compacted ISO date
  # arg: ISO Date, format YYYYMMDDHHMMSS
  my $self = (shift)->getInstance();
  my $arg  = shift;

  my @date = ($arg =~ /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
  sprintf("%04d-%02d-%02d %02d:%02d:%02d", @date);
} ## end sub printableIsoDate


sub readFile {
  # read (slurp) file from disk
  # Example: $self->readFile($filename);
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " write file/content to disk");
  my $self = (shift)->getInstance();
  my $filename = shift;

  my $result = 1;
  if (!-e $filename) {
    $result = CertNanny::Logging->error('MSG', "readFile(): file does not exist: $filename");
  }

  if ($result && !-r $filename) {
    CertNanny::Logging->error('MSG', "readFile(): file is not readable: $filename");
  }

  if ($result) {
    $result = do {
      open my $fh, '<', $filename;
      if (!$fh) {
        $result = CertNanny::Logging->error('MSG', "readFile(): file open failed: $filename");
      }
      if ($result) {
        binmode $fh;
        local $/;
        <$fh>;
      }
    }
  } else {
    $result = undef;
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " write file/content to disk");
  return $result;
} ## end sub readFile


sub writeFile {
  ###########################################################################
  #
  # write file/content to disk
  #
  # Input: caller must provide a hash ref:
  #           SRCFILE    => file name to be read
  #        or SRCCONTENT => content to be read
  #           DSTFILE    => file name to be written
  #
  #           FORCE      => overwrite file if it already exists
  #           APPEND     => append to file if it already exists
  #        APPEND wins against FORCE
  #
  # Output: 1: success
  #         or undef/0 on error
  #
  # Example: $self->writeFile(DSTFILE => $filename, SRCCONTENT => $data);
  #
  # The method will return false if the file already exists unless
  # the optional argument FORCE is set. In this case the method will overwrite
  # the specified file.
  #
  # Example: $self->writeFile(DSTFILE => $filename, SRCCONTENT => $data, FORCE => 1);
  #
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $srcfile    = $args{SRCFILE};
  my $srccontent = $args{SRCCONTENT};
  my $dstfile    = $args{DSTFILE};

  my $rc = 1;
  
  if (!defined $dstfile) {
    $rc = CertNanny::Logging->error('MSG', "writeFile(): Destination File DSTFILE must be defined.");
  }

  if ($rc && ((!defined $srcfile && !defined $srccontent) || (defined $srcfile && defined $srccontent))) {
    $rc = CertNanny::Logging->error('MSG', "writeFile(): Either SRCFILE or SRCCONTENT must be defined to write in <$dstfile>.");
  }

  if ($rc && (-e $dstfile) && (!$args{FORCE}) && (!$args{APPEND})) {
    $rc = CertNanny::Logging->error('MSG', "writeFile(): output file <$dstfile> already exists");
  }

  if ($rc && defined($srccontent)) {
    my $mode = O_WRONLY;
    if (!-e $dstfile) {
      $mode |= O_EXCL | O_CREAT;
    } else {
      if ($args{APPEND}) {
        $mode |= O_APPEND;
      }
    }

    my $fh;
    if (not sysopen($fh, $dstfile, $mode)) {
      $rc = CertNanny::Logging->error('MSG', "writeFile(): output file <$dstfile> open failed");
    } else {
      binmode $fh;
      print {$fh} $srccontent;
      close $fh
    }
  }
  
  if ($rc && defined($srcfile)) {
    if ($args{APPEND}) {
      if (!open OUT, '>>'.$dstfile) {
        $rc = CertNanny::Logging->error('MSG', "writeFile(): output file <$dstfile> open failed");
      }
    } else {
      if (!open OUT, '>'.$dstfile) {
        $rc = CertNanny::Logging->error('MSG', "writeFile(): output file <$dstfile> open failed");
      }
    }
    if ($rc) {
      if (!open IN, $srcfile) {
        $rc = CertNanny::Logging->error('MSG', "writeFile(): input file <$srcfile> open failed");
      }
      if ($rc) {
        binmode IN;
        binmode OUT;
        while (<IN>) {
          print OUT;
        }
        close IN;
        close OUT;
      }
    }
  }
  return $rc;
} ## end sub writeFile


sub createSelfSign {
  ###########################################################################
  #
  # create a selsigned certificate
  # 
  # Input:    FQDN      => Full qualified domain name
  #                        Defaults to $entry->{statedir}/$entryname-selfcert.pem
  #           CERTFILE  => certificate filename to be written
  #                        Defaults to $entry->{statedir}/$entryname-selfcert.pem
  #           KEYFILE   => key filename to be written
  #                        Defaults to $entry->{key}->{file}
  #           DIGEST    => Digest to sign with (md5, sha1, md2, mdc2, md4)
  #                        Defaults to sha1
  #           PIN       => Digest to sign with (md5, sha1, md2, mdc2, md4)
  #                        Defaults to $entry->{key}->{pin} or ''
  #           ENTRYNAME => based on this value the file name to be read
  #                        Only used if CERTFILE is not given
  #           ENTRY     => based on this entry the selfsigned certificate is
  #                        Only used if KEYFILE or CERTFILE is not given
  # 
  # Output: caller gets a hash ref:
  #           KEY  => file containing the key
  #           CERT => file containing the signed certificate
  # 
  # This signs the current certifiate
  # This method should selfsign the current certificate.
  #
  my $self = (shift)->getInstance();
  my %args = ('FQDN'      => '',
              'CERTFILE'  => '',
              'KEYFILE'   => '',
              'DIGEST'    => 'sha1',
              'PIN'       => '',
              'ENTRY'     => '',
              'ENTRYNAME' => '',
              @_);

  my $fqdn      = $args{FQDN};
  my $certfile  = $args{CERTFILE};
  my $keyfile   = $args{KEYFILE};
  my $digest    = "-$args{DIGEST}";
  my $pin       = $args{PIN};
  my $entry     = $args{ENTRY};
  my $entryname = $args{ENTRYNAME};
  
  # SANITY CHECKS
  # sanity check: FQDN must be set
  if ($fqdn eq '') {
    # for inital enrollment we override the DN to use the configured desiered DN rather then the preset enrollment certificates DN
    eval {$fqdn = (defined($entry->{initialenroll}->{activ})) ? $entry->{initialenroll}->{subject} : Net::Domain::hostfqdn();};
    if ($@ || ($fqdn eq '')) {
      CertNanny::Logging->error('MSG', "FQDN <$fqdn> must be one set");
      return;
    }
    CertNanny::Logging->debug('MSG', "Full Qualified Domain name: <$fqdn>");
  }

  # sanity check: Either CERTFILE or ENTRY and ENTRYNAME must be given
  if ($certfile eq '') {
    if (ref($entry) && ($entryname ne '')) {
      eval {$certfile = File::Spec->catfile($entry->{statedir}, $entryname . "-selfcert.pem");};
    }
    if ($@ || ($certfile eq '')) {
      CertNanny::Logging->error('MSG', "Either CERTFILE <$certfile> or ENTRY <$entry> and ENTRYNAME <$entryname> must be set");
      return;
    }
  }

  # sanity check: Either KEYFILE or ENTRY must be given
  if ($keyfile eq '') {
    if (ref($entry) && ($entryname ne '')) {
      eval {$certfile = File::Spec->catfile($entry->{statedir}, $entryname . "-key.pem");};
    }
    if ($@ || ($keyfile eq '')) {
      CertNanny::Logging->error('MSG', "Either KEYFILE <$keyfile> or ENTRY <$entry> must be set");
      return;
    }
  }

  # sanity check: DIGEST must be one supported by the openssl Version
  if (!defined(CertNanny::Util->getDigests()->{$digest})) {
    CertNanny::Logging->error('MSG', "DIGEST <$digest> not supported by your version of openssl " . join(',', keys(%{CertNanny::Util->getDigests()})) . ")");
    return;
  }

  if ($pin eq '') {
    eval {$pin = $entry->{key}->{pin};};
    $pin = '' if $@;
  }

  my $openssl   = $self->{CONFIG}->get('cmd.openssl', 'CMD');

  # split FQDN into individual RDNs. This regex splits at the ','
  # character if it is not escaped with a \ (negative look-behind)
  my @RDN = split(/(?<!\\),\s*/, $fqdn);

  my %RDN_Count;
  foreach (@RDN) {
    my ($key, $value) = (/(.*?)=(.*)/);
    $RDN_Count{$key}++;
  }

  # delete all entries that only showed up once
  # all other keys now indicate the total number of appearance
  map {delete $RDN_Count{$_} if ($RDN_Count{$_} == 1);} keys %RDN_Count;

  my $config_options = CertNanny::Util->getDefaultOpenSSLConfig();
  $config_options->{req} = [];
  push(@{$config_options->{req}}, {prompt             => "no"});
  push(@{$config_options->{req}}, {distinguished_name => "req_distinguished_name"});

  $config_options->{req_distinguished_name} = [];
  foreach (reverse @RDN) {
    my $rdnstr        = "";
    my ($key, $value) = (/(.*?)=(.*)/);
    if (exists $RDN_Count{$key}) {
      $rdnstr = $RDN_Count{$key} . ".";
      $RDN_Count{$key}--;
    }

    $rdnstr .= $key;
    push(@{$config_options->{req_distinguished_name}}, {$rdnstr => $value});
  } ## end foreach (reverse @RDN)

  my $tmpconfigfile = CertNanny::Util->writeOpenSSLConfig($config_options);
  CertNanny::Logging->debug('MSG', "The following configuration was written to $tmpconfigfile:\n" . CertNanny::Util->readFile($tmpconfigfile));

  # generate request
  my @cmd = (CertNanny::Util->osq("$openssl"), 'req', '-config', CertNanny::Util->osq("$tmpconfigfile"), '-x509', '-new', CertNanny::Util->osq("$digest"), '-out', CertNanny::Util->osq("$certfile"), '-key', CertNanny::Util->osq("$keyfile"),);

  push(@cmd, ('-passin', 'env:PIN')) unless $pin eq "";
  $ENV{PIN} = $pin;
  if (CertNanny::Util->runCommand(\@cmd)->{RC} != 0) {
    CertNanny::Logging->error('MSG', "Selfsign certifcate creation failed!");
    delete $ENV{PIN};
    forgetTmpFile('FILE', $tmpconfigfile);
    return;
  }

  forgetTmpFile('FILE', $tmpconfigfile);

  return {CERT => $certfile,
          KEY  => $keyfile};
} ## end sub createSelfSign


sub getCertFormat {
  ###########################################################################
  # Analyses certificate and decides whether it's DER or PEM format
  #
  # Input:  String with Certificate
  # Output: String with Format
  #
  my $self     = (shift)->getInstance();
  my $certdata = shift;
  
  return ($certdata =~ m{ -----.*CERTIFICATE.*----- }xms) ? 'PEM' : 'DER';
} ## end sub getCertFormat


sub getDigests {
  ###########################################################################
  # Get availabe Digests
  #
  # Input:  -
  # Output: Hashref to a hash with all possible digests as keys
  #
  my $self = (shift)->getInstance();
  
  return $self->{DIGESTS} if defined($self->{DIGESTS});
  
  my $rc;
  
  # build commandstring
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd = (CertNanny::Util->osq("$openssl"), 'list-message-digest-commands');

    my $result = CertNanny::Util->runCommand(\@cmd);
    
    if (defined($result)) {
      if ($result->{RC} != 0) {
        CertNanny::Logging->error('MSG', "getDigests(): OpenSSL error $result->{RC}");
      } else {
        if (defined($result->{STDOUT})) {
          my $digests = $result->{STDOUT};
          chomp(@$digests);
          foreach (@$digests) {
            $rc->{$_} = 1;
          }
          $self->{DIGESTS} = $rc;
        } else {
          CertNanny::Logging->error('MSG', "getDigests(): Error executing OpenSSL");
        }
      }
    } else {
      CertNanny::Logging->error('MSG', "getDigests(): Error executing OpenSSL");
    }
  }
  
  return $rc;
} ## end sub getDigests


sub getCiphers {
  ###########################################################################
  # Get availabe Ciphers
  #
  # Input:  -
  # Output: Hashref to a hash with all possible ciphers as keys
  #
  my $self = (shift)->getInstance();
  
  return $self->{CIPHERS} if defined($self->{CIPHERS});
  
  my $rc;
  
  # build commandstring
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd = (CertNanny::Util->osq("$openssl"), 'list-message-cipher-commands');

    my $result = CertNanny::Util->runCommand(\@cmd);
    
    if (defined($result)) {
      if ($result->{RC} != 0) {
        CertNanny::Logging->error('MSG', "getCiphers(): OpenSSL error $result->{RC}");
      } else {
        if (defined($result->{STDOUT})) {
          my $digests = $result->{STDOUT};
          chomp(@$digests);
          foreach (@$digests) {
            $rc->{$_} = 1;
          }
          $self->{CIPHERS} = $rc;
        } else {
          CertNanny::Logging->error('MSG', "getCiphers(): Error executing OpenSSL");
        }
      }
    } else {
      CertNanny::Logging->error('MSG', "getCiphers(): Error executing OpenSSL");
    }
  }
  
  return $rc;
} ## end sub getDigests


sub callOpenSSL {
  # call openssl programm
  #
  # Input:
  #   command   : openSSL command to be executed
  #   params    : Parameterarray
  #   args      : CERTDATA   => directly contains certificate data
  #               CERTFILE   => cert file to parse
  #               CERTFORMAT => PEM|DER (optional, default: DER)
  #
  # Output: Hash with all detected certificate information
  # i.E.:
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   IssuerName             => <cert issuer common name>
  #   SerialNumber           => <cert serial number> Format: xx:xx:xx... (hex, upper case)
  #   NotBefore              => <cert validity> Format: YYYYDDMMHHMMSS
  #   NotAfter               => <cert validity> Format: YYYYDDMMHHMMSS
  #   CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex,cupper case)
  #   Modulus                => <cert >
  #   PublicKey              => <cert public key> Format: Base64 encoded (PEM)
  #   Certificate            => <certifcate> Format: Base64 encoded (PEM)
  #   BasicConstraints       => <cert basic constraints> Text (free style)
  #   KeyUsage               => <cert key usage> Format: Text (free style)
  #
  # optional (if present in certificate):
  #   SubjectAlternativeName => <cert alternative name>
  #   IssuerAlternativeName  => <issuer alternative name>
  #   SubjectKeyIdentifier   => <X509v3 Subject Key Identifier>
  #   AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
  #   CRLDistributionPoints  => <X509v3 CRL Distribution Points>
  #
  my $self    = (shift)->getInstance();
  my $command = shift;
  my $params  = shift;
  my %args    = (@_);

  my $rc;
  
  return if (!$self->_sanityCheckIn('callOpenSSL', %args));
  
  # build commandstring
  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd = (CertNanny::Util->osq("$openssl"), $command);
    push(@cmd, ('-in', CertNanny::Util->osq("$args{CERTFILE}")))       if (defined $args{CERTFILE});
    push(@cmd, ('-inform', CertNanny::Util->osq("$args{CERTFORMAT}"))) if (defined $args{CERTFORMAT});
    foreach (@$params) {push(@cmd, -$_)}

    my $result;
    if (defined($args{CERTFILE})) {
      $result = CertNanny::Util->runCommand(\@cmd);
    }
    
    if (defined($args{CERTDATA})) {
      my $tmpfile = CertNanny::Util->getTmpFile();
      if (CertNanny::Util->writeFile(DSTFILE    => $tmpfile,
                                     SRCCONTENT => $args{CERTDATA})) {
        push(@cmd, "< $tmpfile");
        $result = CertNanny::Util->runCommand(\@cmd);
      } else {
        CertNanny::Logging->error('MSG', "callOpenSSL(): Error writing CERTDATA to $tmpfile");
      }
      CertNanny::Util->forgetTmpFile('FILE', $tmpfile);
    }
    
    if (defined($result)) {
      if ($result->{RC} != 0) {
        if ($result->{RC} == 127) {
          CertNanny::Logging->error('MSG', "callOpenSSL(): open error");
        } else {
          CertNanny::Logging->error('MSG', "callOpenSSL(): Error ASN.1 decoding certificate");
        }
      } else {
        if (defined($result->{STDOUT})) {
          $rc = CertNanny::Util->parseCertData('DATA', $result->{STDOUT})
        } else {
          CertNanny::Logging->error('MSG', "callOpenSSL(): Error analysing ASN.1 decoded certificate");
        }
      }
    } else {
      CertNanny::Logging->error('MSG', "callOpenSSL(): Error executing OpenSSL");
    }
  }
  
  return $rc;
} ## end sub callOpenSSL


sub _sanityCheckIn {
  ###########################################################################
  # Checks whether either CERTDATA or CERTFILE but at least one of them is
  # given
  #
  my $self = (shift)->getInstance();

  my $proc = shift;
  my %args = (@_);    # argument pair list

  my $rc;
  # eather CERTFILE or CERTDATA must be provided
  if (!(defined $args{CERTFILE} or defined $args{CERTDATA})) {
    CertNanny::Logging->error('MSG', $proc . "(): No input data specified");
  } elsif ((defined $args{CERTFILE} and defined $args{CERTDATA})) {
    CertNanny::Logging->error('MSG', $proc . "(): Ambigous input data specified");
  } elsif (defined $args{CERTFILE}) {
    $rc = 'CERTFILE';
  } elsif (defined $args{CERTDATA}) {
    $rc = 'CERTDATA';
  }
  
  return $rc;
}


sub _digest_base64 {
  my $self = (shift)->getInstance();
  my %args = (DIGEST  => 'sha1',
              @_);                   # argument pair list
 
  my $digest;
  my $tmpfile = CertNanny::Util->getTmpFile();
  if (CertNanny::Util->writeFile(DSTFILE    => $tmpfile,
                                 SRCCONTENT => $args{CERTDATA})) {
    my $openssl =$self->{CONFIG}->get('cmd.openssl', 'CMD');
    if (defined($openssl)) {
      my @cmd = (CertNanny::Util->osq("$openssl"), 'dgst', '-' . $args{DIGEST}, CertNanny::Util->osq("$tmpfile"));
      chomp($digest = shift(@{CertNanny::Util->runCommand(\@cmd)->{STDOUT}}));
      if ($digest =~ /^.*\)= (.*)$/) {
        $digest = $1;
      }
    }
    $self->forgetTmpFile('FILE', $tmpfile);
  }

  return $digest;
}


sub getCertDigest {
  ###########################################################################
  #
  # Create DER Digest of a certificate
  # 
  # Input: caller must provide a hash ref:
  #   either  CERTDATA   => mandatory: directly contains certificate data
  #   or      CERTFILE   => mandatory: cert file to parse
  #           CERTFORMAT => optional: PEM|DER (default: PEM)
  #           DIGEST     => optional: openssl digest (default: sha1)
  #
  # exacly one of CERTDATA or CERFILE mut be provided
  #
  # Output: caller gets a hash ref:
  #           CERTDIGEST => String with Digest Hash of DER Certificate
  #
  # Convert - if neccesary - to DER
  # Base64 Konvertierung
  # calculate Digest::SHA1
  #
  my $self = (shift)->getInstance();
  
  my %args = (CERTFORMAT => 'PEM',
              OUTFORMAT  => 'DER',
              DIGEST     => 'sha1',
              @_);                   # argument pair list
              
  my $rc;
             
  my ($certType, $cert, $base64, $digest);
  
  # sanity check: DIGEST must be one supported by the openssl Version
  if (!defined(CertNanny::Util->getDigests()->{$args{DIGEST}})) {
    CertNanny::Logging->error('MSG', "DIGEST <$args{DIGEST}> not supported by your version of openssl " . join(',', keys(%{CertNanny::Util->getDigests()})) . ")");
    return;
  }

  if ($certType = $self->_sanityCheckIn('getCertDigest', %args)) {
    if (defined($self->{getCertDigest}->{$args{$certType}}->{$args{DIGEST}})) {
      $rc = {CERTDIGEST => $self->{getCertDigest}->{$args{$certType}}->{$args{DIGEST}}};
    } else {
      if ($cert = CertNanny::Util->convertCert(%args)) {
        if ($digest = $self->_digest_base64('CERTDATA', $$cert{CERTDATA},
                                            'DIGEST'  , $args{DIGEST})) {
          $rc = {CERTDIGEST => $digest};
          $self->{getCertDigest}->{$args{$certType}}->{$args{DIGEST}} = $digest;
        }
      }
    }
  }
  if (defined($rc)) {
    CertNanny::Logging->debug('MSG', "Digest calculated as <$rc->{CERTDIGEST}>\n");
  } else {
    CertNanny::Logging->debug('MSG', "No Digest calculated\n");
  } 
  

  return $rc;
} ## end sub getCertDigest


sub getCertInfoHash {
  # parse DER encoded X.509v3 certificate and return certificate information
  # in a hash ref
  # Prerequisites: requires external openssl executable
  #
  # Input: Hash with
  #   either   CERTDATA   => directly contains certificate data
  #   or       CERTFILE   => cert file to parse
  #   optional CERTFORMAT => PEM|DER (default: DER)
  #
  # exacly one of CERTDATA or CERFILE must be provided
  #
  # Output: Hash with certificate information
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   IssuerName             => <cert issuer common name>
  #   SerialNumber           => <cert serial number> Format: xx:xx:xx... (hex, upper case)
  #   NotBefore              => <cert validity> Format: YYYYDDMMHHMMSS
  #   NotAfter               => <cert validity> Format: YYYYDDMMHHMMSS
  #   CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex,cupper case)
  #   Modulus                => <cert >
  #   PublicKey              => <cert public key> Format: Base64 encoded (PEM)
  #   Certificate            => <certifcate> Format: Base64 encoded (PEM)
  #   BasicConstraints       => <cert basic constraints> Text (free style)
  #   KeyUsage               => <cert key usage> Format: Text (free style)
  #
  # optional (if present in certificate):
  #   SubjectAlternativeName => <cert alternative name>
  #   IssuerAlternativeName  => <issuer alternative name>
  #   SubjectKeyIdentifier   => <X509v3 Subject Key Identifier>
  #   AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>
  #   CRLDistributionPoints  => <X509v3 CRL Distribution Points>
  #
  my $self = (shift)->getInstance();
  my %args = (CERTFORMAT => 'DER',
              DIGEST     => 'sha1',
              @_);    # argument pair list
              
  my $rc;
  
  if (exists($args{CERTINFO})) {
    $rc = $args{CERTINFO}
  } else {   
    # sanity checks
    return if (!$self->_sanityCheckIn('getCertInfoHash', %args));

    my %month = (Jan => 1,  Feb => 2,  Mar => 3,  Apr => 4,
                 May => 5,  Jun => 6,  Jul => 7,  Aug => 8,
                 Sep => 9,  Oct => 10, Nov => 11, Dec => 12);

    my $command = 'x509';
    my @params  = ('text', 'subject', 'issuer', 'serial', 'email', 
                   'startdate', 'enddate', 
                   'modulus', 'fingerprint', $args{DIGEST}, 'pubkey', 
                   'purpose');

    if (defined($rc = CertNanny::Util->callOpenSSL($command, \@params, %args))) {
      ####
      # rewrite dates from human readable to ISO notation
      foreach my $var (qw(NotBefore NotAfter)) {
        my ($mon, $day, $hh, $mm, $ss, $year, $tz) = $rc->{$var} =~ /(\S+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)\s*(\S*)/;
        my $dmon = $month{$mon};
        if (!defined $dmon) {
          CertNanny::Logging->error('MSG', "getCertInfoHash(): could not parse month <$mon> in date <$rc->{$var}> returned by OpenSSL");
          return;
        }

        $rc->{$var} = sprintf("%04d%02d%02d%02d%02d%02d", $year, $dmon, $day, $hh, $mm, $ss);
      } ## end foreach my $var (qw(NotBefore NotAfter))

      # sanity checks
      foreach my $var (qw(Version SerialNumber SubjectName IssuerName NotBefore NotAfter CertificateFingerprint Modulus)) {
        if (!exists $rc->{$var}) {
          CertNanny::Logging->error('MSG', "getCertInfoHash(): Could not determine field <$var> from X.509 certificate");
          return;
        }
      }
    } else {
      CertNanny::Logging->error('MSG', "getCertInfoHash(): Could not retrieve certificate info.");
    }
  }

  return $rc;
} ## end sub getCertInfoHash


sub dumpCertInfoHash {
  # parse DER encoded X.509v3 certificate and dump certificate information
  # in a hash ref
  # Prerequisites: requires external openssl executable
  #
  # Input: Hash with
  #   either   CERTDATA   => directly contains certificate data
  #   or       CERTFILE   => cert file to parse
  #   optional CERTFORMAT => PEM|DER (default: DER)
  #   optional PADDING    => Indent output by PADDING blanks
  #   optional LOCATION   => output the location
  #   optional TYPE       => output the type
  #
  # exactly one of CERTDATA or CERFILE must be provided
  #
  # Output: Hashdump to OUT with certificate information
  #
  my $self = (shift)->getInstance();
  my %args = (CERTFORMAT => 'DER',
              @_);    # argument pair list
              
  my $certinfo = $args{CERTINFO};

  if (!defined($certinfo) && (defined($args{CERTDATA}) || defined($args{CERTFILE}))) {$certinfo = CertNanny::Util->getCertInfoHash(%args)}
  
  if (defined($certinfo)) {
    my $fillup = defined($args{PADDING}) ? ' ' x $args{PADDING} : '';
    CertNanny::Logging->Out('STR', $fillup . "Subject:                  <$certinfo->{'SubjectName'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "Subject alternative name: <$certinfo->{'SubjectAlternativeName'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "Fingerprint:              <$certinfo->{'CertificateFingerprint'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "Validity from:            <$certinfo->{'NotBefore'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "Validity to:              <$certinfo->{'NotAfter'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "Serial:                   <$certinfo->{'SerialNumber'}>\n");
    CertNanny::Logging->Out('STR', $fillup . "--------------------------------------------------------------------------------------------------------------------\n");
    CertNanny::Logging->Out('STR', $fillup . "Location:                 <" . (defined($args{LOCATION})        ? $args{LOCATION}        : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "Type:                     <" . (defined($args{TYPE})            ? $args{TYPE}            : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "--------------------------------------------------------------------------------------------------------------------\n");
    CertNanny::Logging->Out('STR', $fillup . "HTML Status:              <" . (defined($args{HTMLSTATUS})      ? $args{HTMLSTATUS}      : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "SSCEP Status:             <" . (defined($args{SSCEPSTATUS})     ? $args{SSCEPSTATUS}     : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "Transaction ID:           <" . (defined($args{TRANSACTIONID})   ? $args{TRANSACTIONID}   : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "--------------------------------------------------------------------------------------------------------------------\n");
    CertNanny::Logging->Out('STR', $fillup . "PKI Status:               <" . (defined($args{PKISTATUS})       ? $args{PKISTATUS}       : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "Renewal Status:           <" . (defined($args{RENEWALSTATUS})   ? $args{RENEWALSTATUS}   : 'undefined') . ">\n");
    CertNanny::Logging->Out('STR', $fillup . "Renewal Try Count:        <" . (defined($args{RENEWALTRYCOUNT}) ? $args{RENEWALTRYCOUNT} : 'undefined') . ">\n");
  }
} ## end sub dumpCertInfoHash


sub getCSRInfoHash {
  # parse PEM encoded X.509v3 certificate and return certificate information
  # in a hash ref
  # Prerequisites: requires external openssl executable
  #
  # Input: Hash with
  #   CERTDATA   => directly contains certificate data
  #   CERTFILE   => cert file to parse
  #   CERTFORMAT => PEM|DER (optional, default: PEM)
  #
  # exacly one of CERTDATA or CERFILE mut be provided
  #
  # Output: Hash with certificate information
  # always:
  #   Version                => <cert version, optional> Values: 2, 3
  #   SubjectName            => <cert subject common name>
  #   Modulus  e             => <cert modulus>
  #
  my $self = (shift)->getInstance();

  my %args = (CERTFORMAT => 'PEM',
              @_);    # argument pair list
              
  my $rc;

  # sanity checks
  return if (!$self->_sanityCheckIn('getCSRInfoHash', %args));

  my $command   = 'req';
  my @arguments = ('text', 'subject', 'modulus');

  $rc  = CertNanny::Util->callOpenSSL($command, \@arguments, %args);
  
  # sanity checks
  foreach my $var (qw(Version SubjectName Modulus)) {
    if (!exists $rc->{$var}) {
      CertNanny::Logging->error('MSG', "getCSRInfoHash(): Could not determine field <$var> from certificate signing request.");
      return;
    }
  }

  return $rc;
} ## end sub getCSRInfoHash


sub parseCertData {
  my $self = (shift)->getInstance();
  my %args = (FILEHANDLE  => '',
              DATA        => '',
              @_);                 # argument pair list

  my @data;
  if ($args{FILEHANDLE}) {
    my $fh = $args{FILEHANDLE};
    @data = <$fh>;
  }
  if ($args{DATA}) {@data = @{$args{DATA}}}

  my $certinfo = {};
  my $state    = "";
  my @purposes;

  my %mapping = ('serial'                 => 'SerialNumber',
                 'subject'                => 'SubjectName',
                 'issuer'                 => 'IssuerName',
                 'notBefore'              => 'NotBefore',
                 'notAfter'               => 'NotAfter',
                 'SHA1 Fingerprint'       => 'CertificateFingerprint',
                 'PUBLIC KEY'             => 'PublicKey',
                 'CERTIFICATE'            => 'Certificate',
                 'ISSUERALTNAME'          => 'IssuerAlternativeName',
                 'SUBJECTALTNAME'         => 'SubjectAlternativeName',
                 'BASICCONSTRAINTS'       => 'BasicConstraints',
                 'SUBJECTKEYIDENTIFIER'   => 'SubjectKeyIdentifier',
                 'AUTHORITYKEYIDENTIFIER' => 'AuthorityKeyIdentifier',
                 'CRLDISTRIBUTIONPOINTS'  => 'CRLDistributionPoints',
                 'Modulus'                => 'Modulus',);
#  while (<$fh>) {
  foreach (@data) {
    chomp;
    tr/\r\n//d;

    $state = "PURPOSE"                if (/^Certificate purposes:/);
    $state = "PUBLIC KEY"             if (/^-----BEGIN PUBLIC KEY-----/);
    $state = "CERTIFICATE"            if (/^-----BEGIN CERTIFICATE-----/);
    $state = "SUBJECTALTNAME"         if (/X509v3 Subject Alternative Name:/);
    $state = "ISSUERALTNAME"          if (/X509v3 Issuer Alternative Name:/);
    $state = "BASICCONSTRAINTS"       if (/X509v3 Basic Constraints:/);
    $state = "SUBJECTKEYIDENTIFIER"   if (/X509v3 Subject Key Identifier:/);
    $state = "AUTHORITYKEYIDENTIFIER" if (/X509v3 Authority Key Identifier:/);
    $state = "CRLDISTRIBUTIONPOINTS"  if (/X509v3 CRL Distribution Points:/);

    if ($state eq "PURPOSE") {
      my ($purpose, $bool) = (/(.*?)\s*:\s*(Yes|No)/);
      next unless defined $purpose;
      push(@purposes, $purpose) if ($bool eq "Yes");

      # NOTE: state machine will leave PURPOSE state on the assumption
      # that 'OCSP helper CA' is the last cert purpose printed out
      # by OpenCA. It would be best to have OpenSSL print out
      # purpose information, just to be sure.
      $state = "" if (/^OCSP helper CA :/);
      next;
    } ## end if ($state eq "PURPOSE")

    # Base64 encoded sections
    if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/) {
      my $key = $state;
      $key = $mapping{$key} if (exists $mapping{$key});

      $certinfo->{$key} .= "\n" if (exists $certinfo->{$key});
      $certinfo->{$key} .= $_ unless (/^-----/);

      $state = "" if (/^-----END $state-----/);
      next;
    } ## end if ($state =~ /^(PUBLIC KEY|CERTIFICATE)$/)

    # X.509v3 extension one-liners
    if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/) {
      next if (/X509v3 .*:/);
      my $key = $state;
      $key = $mapping{$key} if (exists $mapping{$key});

      # remove trailing and leading whitespace
      s/^\s*//;
      s/\s*$//;
      $certinfo->{$key} = $_ unless ($_ eq "<EMPTY>");

      # alternative line consists of only one line
      $state = "";
      next;
    } ## end if ($state =~ /^(SUBJECTALTNAME|ISSUERALTNAME|BASICCONSTRAINTS|SUBJECTKEYIDENTIFIER|AUTHORITYKEYIDENTIFIER|CRLDISTRIBUTIONPOINTS)$/)

    if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=|Modulus=)\s*(.*)/) {
      my $key   = $1;
      my $value = $2;

      # remove trailing garbage
      $key =~ s/[ :=]+$//;

      # apply key mapping
      $key = $mapping{$key} if (exists $mapping{$key});

      # store value
      $certinfo->{$key} = $value;
    } ## end if (/(Version:|subject=|issuer=|serial=|notBefore=|notAfter=|SHA1 Fingerprint=|Modulus=)\s*(.*)/)
  } ## end while (<$fh>)

  # compose key usage text field
  $certinfo->{KeyUsage} = join(", ", @purposes);

  ####
  # Postprocessing, rewrite certain fields

  ####
  # serial number
  # extract hex certificate serial number (only required for -text format)
  #$certinfo->{SerialNumber} =~ s/.*\(0x(.*)\)/$1/;

  # store decimal serial number
  #$certinfo->{Serial} = hex($certinfo->{SerialNumber});

  # pad with a leading zero if length is odd
  if (length($certinfo->{SerialNumber}) % 2) {
    $certinfo->{SerialNumber} = '0' . $certinfo->{SerialNumber};
  }

  # convert to upcase and insert colons to separate hex bytes
  $certinfo->{SerialNumber} = uc($certinfo->{SerialNumber});
  $certinfo->{SerialNumber} =~ s/(..)/$1:/g;
  $certinfo->{SerialNumber} =~ s/:$//;

  ####
  # get certificate version
  $certinfo->{Version} =~ s/(\d+).*/$1/;

  ####
  # reverse DN order returned by OpenSSL
  foreach my $var (qw(SubjectName IssuerName)) {
    $certinfo->{$var} =
      join(", ", reverse split(/[\/,]\s*/, $certinfo->{$var}));

    # remove trailing garbage
    $certinfo->{$var} =~ s/[, ]+$//;
  }

  return $certinfo;
} ## end sub parseCertData


sub convertCert {
  # convert certificate to other formats
  # input: hash
  # CERTDATA => string containing certificate data OR
  # CERTFILE => file containing certificate data
  # CERTFORMAT => certificate encoding format (PEM or DER), default: DER
  # OUTFORMAT => desired output certificate format (PEM or DER), default: DER
  #
  # return: hash ref
  # CERTDATA => string containing certificate data
  # CERTFORMAT => certificate encoding format (PEM or DER)
  # or undef on error
  my $self = (shift)->getInstance();

  my %args = (CERTFORMAT => 'DER',
              OUTFORMAT  => 'DER',
              @_);                 # argument pair list
              
  my $rc;
                 
  # sanity checks
  foreach my $key (qw( CERTFORMAT OUTFORMAT )) {
    if ($args{$key} !~ m{ \A (?: DER | PEM ) \z }xms) {
      CertNanny::Logging->error('MSG', "convertCert(): Incorrect <$key>: <$args{$key}>");
      return;
    }
  }

  my $infile;

  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd     = (CertNanny::Util->osq("$openssl"), 'x509', '-in',);

    if (exists $args{CERTDATA}) {
      $infile = CertNanny::Util->getTmpFile();
      if (!CertNanny::Util->writeFile(DSTFILE    => $infile,
                                      SRCCONTENT => $args{CERTDATA})) {
        CertNanny::Logging->error('MSG', "convertCert(): Could not write temporary file: <$infile>");
        return;
      }
      push(@cmd, CertNanny::Util->osq("$infile"));
    } else {
      push(@cmd, CertNanny::Util->osq("$args{CERTFILE}"));
    }

    push(@cmd, ('-inform',  $args{CERTFORMAT}));
    push(@cmd, ('-outform', $args{OUTFORMAT}));

    $rc->{CERTFORMAT} = $args{OUTFORMAT};
    my $result = CertNanny::Util->runCommand(\@cmd);
    $rc->{CERTDATA}   = join("", @{$result->{STDOUT}});
    CertNanny::Util->forgetTmpFile('FILE', $infile);

    if ($result->{RC} != 0) {
      CertNanny::Logging->error('MSG', "convertCert(): Could not convert certificate");
      return;
    }
  }

  return $rc;
} ## end sub convertCert


sub getTmpFile {
  # NOTE: this is UNSAFE (beware of race conditions). We cannot use a file
  # handle here because we are calling external programs to use these
  # temporary files.
  my $self = (shift)->getInstance();

  my ($tmpdir, $template, $tmpfile);
  if (defined($self->{CONFIG})) {
    $tmpdir = $self->{CONFIG}->get('path.tmpdir', 'FILE');
    $template = File::Spec->catfile($tmpdir, "cbXXXXXX");
    $tmpfile = mktemp($template);
    push(@{$self->{TMPFILE}}, $tmpfile);
  }
  
  return $tmpfile;
} ## end sub getTmpFile


sub forgetTmpFile {
  my $self = (shift)->getInstance();
  my %args = ('DELETE', 1,
              @_);
   
  my $rc = 1;           
  if (defined($args{FILE})) {            
    @{$self->{TMPFILE}} = grep {$_ ne $args{FILE}} @{$self->{TMPFILE}};
    CertNanny::Util->wipe(FILE => $args{FILE}, SECURE => 1) if ($args{DELETE});
  }         
  
  return $rc;
} ## end sub getTmpFile


sub staticEngine {
  my $self      = (shift)->getInstance();
  my $engine_id = shift;

  unless (defined $engine_id) {
    CertNanny::Logging->error('MSG', "No engine_id passed to staticEngine() as first argument!");
    die;
  }

  my $openssl = $self->{CONFIG}->get('cmd.openssl', 'CMD');
  
  if (defined($openssl)) {
    my @cmd = (CertNanny::Util->osq("$openssl"));
    push(@cmd, 'engine');
    $engine_id =~ s/[^A-Za-z0-9]*//g;
    push(@cmd, $engine_id);
    push(@cmd, '-t');

    CertNanny::Logging->debug('MSG', "Execute: " . join(' ', @cmd));
    my $output = "";
    open FH, join(' ', @cmd) . " |" or die "Couldn't execute " . join(' ', @cmd) . ": $!\n";
    while (defined(my $line = <FH>)) {
      chomp($line);
      $output .= $line;
    }
    close FH;
    CertNanny::Logging->debug('MSG', "Output is <$output>\n");
    return $output =~ m/\(cs\).*\[ available \]/s;
  }
  return;
} ## end sub staticEngine


sub encodeBMPString {
  my $self           = (shift)->getInstance();
  my $stringToEncode = shift;

  my $hex = unpack('H*', "$stringToEncode");

  my $len = length($stringToEncode);

  my $result = "1e:";
  $result .= sprintf("%02x", $len * 2);

  for (my $i = 0; $i < length $hex; $i += 2) {

    $result .= sprintf(":00:%s", substr($hex, $i, 2));
  }

  #print "Util::BMP String:" .$result;
  return $result;

} ## end sub encodeBMPString


sub writeOpenSSLConfig {
  my $self            = (shift)->getInstance();
  my $config_hash     = shift;
  my $config_filename = shift || CertNanny::Util->getTmpFile();

  open(my $configfile, ">", $config_filename)
    or die "Cannot write $config_filename";

  if (defined $config_hash->{openssl_conf}) {
    print $configfile "openssl_conf=$config_hash->{openssl_conf}\n";
    delete $config_hash->{openssl_conf};
  }

  foreach my $section (keys %{$config_hash}) {
    print $configfile "[$section]\n";
    foreach my $entry_hash (@{$config_hash->{$section}}) {
      foreach my $key (keys(%{$entry_hash})) {
        my $value = $entry_hash->{$key};
        if (-e $value and $^O eq "MSWin32") {

          #on Windows paths have a backslash, so in the string it is \\.
          #In the config it must keep the doubled backslash so the actual
          #string would contain \\\\. Yes this is ridiculous...
          $value =~ s#/#\\#g;
          $value =~ s/\\/\\\\/g;
        }
        print $configfile "$key=$value\n";
      } ## end foreach my $key (keys(%{$entry_hash...}))
    } ## end foreach my $entry_hash (@{$config_hash...})
  } ## end foreach my $section (keys %...)

  close $configfile;
  return $config_filename;
} ## end sub writeOpenSSLConfig


sub getDefaultOpenSSLConfig {
  my $self = (shift)->getInstance();

  my $default_config = {openssl_conf   => "openssl_def",
                        openssl_def    => [{engines => "engine_section"},],
                        engine_section => []};

  return $default_config;
} ## end sub getDefaultOpenSSLConfig


sub backoffTime {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " executing waitcycle");
  my $self   = (shift)->getInstance();
  my $config = shift;

  CertNanny::Logging->debug('MSG', "CertNanny::Util::backoffTime");

  if (exists $config->{CONFIG}->{conditionalwait}->{time}) {
    CertNanny::Logging->debug('MSG', "Conditional delay between 0 and " . $config->{CONFIG}->{conditionalwait}->{time} . " seconds");

    my $date = $self->epochToIsoDate(time(), 1);
    my $currentDate = substr($date, 0, 8);
    my $now = time();

    CertNanny::Logging->debug('MSG', "$now currentDate:  $date");
    my $startTime = CertNanny::Util->isoDateToEpoch($currentDate . $config->{CONFIG}->{conditionalwait}->{start}, 1);
    my $endTime   = CertNanny::Util->isoDateToEpoch($currentDate . $config->{CONFIG}->{conditionalwait}->{end},   1);
    CertNanny::Logging->debug('MSG', "$startTime startISO: " . $currentDate . $config->{CONFIG}->{conditionalwait}->{start});
    CertNanny::Logging->debug('MSG', "$endTime endISO: " . $currentDate . $config->{CONFIG}->{conditionalwait}->{end});

    if ($startTime > $endTime) {

      #if the end time is greater then the end time we assume the start time started the day before.
      $startTime -= 24 * 60 * 60;
      CertNanny::Logging->debug('MSG', "new starttime $startTime in ISO" . CertNanny::Util::epochToIsoDate($startTime, 1));
    }

    if ($now > $startTime and $now < $endTime) {
      my $rndwaittime =
        int(rand($config->{CONFIG}->{conditionalwait}->{time}));
      CertNanny::Logging->debug('MSG', "Inside the conditional time frame, start extended backoff time of $rndwaittime seconds");
      sleep $rndwaittime;
    } else {
      CertNanny::Logging->debug('MSG', "Outside the conditional time, no backoff");
      if (exists $config->{CONFIG}->{randomwait}) {
        CertNanny::Logging->debug('MSG', "Random delay between 0 and " . $config->{CONFIG}->{randomwait} . " seconds");
        my $rndwaittime = int(rand($config->{CONFIG}->{randomwait}));
        CertNanny::Logging->info('MSG', "Scheduling renewal but randomly waiting $rndwaittime seconds to reduce load on the PKI");
        sleep $rndwaittime;
      }
    }
  } else {
    if (exists $config->{CONFIG}->{randomwait}) {
      CertNanny::Logging->debug('MSG', "Random delay between 0 and " . $config->{CONFIG}->{randomwait} . " seconds");
      my $rndwaittime = int(rand($config->{CONFIG}->{randomwait}));
      CertNanny::Logging->info('MSG', "Scheduling renewal but randomly waiting $rndwaittime seconds to reduce load on the PKI");
      sleep $rndwaittime;
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " executing waitcycle");
  return 1;
} ## end sub backoffTime


sub getMacAddresses {
  # Find all ethernet MAC addresses on the system
  # and print them to stdout
  #
  # Author: Andreas Leibl
  #         andreas@leibl.co.uk
  # 2013-01-30 Martin Bartosch: minor changes
  #
  my $self = (shift)->getInstance();
  my $rc = 0;
  
  my $command;
  my $s = ':';    # the separator: ":" for Unix, "-" for Win
  if ($^O eq 'MSWin32') {
    $command = 'ipconfig /all';
    $s       = "-";
  } elsif ($^O eq 'aix') {
    $command = "lsdev | egrep -w 'ent[0-9]+' | cut -d ' ' -f 1 | while read adapter; do entstat -d \$adapter | grep 'Hardware Address:'; done";
  } else {
    my $ifconfig = $self->{CONFIG}->get('cmd.ifconfig', 'CMD');
    if (defined($ifconfig)) {
      if ($ifconfig and $ifconfig ne '') {
        $command = "$ifconfig -a";
      } else {
        $command = "ifconfig -a";
      }
    }
  }

  #print "DEBUG: OS is $^O\n";

  local $/;       # slurp
  
  open(my $cmd, '-|', $command) or $rc=1 ;
  my $ifconfigout = <$cmd>;
  close $cmd;

  #print "DEBUG: full command output:\n$ifconfigout DEBUG: end of full output\n\n\nDEBUG: found MAC addresses:\n";
  my @result;
  if ($rc == 0) {
    while ($ifconfigout =~ s/\b([\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2}$s[\da-f]{1,2})\b//i) {
      my $mac = $1;
      $mac =~ s/-/:/g;    # in case we have windows output, harmonise it
      push @result, $mac;
    }
  } else {
    CertNanny::Logging->info('MSG', " unable to determine MAC addresses - ifconfig not available ? ");
  }

  return @result ;
} ## end sub getMacAddresses


sub fetchFileList {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " fetch a file list");
  my $self   = (shift)->getInstance();
  my $myGlob = shift;
  
  my (@myList, @tmpList);
  # Test if $configfileglob contains regular files
  @myList = glob ("'$myGlob'") ;
  foreach my $item (@myList) {
    $item =~ s/^["']*|["']*$//g;
    $item = File::Spec->canonpath($item);
    CertNanny::Logging->debug('MSG', "cannonpath file: <$item>");
    if (-f $item) {
      CertNanny::Logging->debug('MSG', "Found file: <$item>");
      push(@tmpList, $item);
    } else {
      if (-d $item) {
       CertNanny::Logging->debug('MSG', "Found directory: <$item>");
        if (opendir(DIR, $item)) {
          while (defined(my $file = readdir(DIR))) {
            my $osFileName = File::Spec->catfile($item, $file);
            if (-f $osFileName) {
              CertNanny::Logging->debug('MSG', "Found file: <$osFileName>");
              push(@tmpList, $osFileName);
            } else {
              CertNanny::Logging->debug('MSG', "Found non-file: <$osFileName>");
            }
          }
          closedir(DIR);
        }
      } else {
        CertNanny::Logging->debug('MSG', "Item is empty, does not exist or is binary (possible misconfiguration): <$item>");
      }
    }
  } ## end foreach my $item (@myList)
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " fetch a file list");
  return \@tmpList;
} ## end sub fetchFileList

my %OSTYPES = qw(
  aix         Unix
  bsdos       Unix
  beos        Unix
  bitrig      Unix
  dgux        Unix
  dragonfly   Unix
  dynixptx    Unix
  freebsd     Unix
  linux       Unix
  haiku       Unix
  hpux        Unix
  iphoneos    Unix
  irix        Unix
  darwin      Unix
  machten     Unix
  midnightbsd Unix
  minix       Unix
  mirbsd      Unix
  next        Unix
  openbsd     Unix
  netbsd      Unix
  dec_osf     Unix
  nto         Unix
  svr4        Unix
  svr5        Unix
  sco_sv      Unix
  unicos      Unix
  unicosmk    Unix
  solaris     Unix
  sunos       Unix
  cygwin      Unix
  os2         Unix
  interix     Unix
  gnu         Unix
  gnukfreebsd Unix
  nto         Unix
  qnx         Unix
  android     Unix
 
  dos         Windows
  MSWin32     Windows
 
  os390       EBCDIC
  os400       EBCDIC
  posix-bc    EBCDIC
  vmesa       EBCDIC
 
  MacOS       MacOS
  VMS         VMS
  vos         VOS
  riscos      RiscOS
  amigaos     Amiga
  mpeix       MPEiX
);
 
sub os_type {
  my $self   = (shift)->getInstance();
  my ($os) = @_;
  $os = $^O unless defined $os;
  return $OSTYPES{$os} || q{};
}
 
sub is_os_type {
  my $self   = (shift)->getInstance();
  my ( $type, $os ) = @_;
  return unless $type;
  $os = $^O unless defined $os;
  return os_type($os) eq $type;
}

sub wipe {
  # Input: caller must provide a hash ref:
  #           FILE   => mandatory: File to be deleted
  #           SECURE => optional: 0: normal deletion (default)
  #                               1: secure deletion
  #           '00'   => optional: Fillpattern for the first secure deletion run (default 0x0)
  #           'FF'   => optional: Fillpattern for the second secure deletion run (default 0xFF)
  # 
  # Output: undef : error
  #             0 : file to delete does not exist
  #             1 : success 
  my $self   = (shift)->getInstance();
  
  my %args = (FILE   => '',
              SECURE => '0',
              '00'   => '00',
              FF     => 'FF',
              @_);                   # argument pair list
  
  if (-e $args{FILE}) {
    if ($args{SECURE}) {
      my $bytes = -s $args{FILE};
      if ($bytes > 0) {
        eval {open(FILE, '+<', $args{FILE});
              seek(FILE, 0, 0);
              print FILE pack('h*', $args{'00'} x $bytes);
              close(FILE);
              open(FILE, '+<', $args{FILE});
              seek(FILE, 0, 0);
              print FILE pack('h*', $args{FF} x $bytes);
              close(FILE);};
        if ($@) {
          CertNanny::Logging->error('MSG', "Unable to secure overwrite and delete <$args{FILE}>: ", join('', $@));
          return;
        }
      }
    }
    if (!unlink $args{FILE}) {
      CertNanny::Logging->error('MSG', "Unable to delete <$args{FILE}>: ", join('', $@));
      return;
    }
  } else {
    return 0;
  }
  return 1;
}


1;

=head1 NAME

CertNanny::Util - Utility functions for CertNanny.

=head1 SYNOPSIS

    CertNanny::Util->getCertInfoHash();
    CertNanny::Util->writeFile();
    ...

=head1 DESCRIPTION

Provides utility functions for CertNanny. Some functions should be called without any object/instance, some are called via class or instance. On functions that are called via class/instance it does not matter which is used, there is always a singleton instance which will be used.

=head1 FUNCTIONS

=head2 Function List

=over 4

C<new()>

C<getInstance()>

C<runCommand()>

C<isoDateToEpoch()>

C<epochToIsoDate()>

C<expandStr()>

C<printableIsoDate()>

C<readFile()>

C<writeFile()>

C<getCertInfoHash()>

C<getCSRInfoHash()>

C<parseCertData()>

C<getTmpFile()>

C<staticEngine()>

C<writeOpenSSLConfig()>

C<getDefaultOpenSSLConfig()>

=back

=head2 Function Descriptions

=over 4

=item new()

Should not be called directly. Will be uncallable in a future version. Instead call C<getInstance()>. Normally you do not need to call for any instance at all. Just make calls like CertNanny::Util->functionname().

=item getInstance()

Returns a singleton instance of this class. Can be called, but normally does not need to be.

=item runCommand($command)

Called globally, do not call it via class or instance. Runs a command  and returns its exit code. Prints the output to STDOUT (in CertNanny context this is most likely the logfile).

=over 4

=item $command

The command to execute

=back

=item isoDateToEpoch($time)

Convert an ISO date to a Unix timestamp (seconds since the Epoch). Returns Unix timestamp.
Without paramter: Returns the current time in ISO (UTC) timestamp format.

=over 4

=item epochToIsoDate($time)

Convert an Unix timestamp (seconds since the Epoch) to a ISO date. Returns ISO Date (YYYYMMDDHHMMSS).
Without paramter: Returns the current time in ISO (UTC) timestamp format.

=over 4

=item $time

Time in ISO format (YYYYMMDDHHMMSS)

=back

=item expandStr($format)

Expand time format controls (subset as specified by date(1)). Always uses current time.

=over 4

=item %y last two digits of year (00..99)

=item %Y year (1970...)

=item %m month (01..12)

=item %d day of month (01..31)

=item %H hour (00..23)

=item %M minute (00..59)

=item %S second (00..59)

=back

=over 4

=item $time

Format string of expected time format.

=back

=item printableIsoDate($isodate)

Return a printable represantation of a compacted ISO date.

=over 4

=item $isodate

ISO Date, format YYYYMMDDHHMMSS

=back

=item readFile($filename)
Read (slurp) file from disk.

=over 4

=item $filename

The filename to read.

=back

=item writeFile(%args)

Write file to disk. Returns false if file already existss unless $args{FORCE} is set. In this case the method will overwrite the specified file.

=over 4

=item $args{FILENAME}

The name of the file to write.

=item $args{CONTENT}

The data to write.

=item $args{FORCE}

If set, will overwrite existing file.

=back

=item getCertInfoHash(%args)

Parse DER/PEM encoded X.509v3 certificate and return certificate information in a hash ref.
Prerequisites: requires external openssl executable.
Returns hash reference containing the certificate infomration or undef if conflicts occur.
Returned hash reference contains the following values:

=over 4

=item Version => <cert version, optional> Values: 2, 3

=item SubjectName => <cert subject common name>

=item IssuerName => <cert issuer common name>

=item SerialNumber => <cert serial number> Format: xx:xx:xx... (hex, upper case)

=item Modulus => <cert modulus> Format: hex

=item NotBefore => <cert validity> Format: YYYYDDMMHHMMSS

=item NotAfter  => <cert validity> Format: YYYYDDMMHHMMSS

=item PublicKey => <cert public key> Format: Base64 encoded (PEM)

=item Certificate => <certifcate> Format: Base64 encoded (PEM)

=item BasicConstraints => <cert basic constraints> Text (free style)

=item KeyUsage => <cert key usage> Format: Text (free style)

=item CertificateFingerprint => <cert SHA1 fingerprint> Format: xx:xx:xx... (hex, upper case)

=back

optional:

=over 4

=item SubjectAlternativeName => <cert alternative name>
 
=item IssuerAlternativeName => <issuer alternative name>

=item SubjectKeyIdentifier => <X509v3 Subject Key Identifier>

=item AuthorityKeyIdentifier => <X509v3 Authority Key Identifier>

=item CRLDistributionPoints => <X509v3 CRL Distribution Points>

=back

=over 4

=item $args{CERTDATA}

Directly contains certificate data. Conflicts with $args{CERTFILE}.

=item $args{CERTFILE}

Filename to a certificate. Conflicts with $args{CERTDATA}.

=item $args{CERTFORMAT}

Optional argument for data format. Options are all formats understood by OpenSSL (currently: PEM/DER). Defaults to DER.

=back

=item getCSRInfoHash()

Format is the same a with C<getCertInfoHash()> but does not provide all the information since values like NotAfter are not set until issuance.

=item parseCertData($fh)

Internal function that uses openssl output to retrieve csr/cert information. Can be used externally, but is not intended for use and only works with specific params.

=over 4

=item $fh

Filehandle to the output that should be parsed. See C<getCertInfoHash> and C<getCSRInfoHash> for usage exmaples.

=back

=item getTmpFile()

Returns filename for a temporary file. All requested files get deleted automatically upon destruction of the object.
NOTE: this is UNSAFE (beware of race conditions). We cannot use a file handle here because we are calling external programs to use these temporary files.

=item staticEngine($engine_id)

Checks whether the engine was compiled into OpenSSL statically by checking if it is available to OpenSSL. This will also report true if the engine is already made available dynamically.
Returns true if the engine is available, false otherwise.

=over 4

=item $engine_id

The engine_id which should be checked.

=back

=item writeOpenSSLConfig($config_hash, $config_filename)

Writes an OpenSSL configuration file either to $config_filename or to a temporary file. Returns filename of configuration file.

=over 4

=item $config_hash

Configuration hash reference. This hash reference requires a special structure: The keys of this hash reference are the names of the sections for an OpenSSL configuration file. Inside such a section then is an array reference which is sorted in the way the options should be entered into the configuration file. Each array entry contains a hash reference with a single key => value pair that contains the parameter name as key and the parameter's value as the value of the hash reference.
For example, you pass:
 
{section_name}->[0]->{key_name}=value
 
This will lead to:

[section_name]
    
key_name=value


=item $config_filename

Optional string that contains the desired filename. If none is passed then a temporary one is created. The filename is always returned, regardless of this setting. 

=back

=item getDefaultOpenSSLConfig()

Returns an OpenSSL default configuration hash. For the of the hash syntax see C<writeOpenSSLConfig()>. It contains an out-of-section default value openssl_conf=openssl_def denoting the OpenSSL section used as a starting point and contains a default engines=engine_section inside it.

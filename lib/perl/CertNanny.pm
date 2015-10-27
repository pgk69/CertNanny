#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny;

use base qw(Exporter);

use strict;

our @EXPORT    = ();
our @EXPORT_OK = ();
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION $AUTOLOAD);
use Exporter;
use Carp;
use Clone 'clone';

use FindBin;
use File::Spec;

use CertNanny::Util;
use CertNanny::Config;
use CertNanny::Keystore;
use CertNanny::Logging;
use CertNanny::Enroll;
use CertNanny::Enroll::Sscep;
use Data::Dumper;
use POSIX;

use IPC::Open3;

$VERSION = "1.3.0";

my $INSTANCE;


sub getInstance() {
  $INSTANCE ||= (shift)->new(@_);
  return $INSTANCE;
} ## end sub getInstance


sub new {
  if (!defined $INSTANCE) {
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my %args = (@_);      # argument pair list

    my $self = {};
    bless $self, $class;
    $INSTANCE = $self;
    CertNanny::Logging->info('MSG', "============================================================");
    CertNanny::Logging->info('MSG', "CertNanny Version $VERSION Command(s) " . join('|', @ARGV));
    CertNanny::Logging->info('MSG', "============================================================");

    # Store singleton objects in CertNanny
    $self->{CONFIG}  = CertNanny::Config->getInstance(%args); return unless defined $self->{CONFIG};
    $self->{UTIL}    = CertNanny::Util->getInstance(CONFIG => $self->{CONFIG});
    $self->{LOGGING} = CertNanny::Logging->getInstance(CONFIG => $self->{CONFIG});

    use Config;
    use Sys::Hostname;

    CertNanny::Logging->info('MSG', "CertNanny running on " . CertNanny::Util->os_type() . " ($Config{myuname}) under Perl $Config{version}");

    # set default library path
    my @dirs = File::Spec->splitdir($FindBin::Bin);
    pop @dirs;
    if (!$self->{CONFIG}->get("path.lib", "FILE")) {
      $self->{CONFIG}->set("path.lib", File::Spec->catdir(@dirs, 'lib'));
      CertNanny::Logging->debug('MSG', "set perl path lib to: <" . $self->{CONFIG}->get("path.lib", "FILE") . ">");
    }
    if (!$self->{CONFIG}->get("path.libjava", "FILE")) {
      $self->{CONFIG}->set("path.libjava", File::Spec->catdir($self->{CONFIG}->get("path.lib", "FILE"), 'java'));
      CertNanny::Logging->debug('MSG', "set java path lib to: <" . $self->{CONFIG}->get("path.libjava", "FILE") . ">");
    }

    if ($self->{CONFIG}->get("cmd.opensslconf", "FILE")) {
      $ENV{OPENSSL_CONF} = $self->{CONFIG}->get("cmd.opensslconf", "FILE");
      CertNanny::Logging->debug('MSG', "set OPENSSL_CONF enviroment var to: <" . $self->{CONFIG}->get("cmd.opensslconf", "FILE") . ">");
    }
    $self->{OPENSSL_DIGEST} = 'sha1';
    if ($self->{CONFIG}->get("cmd.openssldigest")) {
      $self->{OPENSSL_DIGEST} = $self->{CONFIG}->get("cmd.openssldigest");
    }
    CertNanny::Logging->debug('MSG', "set default Digest to: <" . $self->{OPENSSL_DIGEST} . ">");

    $self->{ITEMS} = ${$self->{CONFIG}->getRef("keystore", 'ref')};
    delete $self->{ITEMS}->{DEFAULT};
  }
  return $INSTANCE;
} ## end sub new


sub DESTROY {
  # Windows apparently flushes file handles on close() and ignores autoflush...
  $INSTANCE = undef;
}


sub setOption {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3]);
  my $self  = (shift)->getInstance();
  my $key   = shift;
  my $value = shift;

  $self->{OPTION}->{$key} = $value;

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Key: <$key>  Value: <$value>");
  return 1;
} ## end sub setOption


sub getOption {
  my $self  = (shift)->getInstance();
  my $key   = shift;

  my $value;
  if (defined($self->{OPTION}->{$key}) && ($self->{OPTION}->{$key} ne '')) {
    $value = $self->{OPTION}->{$key};
  }

  return $value;
} ## end sub setOption


sub AUTOLOAD {
  my $self = (shift)->getInstance();
  my $attr = $AUTOLOAD;
  $attr =~ s/.*:://;
  return if $attr eq 'DESTROY';

  if ($attr =~ /^(?:dump|test)$/) {
    my $action = "do_$attr";
    return $self->$action();
  }
  if ($attr =~ /^(?:check|renew|enroll|cleanup|updateRootCA|executeHook)$/) {
    return $self->_iterate_entries("do_$attr");
  }

  CertNanny::Logging->error('MSG', "Invalid action specified: <$attr>");
} ## end sub AUTOLOAD


sub _iterate_entries {
  my $self   = (shift)->getInstance();
  my $action = shift;

  my $loglevel   = $self->{CONFIG}->get('log.level') || 3;
  my $myKeystore = $self->getOption('keystore') || '';
  my $mode       = ($self->getOption('force')) ? 'FORCED' : 'SCHEDULED';
 
  foreach my $entryname (keys %{$self->{ITEMS}}) {    # Instantiate every keystore, that is configured
    CertNanny::Logging->debug('MSG', "Testing keystore: <$myKeystore> specified by commandline against keystore found on system: <$entryname>") if ($myKeystore ne '');
    next if (($myKeystore ne '') && ($myKeystore ne $entryname));

    $self->_work_on_entry(ACTION    => $action,
                          MODE      => $mode,
                          ENTRYNAME => $entryname,
                          ENTRY     => $self->{ITEMS}->{$entryname});

  } ## end foreach my $entryname (keys %{$self...})

  return 1;
} ## end sub _iterate_entries


sub _work_on_entry {
  my $self   = (shift)->getInstance();
  my %args = (@_);

  my $action    = $args{ACTION};
  my $mode      = $args{MODE};
  my $entryname = $args{ENTRYNAME};
  my $entry     = $args{ENTRY};

  CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                               'VALUE', $entryname);
  CertNanny::Logging->info('MSG', "-------------------------------------------");
  CertNanny::Logging->info('MSG', "Working on keystore <$entryname>");
  CertNanny::Logging->info('MSG', "-------------------------------------------");
  my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG}, # give it the whole configuration
                                          ENTRY     => $entry,          # all keystore parameters from configfile
                                          ENTRYNAME => $entryname);     # and the keystore name from configfile
  if (ref($keystore)) {
    # Keystore could be instantiated -> execute operation
    $self->$action(MODE      => $mode,
                   ENTRY     => $entry,
                   ENTRYNAME => $entryname,
                   KEYSTORE  => $keystore);
  } elsif ($keystore eq '0') {
    # Keystore could not be instantiated -> skip keystore
    CertNanny::Logging->error('MSG', "Keystore <$entryname> not instantiated. Skipping.");
  } elsif (!defined($keystore)){
    # Keystore could not be instantiated -> may be initial enrollment works
    CertNanny::Logging->error('MSG', "Keystore <$entryname> not instantiated.");
    if ($action eq 'do_renew' or $action eq 'do_enroll') {
      # Maybe some day we allow a enrollment on en existing Keystore if Mode is FORCED
      $self->do_enroll(ENTRYNAME => $entryname,
                       ENTRY     => $entry);
    } else {
      CertNanny::Logging->error('MSG', "Skipping.");
    }
  } else {
    CertNanny::Logging->error('MSG', "Keystore <$entryname> not instantiated. Skipping.");
  }
  CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                               'VALUE', 'Common');

  return 1;
} ## end sub _iterate_entries


sub _dump_value {
  my $self = shift;
  my $cref = shift;
  my $aref = shift;

  # First handle all values
  foreach my $key (sort {lc($a) cmp lc($b)} keys %{$cref}) {
    if (ref($cref->{$key}) ne "HASH") {
      next if ($key eq 'INHERIT');                  # We do not dump this INHERIT stuff since it does give no information
      my $name  = '  ' x ($#$aref + 1) . $key . ' = ';
      my $value = $name =~ /(pin|pw|target_pw|storepass|keypass|srcstorepass|deststorepass|srckeypass|destkeypass)/ ? "*HIDDEN*" : $cref->{$key};
      my $fillup = ' ' x (100 - length($name) - length($value));
      CertNanny::Logging->Out('STR', $name . $fillup . $value . "\n");
    }
  }
  # Then handle all HASHs
  # no $self->{keystore}              : print all
  foreach my $key (sort {lc($a) cmp lc($b)} keys %{$cref}) {
    if (ref($cref->{$key}) eq "HASH") {
      my $target = $self->getOption('keystore');
      next if (!defined($$aref[0]) && ($key eq 'keystore') && (uc($target) eq 'COMMON')); # print all but the keystores
      next if (defined($$aref[0]) && !defined($$aref[1]) && $target &&
              ($$aref[0] eq 'keystore') && ($key ne $target)); # $self->{keystore} = <keystore>: print all but the keystores plus <keystore>
      push(@$aref, $key);
      CertNanny::Logging->Out('STR', '  ' x $#$aref . "$key Start\n");
      $self->_dump_value(\%{$cref->{$key}}, $aref);
      CertNanny::Logging->Out('STR', '  ' x $#$aref . "$key End\n");
      pop(@$aref);
    }
  }
}


sub do_dump {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Dump command");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $config    = $self->{CONFIG};
  my $target = $self->getOption('keystore');

  # If a dump is requested, it should go to console not matter what is specified by commandline or configfile
  CertNanny::Logging->switchConsoleErr('STATUS', 1);
  CertNanny::Logging->switchConsoleOut('STATUS', 1);
  # and by the way we do not want all the junk on the concole
  CertNanny::Logging->logLevel('TARGET', 'console', 'LEVEL', 0);

  if ($self->{OPTION}->{object} =~ /^data/) {
    my @hashname;
    $self->_dump_value(\%{$config->{CONFIG}}, \@hashname);
  } elsif ($self->{OPTION}->{object} =~ /^cfg|^config/) {
    foreach my $configFileName (sort {lc($a) cmp lc($b)} keys %{$config->{CONFIGFILES}}) {
      my $printthiskeystore = 0;
      if (defined($target)) {
        my @keystore = @{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}};
        if (@keystore) {
          foreach my $ks (@keystore) {
            if (($ks eq $target) || ($ks eq 'DEFAULT')) {
              $printthiskeystore = 1;
            }
          }
        } else {
          $printthiskeystore = 1;
        }
      } else {
        $printthiskeystore = 1;
      }
      if ($printthiskeystore) {
        CertNanny::Logging->Out('STR', "File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
        foreach my $lnr (sort {lc($a) <=> lc($b)} keys %{$config->{CONFIGFILES}->{$configFileName}->{CONTENT}}) {
          my $content = $config->{CONFIGFILES}->{$configFileName}->{CONTENT}->{$lnr};
          my $name = (split('=', $content))[0];
          if ($name =~ /(pin|pw|target_pw|storepass|keypass|srcstorepass|deststorepass|srckeypass|destkeypass)/) {
            $content = "${name}= *HIDDEN*";
          }
          CertNanny::Logging->Out('STR', sprintf("Line: %3s Content: <%s>\n", $lnr, $content));
        }
        CertNanny::Logging->Out('STR', "\n");
      }
    }
  } elsif ($self->{OPTION}->{object} =~ /^key/) {
    my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
    foreach my $keystore (@keystores) {
      next if (defined($target) && ($target ne $keystore));
      CertNanny::Logging->Out('STR', "Keystore <$keystore>:\n");
      foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
        foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
          if ($keystore eq $cfgFileKeystore) {
            CertNanny::Logging->Out('STR', "  File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
          }
        }
      }
    }
  } elsif ($self->{OPTION}->{object} =~ /^cert/) {
    my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
    foreach my $keystore (@keystores) {
      next if (defined($target) && ($target ne $keystore));
      CertNanny::Logging->Out('STR', "Keystore <$keystore>:\n");
      CertNanny::Logging->Out('STR', "  --------------------------------------------------------------------------------------------------------------------\n");
      foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
        foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
          if ($keystore eq $cfgFileKeystore) {
            CertNanny::Logging->Out('STR', "  File: <$configFileName> SHA1: $config->{CONFIGFILES}->{$configFileName}->{SHA}\n");
          }
        }
      }
      CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                                   'VALUE', $keystore);
      my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},             # give it the whole configuration
                                              ENTRY     => $self->{ITEMS}->{$keystore}, # all keystore parameters from configfile
                                              ENTRYNAME => $keystore);                  # and the keystore name from configfile
      if ($keystore) {
        my $instance  = $keystore->{INSTANCE};
        my $options   = $instance->{OPTIONS};
        if ($options->{ENTRY}->{'location'} ne 'rootonly') {
          $keystore->{CERT} = $instance->getCert();
          if (defined($keystore->{CERT})) {
            CertNanny::Logging->Out('STR', "  --------------------------------------------------------------------------------------------------------------------\n");
            CertNanny::Util->dumpCertInfoHash(%{$keystore->{CERT}},
                                                'PADDING',         2,
                                                'LOCATION',        $options->{ENTRY}->{'location'},
                                                'TYPE',            $options->{ENTRY}->{'type'},
                                                'HTMLSTATUS',      $instance->{STATE}->{DATA}->{SCEP}->{HTMLSTATUS},
                                                'SSCEPSTATUS',     $instance->{STATE}->{DATA}->{SCEP}->{SSCEPSTATUS},
                                                'PKISTATUS',       $instance->{STATE}->{DATA}->{SCEP}->{PKISTATUS},
                                                'TRANSACTIONID',   $instance->{STATE}->{DATA}->{SCEP}->{TRANSACTIONID},
                                                'RENEWALSTATUS',   $instance->{STATE}->{DATA}->{RENEWAL}->{STATUS});
          }
        }
      }
      CertNanny::Logging->Out('STR', "\n");
      CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                                   'VALUE', 'Common');
    }
  } else {
#    CertNanny::Logging->switchConsoleErr('STATUS', 1);
    CertNanny::Logging->Err('STR', "Missing Argument: --object cfg|data|key|cert   specifies the object to be dumped\n");
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Dump command");
  return 1;
} ## end sub do_cfgdump


sub do_check {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Check command");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $entry     = $args{ENTRY};
  my $config    = $options->{CONFIG};

  my $rc = undef;

  if($options->{ENTRY}->{'location'} eq 'rootonly') {
    CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------");
    CertNanny::Logging->debug('MSG', "ROOTONLY KEYSTORE ($entryname): Skip certificate check and renewal");
    CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------");
    $rc = 1;
  } else {
    $keystore->k_executeHook($entry->{hook}->{execution});
    $keystore->{CERT} = $instance->getCert();
    if (defined($keystore->{CERT})) {
      $keystore->{CERT}->{CERTINFO} = CertNanny::Util->getCertInfoHash(%{$keystore->{CERT}});

      if ($instance->k_validEqualLessThan(0)) {
        CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------");
        CertNanny::Logging->error('MSG', "EXPIRED ($entryname): Certificate has expired. Too late for automatic renewal.");
        CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------");
        $instance->k_executeHook($entry->{hook}->{warnexpired});
      } else {
        $rc = 1;
        if ($instance->k_validEqualLessThan($self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days})) {
          CertNanny::Logging->debug('MSG', "---------------------------------------------------------------------------------------------------------------");
          CertNanny::Logging->info('MSG', "RENEWAL SHOULD BE SCHEDULED ($entryname): Certificate is valid for less than $self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days} days.");
          CertNanny::Logging->debug('MSG', "---------------------------------------------------------------------------------------------------------------");
        } else {
          CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------------------------------");
          CertNanny::Logging->info('MSG', "NO ACTION REQUIRED ($entryname): Certificate is valid for more than $self->{ITEMS}->{$args{ENTRYNAME}}->{autorenew_days} days.");
          CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------------------------------");
        }

        if ($instance->k_validEqualLessThan($self->{ITEMS}->{$args{ENTRYNAME}}->{warnexpiry_days})) {
          CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------------------------");
          CertNanny::Logging->notice('MSG', "WARNEXPIRY ($entryname): Certificate  is valid for less than $self->{ITEMS}->{$args{ENTRYNAME}}->{warnexpiry_days} days");
          CertNanny::Logging->debug('MSG', "------------------------------------------------------------------------------------------------");
          $rc = $instance->k_executeHook($entry->{hook}->{warnexpiry});
        }
      }
    } else {
      CertNanny::Logging->debug('MSG', "----------------------------------------------------------");
      CertNanny::Logging->error('MSG', "ERROR ($entryname): Could not parse instance certificate.");
      CertNanny::Logging->debug('MSG', "----------------------------------------------------------");
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Check command");
  return $rc;
} ## end sub do_check


sub do_renew {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Renew command");
  my $self   = (shift)->getInstance();
  my %args = (@_);
  my %args = (MODE => 'SCHEDULED',
              @_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (($args{MODE} eq 'FORCED') || defined($self->do_check(%args))) {
    $self->do_updateRootCA(%args);
    if($self->{ITEMS}->{$entryname}->{'location'} ne 'rootonly') {
      if (($args{MODE} eq 'FORCED') || $instance->k_validEqualLessThan($self->{ITEMS}->{$entryname}->{autorenew_days})) {
        CertNanny::Logging->debug('MSG', "---------------------------------------------------------------------------------");
        CertNanny::Logging->info('MSG', "RENEWAL IS $args{MODE} ($entryname).");
        CertNanny::Logging->debug('MSG', "---------------------------------------------------------------------------------");
        CertNanny::Util->backoffTime($self->{CONFIG});
        $instance->k_renew();
      } else {
        CertNanny::Logging->debug('MSG',"no renewal " . lc($args{MODE}) . " ($entryname).");
      }
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Renew command");
  return 1;
} ## end sub do_renew


sub _enroll_location {
  my $self      = (shift)->getInstance();
  my %args      = (@_);
 
  my $rc;
  
  if ($args{METHODE} eq 'certificate') {
    $rc = $args{ENTRY}->{initialenroll}->{auth}->{cert}
  }
  if (($args{METHODE} eq 'password') || ($args{METHODE} eq 'anonymous')) {
    $rc = File::Spec->catfile($args{ENTRY}->{statedir}, $args{ENTRYNAME} . "-selfcert.pem");

    if (-e $rc) {
      CertNanny::Logging->debug('MSG', "Initial Enrollment Certificate already exists");
    } else {
      $rc = $args{CERTFILE};
    }
  }

  return $rc;
}


sub _enroll_file {
  my $self      = (shift)->getInstance();
  my %args      = (@_);
 
  my $rc;
  
  if ($args{METHODE} eq 'certificate') {
    $rc = $args{ENTRY}->{initialenroll}->{auth}->{key}
  }
  if (($args{METHODE} eq 'password') || ($args{METHODE} eq 'anonymous')) {
    if ($args{METHODE} eq 'password') {
      if (!defined $args{ENTRY}->{initialenroll}->{auth}->{challengepassword}) {
        CertNanny::Logging->debug('MSG', 'Using commandline argument challangePassword for initial enrollment');
        $args{ENTRY}->{initialenroll}->{auth}->{challengepassword} = $self->getOption('challengepassword');
      }
    }
 
    $rc = File::Spec->catfile($args{ENTRY}->{statedir}, $args{ENTRYNAME} . "-key.pem");
    if (-e $rc) {
      CertNanny::Logging->debug('MSG', "Initial Enrollment Key already generated");
    } else {
      $rc = $args{KEYFILE};
    }
  }

  return $rc;
}


sub do_enroll {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Enroll command");
  my $self      = (shift)->getInstance();
  my %args      = (@_);
  
  my $entryname = $args{ENTRYNAME};
  my $entry     = $args{ENTRY};

  my $rc;

  if (defined($entry->{initialenroll}->{activ})) {
    CertNanny::Logging->info('MSG', "Keystore <$entryname>: Initial enrollment already activ.");
  } else {
    if (defined($args{KEYSTORE}) && ($args{MODE} ne 'FORCED')) {
      # NO KEYSTORE in %args allowed, since enrollment on an existing Keystore ist not supported!!!
      CertNanny::Logging->error('MSG', "Keystore <$entryname>: Initial enrollment on an existing keystore must be forced to be executed.");
    } else {
      CertNanny::Logging->debug('MSG', "Keystore <$entryname>: Check for initial enrollment configuration.");
      if (defined($args{METHODE} = $entry->{initialenroll}->{auth}->{mode})) {
        if (($args{METHODE} eq 'certificate') || ($args{METHODE} eq 'password') || ($args{METHODE} eq 'anonymous')) {
          CertNanny::Logging->info('MSG', "Keystore <$entryname>: Found initial enrollment configuration for " . $self->{ITEMS}->{$entryname}->{initialenroll}->{subject});
          if (($args{METHODE} eq 'password') || ($args{METHODE} eq 'anonymous')) {
            # create selfsigned certificate
            my $selfsigned = CertNanny::Util->createSelfSign('DIGEST'    => $entry->{digest} || $self->{OPENSSL_DIGEST} || 'sha1',
                                                             'ENTRY'     => $entry,
                                                             'ENTRYNAME' => $entryname);
            $args{CERTFILE} = $selfsigned->{CERT};
            $args{KEYFILE}  = $selfsigned->{KEY};
          }
          
          # copy current entry and change copy to an enrollment keystore
          my $newentry                           = clone($entry);
          # save the values of the target entry for later use
          $newentry->{target}                    = $entry;
          # This is an new enrollment keystore, set parameters
          delete($newentry->{statefile});
          $newentry->{initialenroll}->{activ}    = '1';
          $newentry->{type}                      = 'OpenSSL';
          $newentry->{location}                  = $self->_enroll_location(%args);
          $newentry->{key}->{format}             = 'PEM';
          $newentry->{key}->{file}               = $self->_enroll_file(%args);
          $newentry->{key}->{pin}                = $entry->{initialenroll}->{auth}->{pin};
          $newentry->{enroll}->{engine_section}  = undef;
          $newentry->{enroll}->{sscep}->{engine} = undef;
          $args{ENTRYNAME}                       = $entryname.'.enrollment';  
          $args{ENTRY}                           = $newentry;

          # and do a normal renewal
          $rc = $self->_work_on_entry(ACTION    => 'do_renew',
                                      MODE      => 'FORCED',
                                      %args);
        } else {
          CertNanny::Logging->error('MSG', "Keystore <$entryname>: Initial enrollment authentication method <$args{METHODE}> for keystore <$args{ENTRYNAME}> not supported");
        } 
      } else {
        CertNanny::Logging->info('MSG', "Keystore <$entryname>: No initial enrollment configuration found.");
      }
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Enroll command");
  return $rc;
} ## end sub do_enroll


sub do_cleanup {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " CleanUp command");
  my $self = (shift)->getInstance();
  my %args = (@_);
  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};

  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if ($self->getOption('force')) {
    $instance->k_checkclearState(0);
  } else {
    $instance->k_checkclearState(1);
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " CleanUp command");
  return 1;
} ## end sub do_info


sub do_updateRootCA {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Update Root CA command");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (defined $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} &&
      $self->{ITEMS}->{$entryname}->{rootcaupdate}->{enable} eq "true") {
    CertNanny::Logging->debug('MSG', "RootCA update activated. Synchonizing Root CAs.");
    $instance->k_getNextTrustAnchor();
    if ($instance->k_syncRootCAs()) {
      CertNanny::Logging->debug('MSG', "Root CAs successfuly synchronized.");
    } else {
      CertNanny::Logging->debug('MSG', "Synchronizing Root CAs failed.");
    }
  } else {
    CertNanny::Logging->debug('MSG', "RootCA update deactivated");
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3]);
  return 1;
} ## end sub do_updateRootCA


sub do_executeHook {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Info");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $keystore  = $args{KEYSTORE};
  my $instance  = $keystore->{INSTANCE};
  my $options   = $instance->{OPTIONS};
  my $entryname = $options->{ENTRYNAME};
  my $entry     = $options->{ENTRY};
  my $config    = $options->{CONFIG};

  my $hook        = $self->getOption('hook');
  my $definitions = $self->getOption('define');
  my %hookargs;
  foreach (@{$definitions}) {
    (my $key, my $value) = split('=');
    $hookargs{$key} = $value;
  }

  if ($hook) {
    if ($entry->{hook}) {
      CertNanny::Logging->debug('MSG', "Executing keystore <$entryname> hook <$hook> with command <$entry->{hook}>");
      CertNanny::Logging->Out('STR', "Executing keystore <$entryname> hook <$hook> with command <$entry->{hook}>\n");
      $keystore->k_executeHook($entry->{hook}, %hookargs);
    } else {
      CertNanny::Logging->debug('MSG', "No command defined for keystore <$entryname> hook <$hook> (possible typo in config or command line?)");
      CertNanny::Logging->Out('STR', "No command defined for keystore <$entryname> hook <$hook> (possible typo in config or command line?)\n");
    }
  } else {
  	CertNanny::Logging->debug('MSG', "No hook specified for keystore <$entryname> executeHook operation");
    CertNanny::Logging->Out('STR', "No hook specified for keystore <$entryname> executeHook operation\n");
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Update Root CA command");
  return 1;
} ## end sub do_info


sub do_test {
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Test command");
  my $self = (shift)->getInstance();
  my %args = (@_);

  my $config = $self->{CONFIG};
  my $target = $self->getOption('keystore');

  my @keystores = (sort {lc($a) cmp lc($b)} keys(%{$config->{CONFIG}->{'keystore'}}));
  foreach my $keystore (@keystores) {
    next if (defined($target) && ($target ne $keystore));
    CertNanny::Logging->Out('STR', "Keystore <$keystore:>\n");
    foreach my $configFileName (keys %{$config->{CONFIGFILES}}) {
      foreach my $cfgFileKeystore (@{$config->{CONFIGFILES}->{$configFileName}->{KEYSTORE}}) {
        if ($keystore eq $cfgFileKeystore) {
          CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                                       'VALUE', $keystore);
          my $keystore = CertNanny::Keystore->new(CONFIG    => $self->{CONFIG},             # give it the whole configuration
                                                  ENTRY     => $self->{ITEMS}->{$keystore}, # all keystore parameters from configfile
                                                  ENTRYNAME => $keystore);                  # and the keystore name from configfile
          if ($keystore) {
            $keystore     = $keystore->{INSTANCE};
            my $options   = $keystore->{OPTIONS};
            my $entry     = $options->{ENTRY};
            my $enroller  = $keystore->k_getEnroller();
            if (defined($enroller)) {
              my %certs = $enroller->getCA();
              if (%certs) {
                CertNanny::Logging->Out('STR', "  Certificate <$certs{RACERT}>:\n");
                CertNanny::Util->dumpCertInfoHash('CERTINFO', $keystore->{CERT}->{CERTINFO},
                                                  'CERTDATA', $keystore->{CERT}->{CERTDATA},
                                                  'CERTFILE', $keystore->{CERT}->{CERTFILE},
                                                  'PADDING',  4,
                                                  'LOCATION', $entry->{'location'},
                                                  'TYPE',     $entry->{'type'});
                foreach my $cert (@{$certs{CACERTS}}) {
                  CertNanny::Logging->Out('STR', "  Certificate <$cert->{CERTFILE}>:\n");
                  CertNanny::Util->dumpCertInfoHash('CERTINFO', $cert->{CERTINFO},
                                                    'CERTDATA', $cert->{CERTDATA},
                                                    'CERTFILE', $cert->{CERTFILE},
                                                    'PADDING',  4,
                                                    'LOCATION', $entry->{'location'},
                                                    'TYPE',     $entry->{'type'});
                }
                CertNanny::Logging->Out('STR', "\n");
              } else {
                CertNanny::Logging->Out('STR', "  Could not instantiate Keystore: <$keystore>\n");
              }
            }
          }
          CertNanny::Util->setVariable('NAME',  'KEYSTORE',
                                       'VALUE', 'Common');
        }
      }
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Test command");
  return 1;
} ## end sub do_test


1;

#
# CertNanny - Automatic renewal for X509v3 certificates using SCEP
# 2005-02 Martin Bartosch <m.bartosch@cynops.de>
#
# This software is distributed under the GNU General Public License - see the
# accompanying LICENSE file for more details.
#

package CertNanny::Keystore::MQ;

use base qw(Exporter CertNanny::Keystore::OpenSSL);

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS $VERSION);
use Exporter;
use Carp;

# use IO::File;
# use File::Spec;
use File::Copy;
use File::Basename;
use Data::Dumper;
use English;

use CertNanny::Util;

# keyspecific needed modules
use Cwd;


################################################################################


sub new {
  my $proto = shift;
  my $class = ref($proto) || $proto;
  my %args = (@_);    # argument pair list

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " instantiating MQ keystore <$args{ENTRYNAME}>.");

  my $self = {};
  bless $self, $class;

  $self->{OPTIONS} = \%args;

  # GET VALUES AND SET DEFAULTS
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  # get keystore PIN
  $self->{PIN} = $self->_unStash($entry->{location} . ".sth");

  $options->{gsk6cmd} = $config->get('cmd.gsk6cmd', 'CMD');
  $options->{gskcmd} = $config->get('cmd.gskcmd', 'CMD');

  if (defined $options->{gsk6cmd}){
    # on certain platforms we need cannot find the location of the
    #   GSKit library directory ourselves, in this case it must be configured.
    $options->{gsklibdir} = $config->get('path.gsklib', 'FILE');
    $options->{gsklibdir} = undef if ($options->{gsklibdir} eq '');
    return "gsk6cmd not found" unless (defined $options->{gsk6cmd} and -x $options->{gsk6cmd});

    $options->{JAVA} = $config->get('cmd.java', 'CMD');
    if (defined $ENV{JAVA_HOME}) {
      $options->{JAVA} ||= File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java');
    }

    $options->{GSKIT_CLASSPATH} = $config->get('path.gskclasspath', 'FILE');
  } else {
    if (!defined $options->{gskcmd}){
      return "gskcmd not found" unless (defined $options->{gsk6cmd});
    }
  }

  # set key generation operation mode:
  # internal: create RSA key and request with MQ keystore
  # external: create RSA key and request outside MQ keystore (OpenSSL)
  #           and import resulting certificate/key as PKCS#12 into keystore
  $options->{keygenmode} = "external";
  if (exists $entry->{keygenmode}) {
    $options->{keygenmode} = $entry->{keygenmode};
  }

  # SANITY CHECKS
  return "Illegal keygenmode: $options->{keygenmode}" unless ($options->{keygenmode} =~ /^(external)$/);

  # RETRIEVE AND STORE STATE
  # get previous renewal status and check if we can write to the file
  if (!defined($self->k_retrieveState()) || !defined($self->k_storeState())) {
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " instantiating MQ keystore <$args{ENTRYNAME}>.");
    return;
  }

  # return new keystore object
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " instantiating MQ keystore <$args{ENTRYNAME}>.");
  return $self;
} ## end sub new


sub DESTROY {
  my $self = shift;

  # check for an overridden destructor...
  $self->SUPER::DESTROY if $self->can("SUPER::DESTROY");
}


sub getCert {
  ###########################################################################
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE   => file containing the cert OR
  #        or CERTDATA   => string containing the cert
  #        if neither CERTFILE nor CERTDATA ist provided, default is
  #        CERTFILE => $self->{OPTIONS}->{ENTRY}->{location}
  #
  # Input: caller must provide the file location.
  #        if no file location is provided default is
  #        $self->{OPTIONS}->{ENTRY}->{location}
  #
  # Output: caller gets a hash ref:
  #           CERTDATA   => string containg the cert data
  #           CERTFORMAT => 'PEM' or 'DER'
  #           CERTREST   => string containing the rest of the input when the 
  #                         first cert is extracted
  #         or undef on error
  #
  # Gets the first certificate found either in CERTDATA or in CERTFILE and 
  # returns it in CERTDATA. 
  # If there is a rest in the input, it is returned in CERTREST
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (exists $self->{CERTINFO}) {
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
    return  $self->{CERTINFO};
  }
  
  my $filename = $entry->{location} . '.kdb';
  if (!-r "$filename") {
    $filename = $entry->{location};
  }

  if (!-r "$filename") {
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
    return undef;
  }

  my $gsk6cmd = $options->{gsk6cmd};
  if(!defined $options->{gsk6cmd}){
    $gsk6cmd = $options->{gskcmd};   
  }

  my $label = $self->_getCertLabel();
  if (!defined $label) {
    CertNanny::Logging->error('MSG', "getCert(): could not get label");
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
    return undef;
  }

  my $certfile = CertNanny::Util->getTmpFile();

  # get label name for user certificate
  CertNanny::Logging->debug('MSG', "extract cert with label <$label>");
   
  my @cmd;
  @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-extract', '-db', CertNanny::Util->osq("$filename"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-label', CertNanny::Util->osq("$label"), '-target', CertNanny::Util->osq("$certfile"), '-format', 'binary');   
 
  #if (system(join(' ', @cmd)) != 0) {
  if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC} != 0) {  
    CertNanny::Util->wipe(FILE => $certfile, SECURE => 1);
    CertNanny::Logging->error('MSG', "getCert(): could not extract certificate");
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
    return undef;
  }

  # read certificate from file and remove temp file
  my $content = CertNanny::Util->readFile($certfile);
  CertNanny::Util->wipe(FILE => $certfile, SECURE => 1);
  if (!defined $content) {
    CertNanny::Logging->error('MSG', "getCert(): Could not open input file $certfile");
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore");
    return undef;
  }

# Todo Arkadius Frage: getCert: Wieso setzt die Methode dieses CERTINFO, die anderen Keymethoden geben nur einen Hash zurueck
# Todo Arkadius Frage: getCert: Hash Element LABEL existiert nur bei diesem Key!!
  $self->{CERTINFO}->{LABEL}      = $label;
  $self->{CERTINFO}->{CERTDATA}   = $content;
  $self->{CERTINFO}->{CERTFORMAT} = "DER";

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get main certificate from keystore gsk");
  return $self->{CERTINFO};
} ## end sub getCert


sub installCert {
   ###########################################################################
  #
  # installs a new main certificate from the SCEP server in the keystore
  #
  # Input: caller must provide a hash ref:
  #           CERTFILE  => file containing the cert OR
  #           TARGETDIR => directory, where the new certificate should be installed to
  #
  # Output: true: success false: failure
  #
  # This method is called once the new certificate has been received from
  # the SCEP server. Its responsibility is to create a new keystore containing
  # the new key, certificate, CA certificate keychain and collection of Root
  # certificates configured for CertNanny.
  # A true return code indicates that the keystore was installed properly.
  my $self = shift;
  my %args = (@_);    # argument pair list

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $gsk6cmd = $options->{gsk6cmd};

  if(!defined $options->{gsk6cmd}){
    $gsk6cmd = $options->{gskcmd};   
  }

  # new MQ keystore base filename
  my $newkeystorebase = File::Spec->catfile($entry->{statedir}, "tmpkeystore-" . $entryname);
  my $newkeystoredb = $newkeystorebase . ".kdb";

  foreach my $ext (qw(.crl .rdb .kdb .sth)) {
    CertNanny::Util->wipe(FILE => $newkeystorebase.$ext, SECURE => 1) ;
  }

  if ($options->{keygenmode} eq "external") {
    CertNanny::Logging->info('MSG', "Creating MQ keystore (via PKCS#12)");

    # create prototype PKCS#12 file
    my $keyfile  = $self->{STATE}->{DATA}->{RENEWAL}->{REQUEST}->{KEYFILE};
    my $certfile = $args{CERTFILE};
    my $label    = $self->{CERT}->{LABEL};

    CertNanny::Logging->info('MSG', "Creating prototype PKCS#12 from certfile $certfile, keyfile $keyfile, label $label");

    #   # build array of ca certificate filenames
    #   my @cachain;
    #   foreach my $item (@{$self->{STATE}->{DATA}->{CERTCHAIN}}) {
    #       print Dumper $item;
    #       push(@cachain, $item);
    #   }

    # pkcs12file must be an absolute filename (see below, gsk6cmd bug)
    my $pkcs12file = $self->createPKCS12(FILENAME     => CertNanny::Util->getTmpFile(),
                                         FRIENDLYNAME => $label,
                                         EXPORTPIN    => $self->{PIN})->{FILENAME};

    #              CACHAIN => \@cachain);

    if (!defined $pkcs12file) {
      CertNanny::Logging->error('MSG', "Could not create prototype PKCS#12 from received certificate");
      return undef;
    }
    CertNanny::Logging->info('MSG', "Created PKCS#12 file $pkcs12file");

    my @cmd;
    @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-keydb', '-create', '-type', 'cms', '-db', CertNanny::Util->osq("$newkeystoredb"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-stash',);
        
    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC}) {
      CertNanny::Logging->error('MSG', "Keystore creation failed");
      return undef;
    }

    CertNanny::Logging->info('MSG', "New MQ Keystore $newkeystoredb created.");

    # remove all certificates from this keystore
    @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-list', '-db', CertNanny::Util->osq("$newkeystoredb"), '-pw', CertNanny::Util->osq("$self->{PIN}"),);
   
    my @calabels;

    my $match = $entry->{labelmatch} || "ibmwebspheremq.*";
    chomp(my @certs = @{CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{STDOUT}});
    
    if (!defined $options->{gsk6cmd}) {
      if (@certs) {
        foreach my $certlabel (@certs) {       
          if (($certlabel !~ m/Certificates found/) and ($certlabel !~ m/default, - /)) { 
          $certlabel =~ m/\s*(.*$)/;
          $certlabel = $1;
          CertNanny::Logging->debug('MSG', "found label $certlabel");
          push(@calabels, $certlabel);
          }
        }
      }
    } else {  
      if (@certs) {
        foreach (@certs) {
          s/\s*$//;
          next if (m{ \A Certificates\ in\ database}xms);
          next if (m{ \A No\ key}xms);
          next if (m{ \A \S }xms);
          next if (m{ $match }xms);
          s/^\s*//;
          push(@calabels, $_);
        }
      } else {
        CertNanny::Logging->error('MSG', "Could not retrieve certificate list in MQ keystore");
        return undef;
      }
    }

    # now delete all preloaded CAs
    foreach my $label (@calabels) {
      CertNanny::Logging->debug('MSG', "deleting label '$label' from MQ keystore");
      @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-delete', '-db', CertNanny::Util->osq("$newkeystoredb"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-label', CertNanny::Util->osq("$label"),);
    
      if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC}) {
        CertNanny::Logging->debug('MSG', "Could not delete label $label certificate from keystore");
        #return undef;
      }
    } ## end foreach (@calabels)

    # keystore is now empty
    # subordinate certificates from the CA Cert chain

    # all trusted Root CA certificates...
    my @trustedcerts = @{$self->{STATE}->{DATA}->{ROOTCACERTS}};

    # ... plus all certificates from the CA key chain minus its root cert
    push(@trustedcerts, @{$self->{STATE}->{DATA}->{CERTCHAIN}}[1 .. $#{$self->{STATE}->{DATA}->{CERTCHAIN}}]);

    foreach my $item (@trustedcerts) {
      my @RDN = split(/(?<!\\),\s*/, $item->{CERTINFO}->{SubjectName});
      my $CN = $RDN[0];
      $CN =~ s/^CN=//;

      CertNanny::Logging->info('MSG', "Adding certificate '$item->{CERTINFO}->{SubjectName}' from file $item->{CERTFILE}");

      # rewrite certificate into PEM format
      my $cacert = CertNanny::Util->convertCert(OUTFORMAT  => 'PEM',
                                                CERTFILE   => $item->{CERTFILE},
                                                CERTFORMAT => 'PEM',);

      if (!defined $cacert) {
        CertNanny::Logging->error('MSG', "installCert(): Could not convert certificate $item->{CERTFILE}");
        return undef;
      }

      my $cacertfile = CertNanny::Util->getTmpFile();
      if (!CertNanny::Util->writeFile(DSTFILE    => $cacertfile,
                                      SRCCONTENT => $cacert->{CERTDATA})) {
        CertNanny::Logging->error('MSG', "installCert(): Could not write temporary CA file");
        return undef;
      }

      @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-add', '-db', CertNanny::Util->osq("$newkeystoredb"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-file', CertNanny::Util->osq("$cacertfile"), '-format', 'ascii', '-label', CertNanny::Util->osq("$CN"),);       
   
      if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC}) {
        CertNanny::Util->wipe(FILE => $cacertfile, SECURE => 1);
        CertNanny::Logging->error('MSG', "Could not add certificate to keystore");
        return undef;
      }
      CertNanny::Util->wipe(FILE => $cacertfile, SECURE => 1);

    } ## end foreach my $item (@trustedcerts)

    # finally add the PKCS#12 file to the keystore

    # NOTE: gsk6cmd contains a bug that makes it impossible to
    # specify absolute path names as -target
    # pkcs12file is guaranteed to be an absolute pathname (see above),
    # so it is safe to chdir to the target directory temporarily
    my ($basename, $dirname) = fileparse($newkeystoredb);
    my $lastdir = getcwd();
    if (!chdir($dirname)) {
     CertNanny::Logging->error('MSG', "Could not import PKCS#12 file to keystore (chdir to $dirname failed)");
     return undef;
    }
    
    my @importcmd;  

    if (!defined $options->{gsk6cmd}) {
      CertNanny::Logging->debug('MSG', "no gsk6cmd use gskcmd import command ");
      @importcmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-import', '-db', CertNanny::Util->osq("$pkcs12file"),'-type' ,'pkcs12' ,'-pw', CertNanny::Util->osq("$self->{PIN}"), '-target', CertNanny::Util->osq("$newkeystoredb"), '-target_pw', CertNanny::Util->osq("$self->{PIN}"), '-target_type', 'cms');
    } else {
      CertNanny::Logging->debug('MSG', "no gskcmd use gsk6cmd import command ");
      @importcmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-import', '-target', CertNanny::Util->osq("$basename"), '-target_pw', CertNanny::Util->osq("$self->{PIN}"), '-file', CertNanny::Util->osq("$pkcs12file"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-type', 'pkcs12',);      
    }

    if (CertNanny::Util->runCommand(\@importcmd, HIDEPWD => 1)->{RC}) {
      CertNanny::Logging->error('MSG', "Could not import PKCS#12 file to gsk keystore");
      chdir($lastdir);
      return undef;
    }
    chdir($lastdir);

    CertNanny::Logging->info('MSG', "Keystore created");
  } else {
    if ($options->{keygenmode} eq "internal") {
      CertNanny::Logging->info('MSG', "Internal key generation not supported");
      return undef;
    } ## end if ($options->...)
  } ## end else

  # now replace the old keystore with the new one
  if (!-r $newkeystoredb) {
    CertNanny::Logging->error('MSG', "Could not access new prototype keystore file $newkeystoredb");
    return undef;
  }

  CertNanny::Logging->info('MSG', "Installing MQ keystore");
  my $oldlocation = $entry->{location};

  my @newkeystore = ();
  foreach my $ext (qw(.crl .rdb .kdb .sth)) {
    my $data = CertNanny::Util->readFile($newkeystorebase . $ext);
    if (!defined $data) {
      CertNanny::Logging->error('MSG', "Could not read new keystore file " . $newkeystorebase . $ext);
      return undef;
    }

    # schedule for installation
    push(@newkeystore, {DESCRIPTION => "End entity $ext file",
                        DSTFILE     => $oldlocation . $ext,
                        SRCCONTENT  => $data});
  } ## end foreach my $ext (qw(.crl .rdb .kdb .sth))

  ######################################################################
  # try to write the new keystore

  if (!$self->k_saveInstallFile(@newkeystore)) {
    CertNanny::Logging->error('MSG', "Could not install new keystore");
    return undef;
  }

  return 1;
} ## end sub installCert


sub getKey {
  ###########################################################################
  #
  # get private key for main certificate from keystore
  # 
  # Input: caller must provide a hash ref containing the unencrypted private 
  #        key in OpenSSL format
  # 
  # Output: caller gets a hash ref (as expected by k_convertKey()):
  #           KEYDATA   => string containg the private key OR
  #           KEYFORMAT => 'PEM' or 'DER'
  #           KEYTYPE   => format (e. g. 'PKCS8' or 'OpenSSL'
  #           KEYPASS   => key pass phrase (only if protected by pass phrase)
  #         or undef on error
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get private key for main certificate from keystore");
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $keydata;

  if ($options->{gsk6cmd}) {
    # initialize Java and GSKit environment
    if (!$self->_getIBMJavaEnvironment()) {
      CertNanny::Logging->error('MSG', "Could not determine IBM Java environment");
      return undef;
    }

    my $keystore = $entry->{location} . ".kdb";
    if (!-r "$keystore") {
      $keystore = $entry->{location};
    }

    my $label = $self->_getCertLabel();
    if (!defined $label) {
      CertNanny::Logging->error('MSG', "Could not get certificate label");
      return undef;
    }

    my $p8file = CertNanny::Util->getTmpFile();
    chmod 0600, $p8file;

    my $extractkey_jar = File::Spec->catfile($config->get("path.libjava", "FILE"), 'ExtractKey.jar');
    if (!-r $extractkey_jar) {
      CertNanny::Logging->error('MSG', "getKey(): could not locate ExtractKey.jar file");
      return undef;
    }

    my $separator = $OSNAME =~ m{ MSWin }xms ? ';' : ':';

    my $classpath = $options->{GSKIT_CLASSPATH} . $separator . $extractkey_jar;

    my @gsklibdir;
    if (defined $options->{gsklibdir}) {
      @gsklibdir = ('-Djava.library.path=' . CertNanny::Util->osq("$options->{gsklibdir}"));
      $ENV{PATH} .= $separator . $self->{OPTIONS}->{gsklibdir};
    }
  
    my @cmd = (CertNanny::Util->osq("$options->{JAVA}"), 
               '-classpath', CertNanny::Util->osq("$classpath"), 
               'de.cynops.java.crypto.keystore.ExtractKey', @gsklibdir, 
               '-keystore', CertNanny::Util->osq("$keystore"), 
               '-storepass', CertNanny::Util->osq("$self->{PIN}"), 
               '-keypass', CertNanny::Util->osq("$self->{PIN}"), 
               '-key', CertNanny::Util->osq("$label"), 
               '-keyfile', CertNanny::Util->osq("$p8file"), 
               '-provider', 'IBMJCE', 
               '-type', 'CMS');

    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC}) {
      CertNanny::Logging->error('MSG', "getKey(): could not extract private key");
      CertNanny::Util->wipe(FILE => $p8file, SECURE => 1);
      return undef;
    }
    $keydata = CertNanny::Util->readFile($p8file);
    CertNanny::Util->wipe(FILE => $p8file, SECURE => 1);
  } else {
    ##default to new get key for gsk7cmd and up 
  
    my $keystore = $entry->{location} . ".kdb";
    if (!-r "$keystore") {
      $keystore = $entry->{location};
    }

    my $label = $self->_getCertLabel();
    if (!defined $label) {
      CertNanny::Logging->error('MSG', "Could not get certificate label");
      return undef;
    }
  
    my $tmpdir = $config->get('path.tmpdir', 'FILE');

    #the export p12 file has to have the extension .p12 , due to the fact that gsk8capicmd.exe under windows ignores the target_type argument.
    my $exportp12 = File::Spec->catfile($tmpdir, $entryname."export.p12");
    
    chmod 0600, $exportp12;
  
    my @cmd;
    @cmd = (CertNanny::Util->osq("$options->{gskcmd}"), '-cert', '-export', '-db', CertNanny::Util->osq("$keystore"), '-pw', CertNanny::Util->osq("$self->{PIN}"), '-label', CertNanny::Util->osq("$label"), '-type cms', '-target', CertNanny::Util->osq("$exportp12"), '-target_pw' , CertNanny::Util->osq("$self->{PIN}"), '-target_type', 'pkcs12');   

    if (CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{RC}) {
      CertNanny::Logging->error('MSG', "getKey(): could not extract private key");
      CertNanny::Util->wipe(FILE => $exportp12, SECURE => 1);
      return undef;
    }
  
    my $openssl = $config->get('cmd.openssl', 'CMD');
    if (!defined $openssl) {
      CertNanny::Logging->error('MSG', "No openssl shell specified");
      return undef;
    };
  
    my @opensslcmd;
    $ENV{PASSIN} = $self->{PIN};
    my $exportkey = CertNanny::Util->getTmpFile();
    chmod 0600, $exportkey;
  
    @opensslcmd = (CertNanny::Util->osq("$openssl"), 'pkcs12', '-in', CertNanny::Util->osq("$exportp12"), '-passin', CertNanny::Util->osq("env:PASSIN"),  '-out', CertNanny::Util->osq("$exportkey"), '-nodes' , '-nocerts' );

    if (CertNanny::Util->runCommand(\@opensslcmd, HIDEPWD => 1)->{RC}) {
      CertNanny::Logging->error('MSG', "getKey(): could not extract private key");
      CertNanny::Util->wipe(FILE => $exportkey, SECURE => 1);
      return undef;
    }
  
    delete $ENV{PASSIN};
    $keydata = CertNanny::Util->readFile($exportkey);
    CertNanny::Util->wipe(FILE => $exportkey, SECURE => 1);
    CertNanny::Util->wipe(FILE => $exportp12, SECURE => 1);
  
    if ((!defined $keydata) or ($keydata eq "")) {
      CertNanny::Logging->error('MSG', "getKey(): Could not convert private key via pkcs12 export");
      return undef;
    }
  
    CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get private key for main certificate from keystore via pkcs12 export");
  
    return {KEYDATA   => $keydata,
            KEYTYPE   => 'OpenSSL',
            KEYFORMAT => 'PEM'};  # no keypass, unencrypted
  }


  if ((!defined $keydata) or ($keydata eq "")) {
    CertNanny::Logging->error('MSG', "getKey(): Could not convert private key");
    return undef;
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get private key for main certificate from keystore");
  return {KEYDATA   => $keydata,
          KEYTYPE   => 'PKCS8',
          KEYFORMAT => 'DER'};  # no keypass, unencrypted
} ## end sub getKey


sub createRequest {
  ###########################################################################
  #
  # generate a certificate request
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref (as expected by k_convertKey()):
  #           KEYFILE     => file containing the key data (will
  #                          only be generated if not initial 
  #                          enrollment)
  #           REQUESTFILE => file containing the CSR
  # 
  # This method should generate a new private key and certificate request.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key and PKCS#10 request 'outside' of
  # your keystore and import this information later.
  # In this case use the following code:
  # sub createRequest {
  #   my $self = shift;
  #   return $self->SUPER::createRequest(@_) if $self->can("SUPER::createRequest");
  # }
  #
  # If you are able to directly operate on your keystore to generate keys
  # and requests, you might choose to do all this yourself here:
  my $self = shift;

  if ($self->{OPTIONS}->{keygenmode} eq "external") {
    CertNanny::Logging->info('MSG', "External request generation (using OpenSSL)");
    return $self->SUPER::createRequest() if $self->can("SUPER::createRequest");
  }

  return undef;
} ## end sub createRequest


sub generateKey {
  ###########################################################################
  #
  # generate a new keypair
  # 
  # Input: -
  # 
  # Output: caller gets a hash ref:
  #           KEYFILE     => mandatory: file containing the key data (will
  #                          only be generated if not initial 
  #                          enrollment)
  #           REQUESTFILE => optional: file containing the CSR
  # 
  # This method should generate a new private key.
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub generateKey {
  #   my $self = shift;
  #   return $self->SUPER::generateKey(@_) if $self->can("SUPER::generateKey");
  # }
  #
  # If you are able to directly operate on your keystore to generate keys,
  # you might choose to do all this yourself here:
  my $self = shift;
  return $self->SUPER::generateKey(@_) if $self->can("SUPER::generateKey");
}


sub createPKCS12 {
  ###########################################################################
  #
  # create pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILENAME     => mandatory: pkcs12 file to create
  #           FRIENDLYNAME => optional: cert label to be used in pkcs#12 structure
  #           EXPORTPIN    => mandatory: PIN to be set for pkcs#12 structure
  #           CERTFILE     => mandatory: certificate to include in the pkcs#12 file, instance certificate
  #                           if not specified
  #           CERTFORMAT   => mandatory: PEM|DER, instance cert format if not specified
  #           KEYFILE      => mandatory: keyfile, instance key if not specified
  #           PIN          => optional: keyfile pin
  #           CACHAIN      => optional: arrayref containing the certificate info structure of
  #                           CA certificate files to be included in the PKCS#12
  #                           Required keys for entries: CERTFILE, CERTFORMAT, CERTINFO
  # 
  # Output: caller gets undef if the operation failed or a hash ref:
  #           FILENAME    => created pkcs12 file
  # 
  # This method should generate a new pkcs12 file 
  # with all the items that are given
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub createPKCS12 {
  #   my $self = shift;
  #   return $self->SUPER::createPKCS12(@_) if $self->can("SUPER::createPKCS12");
  # }
  my $self = shift;
  return $self->SUPER::createPKCS12(@_) if $self->can("SUPER::createPKCS12");
}


sub importP12 {
  ###########################################################################
  #
  # import pkcs12 file
  # 
  # Input: caller must provide a hash ref:
  #           FILE         => mandatory: 'path/file.p12'
  #           PIN          => mandatory: 'file pin'
  #           ENTRYNAME    => optional:  'capi'
  #           CONF         => optional:  Certnanny Configurationhashref
  # 
  # Output: caller gets a hash ref:
  #           FILENAME    => created pkcs12 file to create
  # 
  # examples:
  # $self->importP12({FILE => 'foo.p12', PIN => 'secretpin'});
  # 
  # Import a p12 with private key and certificate into target keystore
  # also adding the certificate chain if required / included.
  # Is used with inital enrollemnt
  # IMPORTANT NOTICE: THIS METHOD MUST BE CALLED IN STATIC CONTEXT, NEVER AS A CLASS METHOD
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub importP12 {
  #   my $self = shift;
  #   return $self->SUPER::importP12(@_) if $self->can("SUPER::importP12");
  # }
  my $self = shift;
  return $self->SUPER::importP12(@_) if $self->can("SUPER::importP12");
} ## end sub importP12


sub getInstalledCAs {
  ###########################################################################
  #
  # get all installed root certificates
  #
  # Input:  caller must provide a hash ref:
  #           TARGET      => optional : where should the procedure search for installed
  #                          root certificates (DIRECTORY|FILE|CHAINFILE|LOCATION)
  #                          default: all
  # 
  # Output: caller gets a hash ref:
  #           Hashkey is the SHA1 of the certificate
  #           Hashcontent ist the parsed certificate
  #             - CERTDATA      mandatory: certificate data
  #             - CERTINFO      mandatory: parsed certificat info
  #             - CERTFILE       optional (not present): certificate file
  #             - CERTALIAS      optional (present): certificate alias name
  #             - CERTCREATEDATE optional (present): certificate creation date
  #             - CERTTYPE       optional (present): certificate type
  #
  # Reads the config Parameters
  #   keystore.<name>.TrustedRootCA.GENERATED.Directory
  #   keystore.<name>.TrustedRootCA.GENERATED.File
  #   keystore.<name>.TrustedRootCA.GENERATED.ChainFile
  # and look for Trusted Root Certificates. All found certificates are
  # returned in a Hash
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub getInstalledCAs {
  #   my $self = shift;
  #   return $self->SUPER::getInstalledCAs(@_) if $self->can("SUPER::getInstalledCAs");
  # }
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get all installed root certificates gsk");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = 0;
  my $certFound = {};
    my $gsk6cmd = $self->{OPTIONS}->{gsk6cmd};

  if(!defined $self->{OPTIONS}->{gsk6cmd}){
     $gsk6cmd = $self->{OPTIONS}->{gskcmd};   
  }
  my %ignoreCertHashes; 
  my $chain = $self->k_buildCertificateChain($self->getCert()); 
  
  
  # delete root
  shift(@{$chain});
      
  while (my $cert = shift(@{$chain})) {
    my $tmpFile = CertNanny::Util->getTmpFile();
    CertNanny::Util->writeFile(DSTFILE => $tmpFile,
                                          SRCFILE => $cert->{CERTFILE}, 
                                          APPEND  => 0 );
    my  $certSha1 = CertNanny::Util->getCertSHA1(CERTFILE => $tmpFile);    
    $ignoreCertHashes{$certSha1->{'CERTSHA1'}} = $certSha1->{'CERTSHA1'} ;                                     
  }    
     
                       
  my $cert = $self->getCert();
  my $tmpCertFile = CertNanny::Util->getTmpFile();
  CertNanny::Util->writeFile(DSTFILE => $tmpCertFile,
                             SRCCONTENT => $cert->{'RAW'}->{'PEM'}, 
                             APPEND  => 0 );
  CertNanny::Logging->debug('MSG', Dumper($cert)); 
  my  $certSha1 = CertNanny::Util->getCertSHA1(CERTFILE => $tmpCertFile);  
  
  $ignoreCertHashes{$certSha1->{'CERTSHA1'}} = $certSha1->{'CERTSHA1'} ;    

  if (!defined($args{TARGET}) or ($args{TARGET} eq 'LOCATION')) {
    if (defined(my $locName = CertNanny::Util->mangle($entry->{location}, 'FILE'))) {
      $locName .= ".kdb";
      if (!-r "$locName") {
        $locName = CertNanny::Util->mangle($entry->{location}, 'FILE');
      }

      my ($certRef, @certList, $certData, $certSha1, $certAlias, $certCreateDate, $certType, $certFingerprint);
      
      my @cmd ;
      # get label name for user certificate
      @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-list', '-db', CertNanny::Util->osq("$locName"), '-pw', CertNanny::Util->osq("$self->{PIN}"));
      
      @certList = @{CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{STDOUT}};
      foreach my $certlabel (@certList) {
        #if ($_ =~ m/^([^,]*), ([0-3][0-9]\.[0-1][0-9]\.20[0-9][0-9]), (PrivateKeyEntry|trustedCertEntry),.*$/) { # gets Privat Key as well
        # if ($_ =~ m/^([^,]*), ([0-3][0-9]\.[0-1][0-9]\.20[0-9][0-9]), (trustedCertEntry),.*$/) {
        #  ($certAlias, $certCreateDate, $certType) = ($1, $2, $3);
        #}
        CertNanny::Logging->debug('MSG', "analyzing $gsk6cmd output line <$certlabel>"); 
        if( ! ( $certlabel =~ m/Certificates found/ ) and ! ( $certlabel =~ m/default, - / )) {
         
          $certlabel =~ m/\W*(.*$)/;
          $certlabel = $1;
          CertNanny::Logging->debug('MSG', "found certLabel <$certlabel>"); 
          my @certcmd;
          my $certexport= CertNanny::Util->getTmpFile();  
          @certcmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-extract', '-db', CertNanny::Util->osq("$locName"), '-pw', CertNanny::Util->osq("$self->{PIN}") , '-label' ,CertNanny::Util->osq("$certlabel") ,'-target' ,CertNanny::Util->osq("$certexport"));     
     
          $rc = CertNanny::Util->runCommand(\@certcmd, HIDEPWD => 1)->{RC};
            
              
          my $certInfo  = CertNanny::Util->getCertInfoHash(CERTFILE => $certexport , CERTFORMAT => 'PEM');   
          my $ignore = 0;                
          if (defined($certInfo)) {    
            # if (my $certTyp = $self->k_getCertType(CERTINFO => $certInfo)) {     ##skip type definiton for MQ keystores they often contain Verisign certs that are missing basic constrains 
            my $certTyp = $self->k_getCertType(CERTINFO => $certInfo);
            $certSha1 = CertNanny::Util->getCertSHA1(CERTFILE => $certexport);

            if($ignoreCertHashes{$certSha1->{'CERTSHA1'}}){
              $ignore =1 ;
            }            

            if ($ignore == 0) {
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTALIAS}       = $certlabel;
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTCREATEDATE}  = $certInfo->{'NotBefore'};
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTTYPE}        = $certType;
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFINGERPRINT} = $certInfo->{'CertificateFingerprint'};
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTDATA}        = $certInfo->{'Certificate'};
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTFORMAT}      = 'PEM';
              $self->{$certTyp}->{$certSha1->{CERTSHA1}}->{CERTINFO}        = $certInfo;
                  
              $certFound->{$certSha1->{CERTSHA1}} = $self->{$certTyp}->{$certSha1->{CERTSHA1}};
            } else {
              CertNanny::Logging->debug('MSG', "skiping certLabel <$certlabel>"); 
            }
          }            
          CertNanny::Util->wipe(FILE => $certexport, SECURE => 1);        
        }
      }
    }
  }
  
  
  
  
  #CertNanny::Logging->debug('MSG', "__installed rootCAs \n". Dumper($certFound) );
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get all installed root certificates gsk");
  return $certFound;
} ## end sub getInstalledCAs


sub installRoots {
  ###########################################################################
  #
  # install all available root certificates
  #
  # Input: caller must provide a hash ref:
  #           ROOTCERTS   => Hash containing array of all rootcertificates to 
  #                          be installed (as returned by getInstalledCAs)
  #                          Hashkey is tha SHA1 of the certificate
  #                          Hashcontent ist the parsed certificate
  # 
  # Output: 1 : failure  0 : success 
  #
  # this function gets a hash of parsed root certificates
  # install all roots into the keystore depending on keystore type
  # (write files, rebuild kestore, etc.)
  # execute install-root-hook for all certificates that will be new installed
  #
  # You may want to inherit this class from CertNanny::Keystore::OpenSSL if
  # you wish to generate the private key 'outside' of your keystore and 
  # import this information later.
  # In this case use the following code:
  # sub installRoots {
  #   my $self = shift;
  #   return $self->SUPER::installRoots(@_) if $self->can("SUPER::installRoots");
  # }
  
  # INFO Sascha:
  #   - ebenfalls keine Unterscheidung zwischen den Typen der Zertifikate. 
  #     Deswegen gilt das gleiche fuer Root Certs wie schon bei jks.
  #   - fuer die Cert Installation:
  #       gsk7capicmd_64 -cert -add -file CA/uat/testca10.pem -label TestCA -db name_your_db.kdb -format ascii
  #   - wenn die Kette nicht vollstaendig ist, dann verweigert gsk die Aufnahme 
  #     des Zertifikats in den Store.

  # Beispiel:
  # #!/bin/bash
  # 
  # gsk7cmd_64 -cert -import -db certnanny.reworktest.example.com_certnannyOpenSSL.p12new -pw yPdNQfoR55RTajom7VU44g -target key.kdb -target_pw 1234567890 -label cert1
  #
  # #create gsk7 keystore
  # gsk7capicmd_64 -keydb -create -db name_your_db -pw password1
  # 
  # #view available certificates
  # gsk7capicmd_64 -cert -list -db name_your_db.kdb
  # 
  # #install certificate
  # #Parameter:
  # #-file: <certificate you want to install>
  # #-label: <alias for the certificate to use in your database>
  # #-db: <name of your database>.kdb
  # #-format: ascii when using .pem files, binary when using .der files
  # #NOTE: when trying to install a certificate chain, start with the Root of the chain!
  # gsk7capicmd_64 -cert -add -file CA/uat/testca10.pem -label TestCA -db name_your_db.kdb -format ascii
  # 
  # #known errors:
  # #Error 146: GSKKM_ERR_INVALID_CERT_CHAIN
  # #Part of the certificate chain is missing

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Install all available root certificates");
  my $self = shift;
  my %args = (@_);

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};
  
  my $rc = (defined($args{TARGET}) and ($args{TARGET} ne 'LOCATION'));
  CertNanny::Logging->debug('MSG', "Target: ". $args{TARGET});
  
  # run only if no TARGET is defined or TARGET is LOCATION
  if (!$rc) {
    my $gsk6cmd = $self->{OPTIONS}->{gsk6cmd};

    $gsk6cmd = $self->{OPTIONS}->{gskcmd} if (!defined $self->{OPTIONS}->{gsk6cmd});
  
    # build a new temp keystore; Start with a working copy of the existing one
    my $origin = File::Spec->canonpath($entry->{location}) . '.kdb';
    if (!-r "$origin") {
      $origin = File::Spec->canonpath($entry->{location});
    }
    my $dest = $origin . ".work";
    CertNanny::Logging->debug('MSG', "Creating Working copy of <$origin> as <$dest>");

    if (!copy($origin, $dest)) {
      $rc = !CertNanny::Logging->error('MSG', "Could not create working copy of <$origin> as <$dest>");
    }

    if (!$rc) {
      my $installedRootCAs = $args{INSTALLED};
      my $availableRootCAs = $args{AVAILABLE};

      my @cmd;
      my $certData;

      if (!defined($availableRootCAs)) {
        my $rootCertList = $self->k_getAvailableRootCerts();
        if (!defined($rootCertList)) {
          $rc = !CertNanny::Logging->error('MSG', "No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.Directory", 'FILE'));
        }
  
        if (!$rc) {
          my $availableRootCAs = {};
          # Foreach available root cert get the SHA1
          foreach my $certRef (@{$rootCertList}) {
            my $certSHA1 = CertNanny::Util->getCertSHA1(%{$certRef})->{CERTSHA1};
            if (exists($availableRootCAs->{$certSHA1})) {
              if (exists($availableRootCAs->{$certSHA1}->{CERTFILE}) and ($certRef->{CERTFILE})) {
                CertNanny::Logging->debug('MSG', "Identical root certificate in <" . $availableRootCAs->{$certSHA1}->{CERTFILE} . "> and <" . $certRef->{CERTFILE} . ">");
              } else {
                CertNanny::Logging->debug('MSG', "Identical root certificate <" . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName} . "> found.");
              }
            } else {
              $availableRootCAs->{$certSHA1} = $certRef;
            }
          }
        }
      }

      if (!defined($availableRootCAs)) {
        $rc = !CertNanny::Logging->error('MSG', "No root certificates found in " . $config-get("keystore.$entryname.TrustedRootCA.AUTHORITATIVE.dir", 'FILE'));
      } else {
        #  my $locName = $self->_generateKeystore();
        $rc = 1 if (!$dest);
        if (!$rc) {
          # delete every root CA, that does not exist in $availableRootCAs from keystore
          foreach my $certSHA1 (keys %{$installedRootCAs}) {
            if (!exists($availableRootCAs->{$certSHA1}) && ($self->k_getCertType($installedRootCAs->{$certSHA1}) eq 'installedRootCAs')) {
              CertNanny::Logging->debug('MSG', "Deleting root cert " . $installedRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
              my @certcmd;
              @certcmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-delete', '-db', CertNanny::Util->osq("$dest"), '-pw', CertNanny::Util->osq("$self->{PIN}") , '-label' ,CertNanny::Util->osq("$installedRootCAs->{$certSHA1}->{'CERTALIAS'}") );

              if (CertNanny::Util->runCommand(\@certcmd, HIDEPWD => 1)->{RC}) {
                CertNanny::Logging->error('MSG', "Error deleting root cert " . $installedRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
              }
            }
          }

          # copy every root CA, that does not exist in $installedRootCAs to keystore
          foreach my $certSHA1 (keys  %{$availableRootCAs}) {
            if (!exists($installedRootCAs->{$certSHA1})) {
              CertNanny::Logging->debug('MSG', "Importing root cert " . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
              my $tmpFile = CertNanny::Util->getTmpFile();
              CertNanny::Util->writeFile(DSTFILE => $tmpFile,
                                         SRCFILE => $availableRootCAs->{$certSHA1}->{'CERTFILE'});

              my $alias = 'newRoot';
              if ($availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName} =~ /CN=([^,]+).*/) {
                ($alias = $1) =~ s/\s/_/g;
              }

              my @certcmd;
              @certcmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-add', '-db', CertNanny::Util->osq("$dest"), '-pw', CertNanny::Util->osq("$self->{PIN}") , '-label' ,CertNanny::Util->osq("$alias") , '-file', $tmpFile ,'-format', 'ascii'  );

              if (CertNanny::Util->runCommand(\@certcmd, HIDEPWD => 1)->{RC}) {
                CertNanny::Logging->error('MSG', "Error importing root cert " . $availableRootCAs->{$certSHA1}->{CERTINFO}->{SubjectName});
              } else {
                # collect Postinstallhook information
                $self->{hook}->{Type}   .= 'FILE' . ','                                                               if (defined($self->{hook}->{Type})   && ($self->{hook}->{Type}   !~ m/FILE/s));
                $self->{hook}->{File}   .= $availableRootCAs->{$certSHA1}->{CERTFILE} . ','                           if (defined($self->{hook}->{File})   && ($self->{hook}->{File}   !~ m/$availableRootCAs->{$certSHA1}->{CERTFILE}/s));
                $self->{hook}->{FP}     .= $availableRootCAs->{$certSHA1}->{CERTINFO}->{CertificateFingerprint} . ',' if (defined($self->{hook}->{FP})     && ($self->{hook}->{FP}     !~ m/$availableRootCAs->{$certSHA1}->{CERTINFO}->{CertificateFingerprint}/s));
                $self->{hook}->{Target} .= $entry->{location} . ','                                                   if (defined($self->{hook}->{Target}) && ($self->{hook}->{Target} !~ m/$entry->{location}/s));
              }
            }
          }
        }
      
        # copy the temp keystore to $location an delete temp keystore
        if (!File::Copy::copy($dest, $origin)) {
          $rc = !CertNanny::Logging->error('MSG', "Could not copy new store <$dest> to current store <$origin>");
        } else {
          CertNanny::Util->wipe(FILE => $dest, SECURE => 1);
        }
      }
    }
  }
  
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " Install all available root certificates gsk");
  return $rc;
} ## end sub installRoots


sub _buildGskCmd {
  # build a GSK command (as an array) containing all common options, the
  # location (if provided as an argument) and further arguments (if provided)
  # the common options are:
  my $self     = shift;
  my $location = shift;

  my $options = $self->{OPTIONS};
  my $entry   = $options->{ENTRY};
  
  my $gsk6cmd = $options->{gsk6cmd};

  if(!defined $options->{gsk6cmd}){
    $gsk6cmd = $options->{gskcmd};   
  }
  

  my @cmd = (CertNanny::Util->osq("$gsk6cmd"));
  # Commands-keydb - create | -cert -add |  -cert -import | -cert -list
  push(@cmd, -db        => CertNanny::Util->osq("$entry->{db}"))        if ($entry->{db});
  push(@cmd, -pw        => CertNanny::Util->osq("$entry->{pw}"))        if ($entry->{pw});
  push(@cmd, -target    => CertNanny::Util->osq("$entry->{target}"))    if ($entry->{target});
  push(@cmd, -target_pw => CertNanny::Util->osq("$entry->{target_pw}")) if ($entry->{target_pw});
  push(@cmd, -label     => CertNanny::Util->osq("$entry->{label}"))     if ($entry->{label});
  push(@cmd, -file      => CertNanny::Util->osq("$entry->{file}"))      if ($entry->{file});
  push(@cmd, -format    => CertNanny::Util->osq("$entry->{format}"))    if ($entry->{format});
  push(@cmd, @_);
  @cmd;
}


sub _getIBMJavaEnvironment {
  # determine location of the JAVA binary and the necessary CLASSPATH
  # definition for GSKit
  # sets global option JAVA to the location of the Java executable
  # sets global option GSKIT_CLASSPATH to classpath required for accessing
  #   the IBM GSKIT Keystore Implementation
  my $self = shift;

  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  if (defined $options->{JAVA}            && $options->{JAVA}            ne '' && 
      defined $options->{GSKIT_CLASSPATH} && $options->{GSKIT_CLASSPATH} ne '') {
    return 1;
  }

  if ($OSNAME =~ m{ MSWin }xms) {
    # determine classpath for IBM classes
    my $gsk6cmd = $options->{gsk6cmd};

    if(!defined $options->{gsk6cmd}){
      $gsk6cmd = $options->{gskcmd};   
    }

    my $cmd = CertNanny::Util->osq("$gsk6cmd") . " -version";

    CertNanny::Logging->debug('MSG', "Execute: <$cmd>");
    open my $fh, $cmd . '|';
    if (!$fh) {
      CertNanny::Logging->error('MSG', "getIBMJavaEnvironment(): could not run gskit command line executable");
      return undef;
    }

    my $java;
    my $classpath;
  LINE:
    while (my $line = <$fh>) {
      if ($line =~ m{ \A \s* "(.*)" \s* -classpath \s* "(.*?)" }xms) {
        $options->{JAVA}            = $1;
        $options->{GSKIT_CLASSPATH} = $2;
        close $fh;
        return 1;
      }
    }
    close $fh;
    CertNanny::Logging->error('MSG', "getIBMJavaEnvironment(): could not determine GSK classpath");
    return undef;
  } else {
    # assume we have a Unix-like system
    my $javacmd = File::Spec->catfile($ENV{JAVA_HOME}, 'bin', 'java');
    if (!-x $javacmd) {
      CertNanny::Logging->error('MSG', "getIBMJavaEnvironment(): could not determine Java executable (JAVA_HOME not set?)");
      return undef;
    }
    $options->{JAVA} = $javacmd;

    # determine classpath for IBM classes
    my $gsk6cmd = $options->{gsk6cmd};

    if(!defined $options->{gsk6cmd}){
      $gsk6cmd = $options->{gskcmd};   
    }

    my $cmd = ". $gsk6cmd >/dev/null 2>&1 ; echo \$JAVA_FLAGS";
    CertNanny::Logging->debug('MSG', "Execute: <$cmd>");
    my $classpath = `$cmd`;
    chomp $classpath;

    if (($? != 0) or (!defined $classpath) or ($classpath eq "")) {
      CertNanny::Logging->error('MSG', "getIBMJavaEnvironment(): could not determine GSK classpath");
      return undef;
    }

    # remove any options left over
    $classpath =~ s/-?-\w+//g;
    $classpath =~ s/^\s+|\s+$//g ;

    CertNanny::Logging->debug('MSG', "gsk6cmd classpath: $classpath");

    $options->{GSKIT_CLASSPATH} = $classpath;

    return 1;
  } ## end else [ if ($OSNAME =~ m{ MSWin }xms)]

  return undef;
} ## end sub getIBMJavaEnvironment


sub _unStash {
# descramble password in MQ stash file
  my $self      = shift;
  my $stashfile = shift;

  my $content = CertNanny::Util->readFile($stashfile);
  if (!defined $content) {
    CertNanny::Logging->error('MSG', "_unStash(): Could not open input file $stashfile");
    return undef;
  }

  # =8->
  my $result = pack("C*", map {$_ ^ 0xf5} unpack("C*", $content));
  return substr($result, 0, index($result, chr(0)));
} ## end sub _unStash


sub _getCertLabel {
# get label of end entity certificate
  my $self = shift;

  if (exists $self->{CERTLABEL}) {
    return $self->{CERTLABEL};
  }

  my $filename = $self->{OPTIONS}->{ENTRY}->{location} . '.kdb';
  if (!-r "$filename") {
    $filename = $self->{OPTIONS}->{ENTRY}->{location};
  }

  return unless (-r "$filename");

  my $gsk6cmd = $self->{OPTIONS}->{gsk6cmd};

  if(!defined $self->{OPTIONS}->{gsk6cmd}){
     $gsk6cmd = $self->{OPTIONS}->{gskcmd};   
  }

  # get label name for user certificate
  my @cmd;
  @cmd = (CertNanny::Util->osq("$gsk6cmd"), '-cert', '-list', 'personal', '-db', CertNanny::Util->osq("$filename"), '-pw', CertNanny::Util->osq("$self->{PIN}"));

  my  @certList = @{CertNanny::Util->runCommand(\@cmd, HIDEPWD => 1)->{STDOUT}};
  my $label;
  my $match = $self->{OPTIONS}->{ENTRY}->{labelmatch} || "ibmwebspheremq.*";
  
  foreach my $entry (@certList) {
   chomp $entry;
   # some gskit versions prefix the label with a dash and whitespace
   $entry =~ s{ \A [\-!*]+ \s* }{}xms;
   if ($entry =~ m/$match/) { 
    $label = $entry;
    CertNanny::Logging->debug('MSG', "found label '$label'");
    }
  }
  chomp($label);

  if (!defined $label) {
    CertNanny::Logging->error('MSG', "getCert(): could not get label");
    return undef;
  }
 $label =~ s/^\s+|\s+$//g ;
  # cache information
  $self->{CERTLABEL} = $label;

  return $label;
} ## end sub _getCertLabel


sub getCertLocation {
  ###########################################################################
  #
  # get the key specific locations for certificates
  # 
  # Input: caller must provide a hash ref containing 
  #           TYPE      => TrustedRootCA or CAChain
  #                        Default: TrustedRootCA
  # 
  # Output: caller gets a hash ref:
  #           <locationname in lowercase> => <Location>
  #         or undef on error
  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get the key specific locations for certificates");
  my $self = shift;
  my %args = (TYPE => 'TrustedRootCA',
              @_);
  
  my $options   = $self->{OPTIONS};
  my $entry     = $options->{ENTRY};
  my $entryname = $options->{ENTRYNAME};
  my $config    = $options->{CONFIG};

  my $rc = undef;

  if ($args{TYPE} eq 'TrustedRootCA') {
    foreach ('Directory', 'File', 'ChainFile') {
      if (my $location = CertNanny::Util->mangle($entry->{TrustedRootCA}->{GENERATED}->{$_}, 'FILE')) {
        $rc->{lc($_)} = $location;
      }
    }
    if (my $location = CertNanny::Util->mangle($entry->{location}, 'FILE')) {
      $rc->{location} = $location;
    }
  }
  if ($args{CAChain}) {
    foreach ('Directory', 'File') {
      if (my $location = CertNanny::Util->mangle($entry->{CAChain}->{GENERATED}->{$_}, 'FILE')) {
        $rc->{lc($_)} = $location;
      }
    }
  }

  CertNanny::Logging->debug('MSG', (eval 'ref(\$self)' ? "End " : "Start ") . (caller(0))[3] . " get the key specific locations for certificates");
  return $rc
} ## end sub getKey


1;

{ config, options, lib, pkgs, utils, ... }:

with lib;
with utils;

let

  cfg = config.networking;

in

{

  ###### interface

  options = {

    networking.hostName = mkOption {
      default = config.system.nixos.distroId;
      defaultText = literalExpression "config.system.nixos.distroId";
      # Only allow hostnames without the domain name part (i.e. no FQDNs, see
      # e.g. "man 5 hostname") and require valid DNS labels (recommended
      # syntax). Note: We also allow underscores for compatibility/legacy
      # reasons (as undocumented feature):
      type = types.strMatching
        "^$|^[[:alnum:]]([[:alnum:]_-]{0,61}[[:alnum:]])?$";
      description = ''
        The name of the machine. Leave it empty if you want to obtain it from a
        DHCP server (if using DHCP). The hostname must be a valid DNS label (see
        RFC 1035 section 2.3.1: "Preferred name syntax", RFC 1123 section 2.1:
        "Host Names and Numbers") and as such must not contain the domain part.
        This means that the hostname must start with a letter or digit,
        end with a letter or digit, and have as interior characters only
        letters, digits, and hyphen. The maximum length is 63 characters.
        Additionally it is recommended to only use lower-case characters.
        If (e.g. for legacy reasons) a FQDN is required as the Linux kernel
        network node hostname (uname --nodename) the option
        boot.kernel.sysctl."kernel.hostname" can be used as a workaround (but
        the 64 character limit still applies).

        WARNING: Do not use underscores (_) or you may run into unexpected issues.
      '';
      # warning until the issues in https://github.com/NixOS/nixpkgs/pull/138978
      # are resolved
    };

    networking.enableIPv6 = mkOption {
      default = true;
    };

    networking.fqdn = mkOption {
      readOnly = true;
      type = types.str;
      default =
        if (cfg.hostName != "" && cfg.domain != null)
        then "${cfg.hostName}.${cfg.domain}"
        else
          throw ''
            The FQDN is required but cannot be determined. Please make sure that
            both networking.hostName and networking.domain are set properly.
          '';
      defaultText = literalExpression ''"''${networking.hostName}.''${networking.domain}"'';
      description = ''
        The fully qualified domain name (FQDN) of this host. It is the result
        of combining `networking.hostName` and `networking.domain.` Using this
        option will result in an evaluation error if the hostname is empty or
        no domain is specified.

        Modules that accept a mere `networking.hostName` but prefer a fully qualified
        domain name may use `networking.fqdnOrHostName` instead.
      '';
    };

    networking.fqdnOrHostName = mkOption {
      readOnly = true;
      type = types.str;
      default = if cfg.domain == null then cfg.hostName else cfg.fqdn;
      defaultText = literalExpression ''
        if cfg.domain == null then cfg.hostName else cfg.fqdn
      '';
      description = ''
        Either the fully qualified domain name (FQDN), or just the host name if
        it does not exists.

        This is a convenience option for modules to read instead of `fqdn` when
        a mere `hostName` is also an acceptable value; this option does not
        throw an error when `domain` is unset.
      '';
    };


    networking.nameservers = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "130.161.158.4" "130.161.33.17" ];
      description = ''
        The list of nameservers.  It can be left empty if it is auto-detected through DHCP.
      '';
    };

    networking.search = mkOption {
      default = [ ];
      example = [ "example.com" "home.arpa" ];
      type = types.listOf types.str;
      description = ''
        The list of search paths used when resolving domain names.
      '';
    };

    networking.domain = mkOption {
      default = null;
      example = "home.arpa";
      type = types.nullOr types.str;
      description = ''
        The domain.  It can be left empty if it is auto-detected through DHCP.
      '';
    };

    networking.useHostResolvConf = mkOption {
      type = types.bool;
      default = false;
      description = ''
        In containers, whether to use the
        {file}`resolv.conf` supplied by the host.
      '';
    };

  };


  ###### implementation

  config = {

    systemd.services.domainname = lib.mkIf (cfg.domain != null) {
      wantedBy = [ "sysinit.target" ];
      before = [ "sysinit.target" "shutdown.target" ];
      conflicts = [ "shutdown.target" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig.ExecStart = ''${pkgs.nettools}/bin/domainname "${cfg.domain}"'';
      serviceConfig.Type = "oneshot";
    };

    # static hostname configuration needed for hostnamectl and the
    # org.freedesktop.hostname1 dbus service (both provided by systemd)
    environment.etc.hostname = mkIf (cfg.hostName != "")
      {
        text = cfg.hostName + "\n";
      };

    environment.systemPackages =
      [
        pkgs.host
        pkgs.iproute2
        pkgs.iputils
        pkgs.nettools
      ];

  };

}

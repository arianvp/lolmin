{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.journald;
in {

  options = {
    services.journald.console = mkOption {
      default = "";
      type = types.str;
      description = "If non-empty, write log messages to the specified TTY device.";
    };

    services.journald.rateLimitInterval = mkOption {
      default = "30s";
      type = types.str;
      description = ''
        Configures the rate limiting interval that is applied to all
        messages generated on the system. This rate limiting is applied
        per-service, so that two services which log do not interfere with
        each other's limit. The value may be specified in the following
        units: s, min, h, ms, us. To turn off any kind of rate limiting,
        set either value to 0.

        See {option}`services.journald.rateLimitBurst` for important
        considerations when setting this value.
      '';
    };

    services.journald.storage = mkOption {
      default = "persistent";
      type = types.enum [ "persistent" "volatile" "auto" "none" ];
      description = ''
        Controls where to store journal data. See
        {manpage}`journald.conf(5)` for further information.
      '';
    };

    services.journald.rateLimitBurst = mkOption {
      default = 10000;
      type = types.int;
      description = ''
        Configures the rate limiting burst limit (number of messages per
        interval) that is applied to all messages generated on the system.
        This rate limiting is applied per-service, so that two services
        which log do not interfere with each other's limit.

        Note that the effective rate limit is multiplied by a factor derived
        from the available free disk space for the journal as described on
        [
        journald.conf(5)](https://www.freedesktop.org/software/systemd/man/journald.conf.html).

        Note that the total amount of logs stored is limited by journald settings
        such as `SystemMaxUse`, which defaults to 10% the file system size
        (capped at max 4GB), and `SystemKeepFree`, which defaults to 15% of the
        file system size.

        It is thus recommended to compute what period of time that you will be
        able to store logs for when an application logs at full burst rate.
        With default settings for log lines that are 100 Bytes long, this can
        amount to just a few hours.
      '';
    };

    services.journald.extraConfig = mkOption {
      default = "";
      type = types.lines;
      example = "Storage=volatile";
      description = ''
        Extra config options for systemd-journald. See man journald.conf
        for available options.
      '';
    };

    services.journald.forwardToSyslog = mkOption {
      default = false;
      type = types.bool;
      description = ''
        Whether to forward log messages to syslog.
      '';
    };
  };

  config = {
    systemd.additionalUpstreamSystemUnits = [
      "systemd-journald.socket"
      "systemd-journald@.socket"
      "systemd-journald-varlink@.socket"
      "systemd-journald.service"
      "systemd-journald@.service"
      "systemd-journal-flush.service"
      "systemd-journal-catalog-update.service"
      ] ++ (optional (!config.boot.isContainer) "systemd-journald-audit.socket") ++ [
      "systemd-journald-dev-log.socket"
      "syslog.socket"
      ];

    environment.etc = {
      "systemd/journald.conf".text = ''
        [Journal]
        Storage=${cfg.storage}
        RateLimitInterval=${cfg.rateLimitInterval}
        RateLimitBurst=${toString cfg.rateLimitBurst}
        ${optionalString (cfg.console != "") ''
          ForwardToConsole=yes
          TTYPath=${cfg.console}
        ''}
        ${optionalString (cfg.forwardToSyslog) ''
          ForwardToSyslog=yes
        ''}
        ${cfg.extraConfig}
      '';
    };

    users.groups.systemd-journal.gid = config.ids.gids.systemd-journal;

    systemd.services.systemd-journal-flush.restartIfChanged = false;
    systemd.services.systemd-journald.restartTriggers = [ config.environment.etc."systemd/journald.conf".source ];
    systemd.services.systemd-journald.stopIfChanged = false;
    systemd.services."systemd-journald@".restartTriggers = [ config.environment.etc."systemd/journald.conf".source ];
    systemd.services."systemd-journald@".stopIfChanged = false;
  };
}

# This module provides configuration for the PAM (Pluggable
# Authentication Modules) system.

{ config, lib, pkgs, ... }:

with lib;

let

  mkRulesTypeOption = type: mkOption {
    # These options are experimental and subject to breaking changes without notice.
    description = ''
      PAM `${type}` rules for this service.

      Attribute keys are the name of each rule.
    '';
    type = types.attrsOf (types.submodule ({ name, config, ... }: {
      options = {
        name = mkOption {
          type = types.str;
          description = ''
            Name of this rule.
          '';
          internal = true;
          readOnly = true;
        };
        enable = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether this rule is added to the PAM service config file.
          '';
        };
        order = mkOption {
          type = types.int;
          description = ''
            Order of this rule in the service file. Rules are arranged in ascending order of this value.

            ::: {.warning}
            The `order` values for the built-in rules are subject to change. If you assign a constant value to this option, a system update could silently reorder your rule. You could be locked out of your system, or your system could be left wide open. When using this option, set it to a relative offset from another rule's `order` value:

            ```nix
            {
              security.pam.services.login.rules.auth.foo.order =
                config.security.pam.services.login.rules.auth.unix.order + 10;
            }
            ```
            :::
          '';
        };
        control = mkOption {
          type = types.str;
          description = ''
            Indicates the behavior of the PAM-API should the module fail to succeed in its authentication task. See `control` in {manpage}`pam.conf(5)` for details.
          '';
        };
        modulePath = mkOption {
          type = types.str;
          description = ''
            Either the full filename of the PAM to be used by the application (it begins with a '/'), or a relative pathname from the default module location. See `module-path` in {manpage}`pam.conf(5)` for details.
          '';
        };
        args = mkOption {
          type = types.listOf types.str;
          description = ''
            Tokens that can be used to modify the specific behavior of the given PAM. Such arguments will be documented for each individual module. See `module-arguments` in {manpage}`pam.conf(5)` for details.

            Escaping rules for spaces and square brackets are automatically applied.

            {option}`settings` are automatically added as {option}`args`. It's recommended to use the {option}`settings` option whenever possible so that arguments can be overridden.
          '';
        };
        settings = mkOption {
          type = with types; attrsOf (nullOr (oneOf [ bool str int pathInStore ]));
          default = { };
          description = ''
            Settings to add as `module-arguments`.

            Boolean values render just the key if true, and nothing if false. Null values are ignored. All other values are rendered as key-value pairs.
          '';
        };
      };
      config = {
        inherit name;
        # Formats an attrset of settings as args for use as `module-arguments`.
        args = concatLists (flip mapAttrsToList config.settings (name: value:
          if isBool value
          then optional value name
          else optional (value != null) "${name}=${toString value}"
        ));
      };
    }));
  };

  parentConfig = config;

  pamOpts = { config, name, ... }:
    let cfg = config; in let config = parentConfig; in {

      imports = [
        (lib.mkRenamedOptionModule [ "enableKwallet" ] [ "kwallet" "enable" ])
      ];

      options = {

        name = mkOption {
          example = "sshd";
          type = types.str;
          description = "Name of the PAM service.";
        };

        rules = mkOption {
          # This option is experimental and subject to breaking changes without notice.
          visible = false;

          description = ''
            PAM rules for this service.

            ::: {.warning}
            This option and its suboptions are experimental and subject to breaking changes without notice.

            If you use this option in your system configuration, you will need to manually monitor this module for any changes. Otherwise, failure to adjust your configuration properly could lead to you being locked out of your system, or worse, your system could be left wide open to attackers.

            If you share configuration examples that use this option, you MUST include this warning so that users are informed.

            You may freely use this option within `nixpkgs`, and future changes will account for those use sites.
            :::
          '';
          type = types.submodule {
            options = genAttrs [ "account" "auth" "password" "session" ] mkRulesTypeOption;
          };
        };

        unixAuth = mkOption {
          default = true;
          type = types.bool;
          description = ''
            Whether users can log in with passwords defined in
            {file}`/etc/shadow`.
          '';
        };

        rootOK = mkOption {
          default = false;
          type = types.bool;
          description = ''
            If set, root doesn't need to authenticate (e.g. for the
            {command}`useradd` service).
          '';
        };

        p11Auth = mkOption {
          default = config.security.pam.p11.enable;
          defaultText = literalExpression "config.security.pam.p11.enable";
          type = types.bool;
          description = ''
            If set, keys listed in
            {file}`~/.ssh/authorized_keys` and
            {file}`~/.eid/authorized_certificates`
            can be used to log in with the associated PKCS#11 tokens.
          '';
        };

        startSession = mkOption {
          default = false;
          type = types.bool;
          description = ''
            If set, the service will register a new session with
            systemd's login manager.  For local sessions, this will give
            the user access to audio devices, CD-ROM drives.  In the
            default PolicyKit configuration, it also allows the user to
            reboot the system.
          '';
        };

        setEnvironment = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether the service should set the environment variables
            listed in {option}`environment.sessionVariables`
            using `pam_env.so`.
          '';
        };

        setLoginUid = mkOption {
          type = types.bool;
          description = ''
            Set the login uid of the process
            ({file}`/proc/self/loginuid`) for auditing
            purposes.  The login uid is only set by ‘entry points’ like
            {command}`login` and {command}`sshd`, not by
            commands like {command}`sudo`.
          '';
        };

        ttyAudit = {
          enable = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Enable or disable TTY auditing for specified users
            '';
          };

          enablePattern = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              For each user matching one of comma-separated
              glob patterns, enable TTY auditing
            '';
          };

          disablePattern = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              For each user matching one of comma-separated
              glob patterns, disable TTY auditing
            '';
          };

          openOnly = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Set the TTY audit flag when opening the session,
              but do not restore it when closing the session.
              Using this option is necessary for some services
              that don't fork() to run the authenticated session,
              such as sudo.
            '';
          };
        };

        forwardXAuth = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Whether X authentication keys should be passed from the
            calling user to the target user (e.g. for
            {command}`su`)
          '';
        };

        /*pamMount = mkOption {
          default = config.security.pam.mount.enable;
          defaultText = literalExpression "config.security.pam.mount.enable";
          type = types.bool;
          description = ''
            Enable PAM mount (pam_mount) system to mount filesystems on user login.
          '';
        };*/

        allowNullPassword = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Whether to allow logging into accounts that have no password
            set (i.e., have an empty password field in
            {file}`/etc/passwd` or
            {file}`/etc/group`).  This does not enable
            logging into disabled accounts (i.e., that have the password
            field set to `!`).  Note that regardless of
            what the pam_unix documentation says, accounts with hashed
            empty passwords are always allowed to log in.
          '';
        };

        nodelay = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Whether the delay after typing a wrong password should be disabled.
          '';
        };

        requireWheel = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Whether to permit root access only to members of group wheel.
          '';
        };

        limits = mkOption {
          default = [ ];
          type = limitsType;
          description = ''
            Attribute set describing resource limits.  Defaults to the
            value of {option}`security.pam.loginLimits`.
            The meaning of the values is explained in {manpage}`limits.conf(5)`.
          '';
        };

        showMotd = mkOption {
          default = false;
          type = types.bool;
          description = "Whether to show the message of the day.";
        };

        makeHomeDir = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Whether to try to create home directories for users
            with `$HOME`s pointing to nonexistent
            locations on session login.
          '';
        };

        updateWtmp = mkOption {
          default = false;
          type = types.bool;
          description = "Whether to update {file}`/var/log/wtmp`.";
        };

        logFailures = mkOption {
          default = false;
          type = types.bool;
          description = "Whether to log authentication failures in {file}`/var/log/faillog`.";
        };

        enableAppArmor = mkOption {
          default = false;
          type = types.bool;
          description = ''
            Enable support for attaching AppArmor profiles at the
            user/group level, e.g., as part of a role based access
            control scheme.
          '';
        };

        kwallet = {
          enable = mkOption {
            default = false;
            type = types.bool;
            description = ''
              If enabled, pam_wallet will attempt to automatically unlock the
              user's default KDE wallet upon login. If the user has no wallet named
              "kdewallet", or the login password does not match their wallet
              password, KDE will prompt separately after login.
            '';
          };

          package = mkPackageOption pkgs.plasma5Packages "kwallet-pam" {
            pkgsText = "pkgs.plasma5Packages";
          };
        };

        sssdStrictAccess = mkOption {
          default = false;
          type = types.bool;
          description = "enforce sssd access control";
        };

        enableGnomeKeyring = mkOption {
          default = false;
          type = types.bool;
          description = ''
            If enabled, pam_gnome_keyring will attempt to automatically unlock the
            user's default Gnome keyring upon login. If the user login password does
            not match their keyring password, Gnome Keyring will prompt separately
            after login.
          '';
        };

        failDelay = {
          enable = mkOption {
            type = types.bool;
            default = false;
            description = ''
              If enabled, this will replace the `FAIL_DELAY` setting from `login.defs`.
              Change the delay on failure per-application.
            '';
          };

          delay = mkOption {
            default = 3000000;
            type = types.int;
            example = 1000000;
            description = "The delay time (in microseconds) on failure.";
          };
        };

        gnupg = {
          enable = mkOption {
            type = types.bool;
            default = false;
            description = ''
              If enabled, pam_gnupg will attempt to automatically unlock the
              user's GPG keys with the login password via
              {command}`gpg-agent`. The keygrips of all keys to be
              unlocked should be written to {file}`~/.pam-gnupg`,
              and can be queried with {command}`gpg -K --with-keygrip`.
              Presetting passphrases must be enabled by adding
              `allow-preset-passphrase` in
              {file}`~/.gnupg/gpg-agent.conf`.
            '';
          };

          noAutostart = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Don't start {command}`gpg-agent` if it is not running.
              Useful in conjunction with starting {command}`gpg-agent` as
              a systemd user service.
            '';
          };

          storeOnly = mkOption {
            type = types.bool;
            default = false;
            description = ''
              Don't send the password immediately after login, but store for PAM
              `session`.
            '';
          };
        };

        zfs = mkOption {
          default = config.security.pam.zfs.enable;
          defaultText = literalExpression "config.security.pam.zfs.enable";
          type = types.bool;
          description = ''
            Enable unlocking and mounting of encrypted ZFS home dataset at login.
          '';
        };

        text = mkOption {
          type = types.nullOr types.lines;
          description = "Contents of the PAM service file.";
        };

      };

      # The resulting /etc/pam.d/* file contents are verified in
      # nixos/tests/pam/pam-file-contents.nix. Please update tests there when
      # changing the derivation.
      config = {
        name = mkDefault name;
        setLoginUid = mkDefault cfg.startSession;
        limits = mkDefault config.security.pam.loginLimits;

        text =
          let
            ensureUniqueOrder = type: rules:
              let
                checkPair = a: b: assert assertMsg (a.order != b.order) "security.pam.services.${name}.rules.${type}: rules '${a.name}' and '${b.name}' cannot have the same order value (${toString a.order})"; b;
                checked = zipListsWith checkPair rules (drop 1 rules);
              in
              take 1 rules ++ checked;
            # Formats a string for use in `module-arguments`. See `man pam.conf`.
            formatModuleArgument = token:
              if hasInfix " " token
              then "[${replaceStrings ["]"] ["\\]"] token}]"
              else token;
            formatRules = type: pipe cfg.rules.${type} [
              attrValues
              (filter (rule: rule.enable))
              (sort (a: b: a.order < b.order))
              (ensureUniqueOrder type)
              (map (rule: concatStringsSep " " (
                [ type rule.control rule.modulePath ]
                ++ map formatModuleArgument rule.args
                ++ [ "# ${rule.name} (order ${toString rule.order})" ]
              )))
              (concatStringsSep "\n")
            ];
          in
          mkDefault ''
            # Account management.
            ${formatRules "account"}

            # Authentication management.
            ${formatRules "auth"}

            # Password management.
            ${formatRules "password"}

            # Session management.
            ${formatRules "session"}
          '';

        # !!! TODO: move the LDAP stuff to the LDAP module, and the
        # Samba stuff to the Samba module.  This requires that the PAM
        # module provides the right hooks.
        rules =
          let
            autoOrderRules = flip pipe [
              (imap1 (index: rule: rule // { order = mkDefault (10000 + index * 100); }))
              (map (rule: nameValuePair rule.name (removeAttrs rule [ "name" ])))
              listToAttrs
            ];
          in
          {
            account = autoOrderRules [
              #{ name = "ldap"; enable = use_ldap; control = "sufficient"; modulePath = "${pam_ldap}/lib/security/pam_ldap.so"; }
              /*{
                name = "mysql";
                enable = cfg.mysqlAuth;
                control = "sufficient";
                modulePath = "${pkgs.pam_mysql}/lib/security/pam_mysql.so";
                settings = {
                  config_file = "/etc/security/pam_mysql.conf";
                };
              }*/
              /*{
                name = "kanidm";
                enable = config.services.kanidm.enablePam;
                control = "sufficient";
                modulePath = "${pkgs.kanidm}/lib/pam_kanidm.so";
                settings = {
                  ignore_unknown_user = true;
                };
              }*/
              #{ name = "sss"; enable = config.services.sssd.enable; control = if cfg.sssdStrictAccess then "[default=bad success=ok user_unknown=ignore]" else "sufficient"; modulePath = "${pkgs.sssd}/lib/security/pam_sss.so"; }
              #{ name = "krb5"; enable = config.security.pam.krb5.enable; control = "sufficient"; modulePath = "${pam_krb5}/lib/security/pam_krb5.so"; }
              #{ name = "oslogin_login"; enable = cfg.googleOsLoginAccountVerification; control = "[success=ok ignore=ignore default=die]"; modulePath = "${pkgs.google-guest-oslogin}/lib/security/pam_oslogin_login.so"; }
              #{ name = "oslogin_admin"; enable = cfg.googleOsLoginAccountVerification; control = "[success=ok default=ignore]"; modulePath = "${pkgs.google-guest-oslogin}/lib/security/pam_oslogin_admin.so"; }
              #{ name = "systemd_home"; enable = config.services.homed.enable; control = "sufficient"; modulePath = "${config.systemd.package}/lib/security/pam_systemd_home.so"; }
              # The required pam_unix.so module has to come after all the sufficient modules
              # because otherwise, the account lookup will fail if the user does not exist
              # locally, for example with MySQL- or LDAP-auth.
              { name = "unix"; control = "required"; modulePath = "pam_unix.so"; }
            ];

            auth = autoOrderRules ([
              { name = "rootok"; enable = cfg.rootOK; control = "sufficient"; modulePath = "pam_rootok.so"; }
              {
                name = "wheel";
                enable = cfg.requireWheel;
                control = "required";
                modulePath = "pam_wheel.so";
                settings = {
                  use_uid = true;
                };
              }
              { name = "faillock"; enable = cfg.logFailures; control = "required"; modulePath = "pam_faillock.so"; }
            ] ++
            # Modules in this block require having the password set in PAM_AUTHTOK.
            # pam_unix is marked as 'sufficient' on NixOS which means nothing will run
            # after it succeeds. Certain modules need to run after pam_unix
            # prompts the user for password so we run it once with 'optional' at an
            # earlier point and it will run again with 'sufficient' further down.
            # We use try_first_pass the second time to avoid prompting password twice.
            #
            # The same principle applies to systemd-homed
            (optionals
              ((cfg.unixAuth || config.services.homed.enable))
              [
                { name = "systemd_home-early"; enable = config.services.homed.enable; control = "optional"; modulePath = "${config.systemd.package}/lib/security/pam_systemd_home.so"; }
                {
                  name = "unix-early";
                  enable = cfg.unixAuth;
                  control = "optional";
                  modulePath = "pam_unix.so";
                  settings = {
                    nullok = cfg.allowNullPassword;
                    inherit (cfg) nodelay;
                    likeauth = true;
                  };
                }
                {
                  name = "faildelay";
                  enable = cfg.failDelay.enable;
                  control = "optional";
                  modulePath = "${pkgs.pam}/lib/security/pam_faildelay.so";
                  settings = {
                    inherit (cfg.failDelay) delay;
                  };
                }
              ]) ++ [
              { name = "systemd_home"; enable = config.services.homed.enable; control = "sufficient"; modulePath = "${config.systemd.package}/lib/security/pam_systemd_home.so"; }
              {
                name = "unix";
                enable = cfg.unixAuth;
                control = "sufficient";
                modulePath = "pam_unix.so";
                settings = {
                  nullok = cfg.allowNullPassword;
                  inherit (cfg) nodelay;
                  likeauth = true;
                  try_first_pass = true;
                };
              }
              { name = "deny"; control = "required"; modulePath = "pam_deny.so"; }
            ]);

            password = autoOrderRules [
              { name = "systemd_home"; enable = config.services.homed.enable; control = "sufficient"; modulePath = "${config.systemd.package}/lib/security/pam_systemd_home.so"; }
              {
                name = "unix";
                control = "sufficient";
                modulePath = "pam_unix.so";
                settings = {
                  nullok = true;
                  yescrypt = true;
                };
              }
            ];

            session = autoOrderRules [
              {
                name = "env";
                enable = cfg.setEnvironment;
                control = "required";
                modulePath = "pam_env.so";
                settings = {
                  conffile = "/etc/pam/environment";
                  readenv = 0;
                };
              }
              { name = "unix"; control = "required"; modulePath = "pam_unix.so"; }
              { name = "loginuid"; enable = cfg.setLoginUid; control = if config.boot.isContainer then "optional" else "required"; modulePath = "pam_loginuid.so"; }
              {
                name = "tty_audit";
                enable = cfg.ttyAudit.enable;
                control = "required";
                modulePath = "${pkgs.pam}/lib/security/pam_tty_audit.so";
                settings = {
                  open_only = cfg.ttyAudit.openOnly;
                  enable = cfg.ttyAudit.enablePattern;
                  disable = cfg.ttyAudit.disablePattern;
                };
              }
              { name = "systemd_home"; enable = config.services.homed.enable; control = "required"; modulePath = "${config.systemd.package}/lib/security/pam_systemd_home.so"; }
              {
                name = "mkhomedir";
                enable = cfg.makeHomeDir;
                control = "required";
                modulePath = "${pkgs.pam}/lib/security/pam_mkhomedir.so";
                settings = {
                  silent = true;
                  skel = config.security.pam.makeHomeDir.skelDirectory;
                  inherit (config.security.pam.makeHomeDir) umask;
                };
              }
              {
                name = "lastlog";
                enable = cfg.updateWtmp;
                control = "required";
                modulePath = "${pkgs.pam}/lib/security/pam_lastlog.so";
                settings = {
                  silent = true;
                };
              }
              { name = "systemd"; enable = cfg.startSession; control = "optional"; modulePath = "${config.systemd.package}/lib/security/pam_systemd.so"; }
              {
                name = "limits";
                enable = cfg.limits != [ ];
                control = "required";
                modulePath = "${pkgs.pam}/lib/security/pam_limits.so";
                settings = {
                  conf = "${makeLimitsConf cfg.limits}";
                };
              }
              {
                name = "motd";
                enable = cfg.showMotd && (config.users.motd != null || config.users.motdFile != null);
                control = "optional";
                modulePath = "${pkgs.pam}/lib/security/pam_motd.so";
                settings = {
                  inherit motd;
                };
              }
              {
                name = "apparmor";
                enable = cfg.enableAppArmor && config.security.apparmor.enable;
                control = "optional";
                modulePath = "${pkgs.apparmor-pam}/lib/security/pam_apparmor.so";
                settings = {
                  order = "user,group,default";
                  debug = true;
                };
              }
              { name = "kwallet"; enable = cfg.kwallet.enable; control = "optional"; modulePath = "${cfg.kwallet.package}/lib/security/pam_kwallet5.so"; }
              {
                name = "gnome_keyring";
                enable = cfg.enableGnomeKeyring;
                control = "optional";
                modulePath = "${pkgs.gnome.gnome-keyring}/lib/security/pam_gnome_keyring.so";
                settings = {
                  auto_start = true;
                };
              }
              {
                name = "gnupg";
                enable = cfg.gnupg.enable;
                control = "optional";
                modulePath = "${pkgs.pam_gnupg}/lib/security/pam_gnupg.so";
                settings = {
                  no-autostart = cfg.gnupg.noAutostart;
                };
              }
            ];
          };
      };

    };


  inherit (pkgs) pam_krb5 pam_ccreds;

  use_ldap = (config.users.ldap.enable && config.users.ldap.loginPam);
  pam_ldap = if config.users.ldap.daemon.enable then pkgs.nss_pam_ldapd else pkgs.pam_ldap;

  # Create a limits.conf(5) file.
  makeLimitsConf = limits:
    pkgs.writeText "limits.conf"
      (concatMapStrings
        ({ domain, type, item, value }:
          "${domain} ${type} ${item} ${toString value}\n")
        limits);

  limitsType = with lib.types; listOf (submodule ({ ... }: {
    options = {
      domain = mkOption {
        description = "Username, groupname, or wildcard this limit applies to";
        example = "@wheel";
        type = str;
      };

      type = mkOption {
        description = "Type of this limit";
        type = enum [ "-" "hard" "soft" ];
        default = "-";
      };

      item = mkOption {
        description = "Item this limit applies to";
        type = enum [
          "core"
          "data"
          "fsize"
          "memlock"
          "nofile"
          "rss"
          "stack"
          "cpu"
          "nproc"
          "as"
          "maxlogins"
          "maxsyslogins"
          "priority"
          "locks"
          "sigpending"
          "msgqueue"
          "nice"
          "rtprio"
        ];
      };

      value = mkOption {
        description = "Value of this limit";
        type = oneOf [ str int ];
      };
    };
  }));

  motd =
    if config.users.motdFile == null
    then pkgs.writeText "motd" config.users.motd
    else config.users.motdFile;

  makePAMService = name: service:
    {
      name = "pam.d/${name}";
      value.source = pkgs.writeText "${name}.pam" service.text;
    };

  optionalSudoConfigForSSHAgentAuth = optionalString config.security.pam.sshAgentAuth.enable ''
    # Keep SSH_AUTH_SOCK so that pam_ssh_agent_auth.so can do its magic.
    Defaults env_keep+=SSH_AUTH_SOCK
  '';

in

{

  meta.maintainers = [ maintainers.majiir ];

  ###### interface

  options = {

    security.pam.loginLimits = mkOption {
      default = [ ];
      type = limitsType;
      example =
        [{
          domain = "ftp";
          type = "hard";
          item = "nproc";
          value = "0";
        }
          {
            domain = "@student";
            type = "-";
            item = "maxlogins";
            value = "4";
          }];

      description = ''
        Define resource limits that should apply to users or groups.
        Each item in the list should be an attribute set with a
        {var}`domain`, {var}`type`,
        {var}`item`, and {var}`value`
        attribute.  The syntax and semantics of these attributes
        must be that described in {manpage}`limits.conf(5)`.

        Note that these limits do not apply to systemd services,
        whose limits can be changed via {option}`systemd.extraConfig`
        instead.
      '';
    };

    security.pam.services = mkOption {
      default = { };
      type = with types; attrsOf (submodule pamOpts);
      description = ''
        This option defines the PAM services.  A service typically
        corresponds to a program that uses PAM,
        e.g. {command}`login` or {command}`passwd`.
        Each attribute of this set defines a PAM service, with the attribute name
        defining the name of the service.
      '';
    };

    security.pam.makeHomeDir.skelDirectory = mkOption {
      type = types.str;
      default = "/var/empty";
      example = "/etc/skel";
      description = ''
        Path to skeleton directory whose contents are copied to home
        directories newly created by `pam_mkhomedir`.
      '';
    };

    security.pam.makeHomeDir.umask = mkOption {
      type = types.str;
      default = "0077";
      example = "0022";
      description = ''
        The user file mode creation mask to use on home directories
        newly created by `pam_mkhomedir`.
      '';
    };

    security.pam.sshAgentAuth = {
      enable = mkEnableOption ''
        authenticating using a signature performed by the ssh-agent.
        This allows using SSH keys exclusively, instead of passwords, for instance on remote machines
      '';

      authorizedKeysFiles = mkOption {
        type = with types; listOf str;
        description = ''
          A list of paths to files in OpenSSH's `authorized_keys` format, containing
          the keys that will be trusted by the `pam_ssh_agent_auth` module.

          The following patterns are expanded when interpreting the path:
          - `%f` and `%H` respectively expand to the fully-qualified and short hostname ;
          - `%u` expands to the username ;
          - `~` or `%h` expands to the user's home directory.

          ::: {.note}
          Specifying user-writeable files here result in an insecure configuration:  a malicious process
          can then edit such an authorized_keys file and bypass the ssh-agent-based authentication.

          See [issue #31611](https://github.com/NixOS/nixpkgs/issues/31611)
          :::
        '';
        default = [ "/etc/ssh/authorized_keys.d/%u" ];
      };
    };

    security.pam.enableOTPW = mkEnableOption "the OTPW (one-time password) PAM module";

    security.pam.dp9ik = {
      enable = mkEnableOption ''
        the dp9ik pam module provided by tlsclient.

        If set, users can be authenticated against the 9front
        authentication server given in {option}`security.pam.dp9ik.authserver`.
      '';
      control = mkOption {
        default = "sufficient";
        type = types.str;
        description = ''
          This option sets the pam "control" used for this module.
        '';
      };
      authserver = mkOption {
        default = null;
        type = with types; nullOr str;
        description = ''
          This controls the hostname for the 9front authentication server
          that users will be authenticated against.
        '';
      };
    };


    users.motd = mkOption {
      default = null;
      example = "Today is Sweetmorn, the 4th day of The Aftermath in the YOLD 3178.";
      type = types.nullOr types.lines;
      description = "Message of the day shown to users when they log in.";
    };

    users.motdFile = mkOption {
      default = null;
      example = "/etc/motd";
      type = types.nullOr types.path;
      description = "A file containing the message of the day shown to users when they log in.";
    };
  };


  ###### implementation

  config = {
    assertions = [
      {
        assertion = config.users.motd == null || config.users.motdFile == null;
        message = ''
          Only one of users.motd and users.motdFile can be set.
        '';
      }
    ];

    environment.systemPackages = [ pkgs.pam ];

    #boot.supportedFilesystems = optionals config.security.pam.enableEcryptfs [ "ecryptfs" ];

    security.wrappers = {
      unix_chkpwd = {
        setuid = true;
        owner = "root";
        group = "root";
        source = "${pkgs.pam}/bin/unix_chkpwd";
      };
    };

    environment.etc = mapAttrs' makePAMService config.security.pam.services;

    security.pam.services =
      {
        other.text =
          ''
            auth     required pam_warn.so
            auth     required pam_deny.so
            account  required pam_warn.so
            account  required pam_deny.so
            password required pam_warn.so
            password required pam_deny.so
            session  required pam_warn.so
            session  required pam_deny.so
          '';

        # Most of these should be moved to specific modules.

        runuser = { rootOK = true; unixAuth = false; setEnvironment = false; };

        /* FIXME: should runuser -l start a systemd session? Currently
           it complains "Cannot create session: Already running in a
           session". */
        runuser-l = { rootOK = true; unixAuth = false; };
      };

    security.apparmor.includes."abstractions/pam" =
      lib.concatMapStrings
        (name: "r ${config.environment.etc."pam.d/${name}".source},\n")
        (attrNames config.security.pam.services) +
      ''
        mr ${getLib pkgs.pam}/lib/security/pam_filter/*,
        mr ${getLib pkgs.pam}/lib/security/pam_*.so,
        r ${getLib pkgs.pam}/lib/security/,
      '' +
      (with lib; pipe config.security.pam.services [
        attrValues
        (catAttrs "rules")
        (concatMap attrValues)
        (concatMap attrValues)
        (filter (rule: rule.enable))
        (catAttrs "modulePath")
        (filter (hasPrefix "/"))
        unique
        (map (module: "mr ${module},"))
        concatLines
      ]);

    security.sudo.extraConfig = optionalSudoConfigForSSHAgentAuth;
    security.sudo-rs.extraConfig = optionalSudoConfigForSSHAgentAuth;
  };
}

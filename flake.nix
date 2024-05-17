{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }: {
    nixosModules.minimal = {
      imports = [
        ({ lib, ... }: {
          options.boot.loader.grub.enable = lib.mkEnableOption "no";
        })
        (nixpkgs + "/nixos/modules/misc/assertions.nix")
        (nixpkgs + "/nixos/modules/misc/extra-arguments.nix")
        (nixpkgs + "/nixos/modules/misc/nixpkgs.nix")
        (nixpkgs + "/nixos/modules/misc/lib.nix")
        (nixpkgs + "/nixos/modules/misc/ids.nix")
        (nixpkgs + "/nixos/modules/misc/version.nix")
        (nixpkgs + "/nixos/modules/system/boot/loader/systemd-boot/systemd-boot.nix")
        (nixpkgs + "/nixos/modules/system/boot/loader/efi.nix")
        (nixpkgs + "/nixos/modules/system/boot/loader/loader.nix")
        (nixpkgs + "/nixos/modules/system/boot/kernel.nix")
        (nixpkgs + "/nixos/modules/system/boot/stage-1.nix")
        (nixpkgs + "/nixos/modules/system/boot/stage-2.nix")
        (nixpkgs + "/nixos/modules/system/boot/systemd.nix")
        ({ lib, ... }: {
          options.boot.isContainer = lib.mkEnableOption "no";
          options.boot.swraid.mdadmConf = lib.mkOption {
            # euhm
            type = lib.types.str;
            default = "";

            description = ''
              The content of /etc/mdadm.conf
            '';
          };
        })
        (nixpkgs + "/nixos/modules/config/sysctl.nix")
        (nixpkgs + "/nixos/modules/config/swap.nix")
        ./system-path.nix
        (nixpkgs + "/nixos/modules/config/shells-environment.nix")
        (nixpkgs + "/nixos/modules/config/system-environment.nix")
        (nixpkgs + "/nixos/modules/config/users-groups.nix")
        (nixpkgs + "/nixos/modules/config/nsswitch.nix")
        (nixpkgs + "/nixos/modules/config/i18n.nix")
        (nixpkgs + "/nixos/modules/config/iproute2.nix")
        (nixpkgs + "/nixos/modules/config/nix.nix")
        (nixpkgs + "/nixos/modules/config/nix-remote-build.nix")
        ./nix-daemon.nix
        (nixpkgs + "/nixos/modules/config/resolvconf.nix")
        (nixpkgs + "/nixos/modules/config/networking.nix")
        (nixpkgs + "/nixos/modules/config/power-management.nix")
        (nixpkgs + "/nixos/modules/programs/environment.nix")
        (nixpkgs + "/nixos/modules/programs/less.nix")
        (nixpkgs + "/nixos/modules/programs/shadow.nix")
        (nixpkgs + "/nixos/modules/programs/bash/bash.nix")
        (nixpkgs + "/nixos/modules/programs/bash/bash-completion.nix")

        ./pam.nix
        (nixpkgs + "/nixos/modules/security/polkit.nix")
        ./sudo.nix
        (nixpkgs + "/nixos/modules/security/sudo-rs.nix")
        (nixpkgs + "/nixos/modules/security/apparmor.nix")
        (nixpkgs + "/nixos/modules/security/wrappers/default.nix")

        (nixpkgs + "/nixos/modules/services/logging/logrotate.nix")

        (nixpkgs + "/nixos/modules/services/system/dbus.nix")
        (nixpkgs + "/nixos/modules/services/system/nscd.nix")
        (nixpkgs + "/nixos/modules/system/boot/modprobe.nix")
        ./systemd-initrd.nix
        (nixpkgs + "/nixos/modules/system/boot/systemd/sysusers.nix")
        (nixpkgs + "/nixos/modules/system/boot/systemd/oomd.nix")
        ./systemd-user.nix
        (nixpkgs + "/nixos/modules/system/boot/systemd/homed.nix")
        (nixpkgs + "/nixos/modules/system/boot/systemd/userdbd.nix")
        (nixpkgs + "/nixos/modules/system/boot/systemd/tmpfiles.nix")
        ./journald.nix
        # (nixpkgs + "/nixos/modules/system/boot/resolved.nix")
        (nixpkgs + "/nixos/modules/system/activation/bootspec.nix")
        (nixpkgs + "/nixos/modules/system/activation/specialisation.nix")
        (nixpkgs + "/nixos/modules/system/activation/activation-script.nix")
        (nixpkgs + "/nixos/modules/system/activation/top-level.nix")
        (nixpkgs + "/nixos/modules/system/etc/etc.nix")
        (nixpkgs + "/nixos/modules/tasks/filesystems.nix")
        ./network-interfaces.nix


        (nixpkgs + "/nixos/modules/services/hardware/udev.nix")
        (nixpkgs + "/nixos/modules/hardware/device-tree.nix")
      ];
    };

    nixosModules.x86_64-linux = { nixpkgs.pkgs = nixpkgs.legacyPackages.x86_64-linux; };
    nixosModules.aarch64-linux = { nixpkgs.pkgs = nixpkgs.legacyPackages.aarch64-linux; };

    nixosModules.config = {
      networking.hostName = "foo";
      fileSystems."/".device = "/dev/disk/by-label/nixos";
      boot.loader.systemd-boot.enable = true;
      boot.initrd.systemd.enable = true;
      system.stateVersion = "24.05";
    };

    nixosConfigurations.aarch64-linux = nixpkgs.lib.nixosSystem {
      modules = with self.nixosModules; [ aarch64-linux config ];
    };

    nixosConfigurations.aarch64-linux-minimal = nixpkgs.lib.nixos.evalModules {
      modules = with self.nixosModules; [ aarch64-linux minimal config ];
    };
  };
}

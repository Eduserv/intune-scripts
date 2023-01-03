# Dell Specific Scripts

Make sure you are deploying Dell Command | Update through intune!

- [CommandUpdateDetection.ps1](./CommandUpdateDetection.ps1) detects if Dell Command Update has updates to install

- [CommandUpdateRemediation.ps1](./CommandUpdateRemediation.ps1) applys the updates.
During the checks:
    - sets commandupdate to auto update and auto install
    - if a BIOS password has been set, sets Dell Command Update to the password in KeyVault <br />(see [BiosPassword/README.md](../BiosPassword/README.md) for parameters that need to be set for this script to work).
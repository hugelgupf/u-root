#!/bin/bash
set -euo pipefail
set -v

# Path to a working Windows *raw* image:
WINDOWS_DISK="${EFI_WORKSPACE}"/windows.img

START_PATH=$(realpath .)

### Downloading and extracting ovmf EFI firmawre ###
mkdir -p "${EFI_WORKSPACE}"/downloads
cd "${EFI_WORKSPACE}"/downloads
FIRMWARE_URL=https://www.kraxel.org/repos/jenkins/edk2/edk2.git-ovmf-x64-0-20190704.1212.g76e12fa334.noarch.rpm
FIRMWARE_IMAGE=$(basename ${FIRMWARE_URL})
echo "${FIRMWARE_IMAGE}"

if [[ ! -f ${FIRMWARE_IMAGE} ]]; then
  wget "${FIRMWARE_URL}" -O "${FIRMWARE_IMAGE}"

  fakeroot alien -d "${FIRMWARE_IMAGE}"

  # Assuming there is exatcly one .deb file:
  FIRMWARE_DEB=$(find . -name '*edk2.git-ovmf*deb*')

  rm -rf ovmf
  dpkg-deb -x "${FIRMWARE_DEB}" ovmf

else
  echo "NOTE: $(realpath "${FIRMWARE_IMAGE}") exists!! " \
       "Remove file to re-download EFI firmware." 1>&2
fi

# Clone the forked Linux kernel and build it. There may be some pre-requisties
# missing.

if [[ ! -d "${EFI_WORKSPACE}/linux" ]]; then
  git clone https://github.com/hugelgupf/linux.git
fi

pushd linux
git checkout efikexec

# the branch currently has a .config -- we'll fix this later.

#cp "$START_PATH/linux_config/dot_config" .config
#make olddefconfig # populate config with default values which may be missing

echo "Installing libelf-dev, may prompt for sudo password:"
sudo apt-get install libelf-dev


DPDK_VERSION="23.11"

# Install dependencies
sudo apt install -y build-essential meson ninja-build pkg-config
sudo apt install -y linux-headers-$(uname -r)
sudo apt install -y libnuma-dev libpcap-dev libelf-dev
sudo apt install -y libibverbs1 ibverbs-providers libibverbs-dev
sudo apt install -y wget
sudo apt install -y python3-pyelftools

# Download DPDK source code
cd /opt
sudo wget http://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz

# Extract DPDK source code
sudo tar -xf dpdk-${DPDK_VERSION}.tar.xz
cd dpdk-${DPDK_VERSION}

# Build & install DPDK
sudo meson setup build
cd build
sudo ninja
sudo meson install
sudo ldconfig

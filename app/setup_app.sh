#!/bin/bash

# Setup script for CryptoChat App
# Run this once with: sudo ./setup_app.sh

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# echo "[1/4] Building latest binaries..."
# make clean && make  # Disabling this as install.sh already did the build

echo "[1/3] Installing binaries to /usr/local/bin..."
cp gui_client /usr/local/bin/cryptochat-gui
chmod +x /usr/local/bin/cryptochat-gui

# Create a launcher script to ensure it runs correctly
cat <<EOF > /usr/local/bin/cryptochat-launcher
#!/bin/bash
# Launcher for CryptoChat
/usr/local/bin/cryptochat-gui
EOF
chmod +x /usr/local/bin/cryptochat-launcher

echo "[2/3] Configuring driver permissions (udev rules)..."
# This allows any user in the current user's group to access the crypto driver
REAL_USER=${SUDO_USER:-$USER}
echo "KERNEL==\"crypto_chat\", MODE=\"0666\"" > /etc/udev/rules.d/99-cryptochat.rules
udevadm control --reload-rules
udevadm trigger

echo "[3/3] Installing Desktop Entry..."
cp cryptochat.desktop /usr/share/applications/
# Try to copy a generic icon if available, otherwise it uses system default
if [ -f "client/resources/icon.png" ]; then
    mkdir -p /usr/share/icons/hicolor/256x256/apps/
    cp client/resources/icon.png /usr/share/icons/hicolor/256x256/apps/cryptochat.png
fi

echo "--------------------------------------------------"
echo "DONE! CryptoChat is now installed as a system app."
echo "You can now find 'CryptoChat' in your application menu."
echo "You NO LONGER need sudo to run it."
echo "--------------------------------------------------"

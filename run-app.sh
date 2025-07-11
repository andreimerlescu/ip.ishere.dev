#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check SELinux status
function check_selinux_status() {
    if command -v getenforce >/dev/null 2>&1; then
        local selinux_status=$(getenforce 2>/dev/null || echo "Disabled")
        case "$selinux_status" in
            "Enforcing"|"Permissive")
                return 0  # SELinux is active
                ;;
            "Disabled"|*)
                return 1  # SELinux is disabled or not available
                ;;
        esac
    else
        return 1  # SELinux tools not available
    fi
}

if ! [ -d app ]; then
    mkdir app
fi
if ! [ -d app-data ]; then
    mkdir app-data
fi

# Check if SELinux is enabled
if check_selinux_status; then
    echo -e "${GREEN}SELinux is active. Setting up SELinux contexts for ip application...${NC}"

    # Remove any existing file contexts to avoid conflicts
    echo -e "${YELLOW}Cleaning up existing file contexts...${NC}"
    sudo semanage fcontext -d "app(/.*)?" 2>/dev/null || true
    sudo semanage fcontext -d "app-data(/.*)?" 2>/dev/null || true
    if [ -f ip.ishere.dev-linux-amd64 ]; then
        sudo semanage fcontext -d "ip\.ishere\.dev-linux-amd64" 2>/dev/null || true
    fi
    if [ -f bin/ip.ishere.dev-linux-amd64 ]; then
        sudo semanage fcontext -d "bin/ip\.ishere\.dev-linux-amd64" 2>/dev/null || true
    fi

    # Set file contexts using httpd_sys_content_t
    echo -e "${YELLOW}Setting file contexts...${NC}"
    if [ -f ip.ishere.dev-linux-amd64 ]; then
        sudo semanage fcontext -a -t bin_t "ip\.ishere\.dev-linux-amd64"
    fi
    if [ -f bin/ip.ishere.dev-linux-amd64 ]; then
        sudo semanage fcontext -a -t bin_t "bin/ip\.ishere\.dev-linux-amd64"
    fi
    sudo semanage fcontext -a -t httpd_sys_content_t "app(/.*)?"
    sudo semanage fcontext -a -t httpd_sys_rw_content_t "app-data(/.*)?"

    # Apply the contexts
    echo -e "${YELLOW}Applying file contexts...${NC}"
    if [ -f ip.ishere.dev-linux-amd64 ]; then
        sudo restorecon -v ip.ishere.dev-linux-amd64
    fi
    if [ -f bin/ip.ishere.dev-linux-amd64 ]; then
        sudo restorecon -v bin/ip.ishere.dev-linux-amd64
    fi
    sudo restorecon -Rv app
    sudo restorecon -Rv app-data

    echo -e "${GREEN}SELinux context setup complete!${NC}"
else
    echo -e "${YELLOW}SELinux is disabled or not available. Skipping SELinux context setup.${NC}"
fi

# Set capabilities for the binary (this works regardless of SELinux status)
echo -e "${YELLOW}Setting capabilities for ip binary...${NC}"
sudo setcap cap_net_bind_service=+ep ip.ishere.dev-linux-amd64

echo -e "${YELLOW}Starting application...${NC}"

check_systemd_service() {
    local service_file="/etc/systemd/system/ip.service"

    # Check if service file exists
    if [[ ! -f "$service_file" ]]; then
        echo -e "${YELLOW}ip.service not found at $service_file${NC}"
        return 1
    fi

    # Check if systemctl is available
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "${YELLOW}systemctl command not available${NC}"
        return 1
    fi

    # Try to reload systemd daemon
    if ! sudo systemctl daemon-reload 2>/dev/null; then
        echo -e "${YELLOW}Failed to reload systemd daemon${NC}"
        return 1
    fi

    return 0
}

# Try to use systemd service first
if check_systemd_service; then
    echo -e "${GREEN}Found ip.service. Starting via systemd...${NC}"

    # Start the service
    if sudo systemctl start ip.service; then
        echo -e "${GREEN}Service started successfully${NC}"

        # Enable the service for auto-start
        if sudo systemctl enable ip.service; then
            echo -e "${GREEN}Service enabled for auto-start${NC}"
        else
            echo -e "${YELLOW}Warning: Failed to enable service for auto-start${NC}"
        fi

        # Show service status
        echo -e "${GREEN}Service status:${NC}"
        sudo systemctl status ip.service --no-pager
    else
        echo -e "${RED}Failed to start service via systemd. Falling back to direct execution...${NC}"
        # Fallback to direct execution
        IP_CONFIG_FILE=$(realpath app/config.yaml) /home/admin/ip.ishere.dev-linux-amd64
    fi
else
    echo -e "${YELLOW}Using direct execution method...${NC}"
    # Fallback to direct execution
    IP_CONFIG_FILE=$(realpath app/config.yaml) /home/admin/ip.ishere.dev-linux-amd64
fi


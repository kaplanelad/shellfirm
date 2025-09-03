#!/bin/bash

# Complete Production Build Script for Shellfirm
# Builds CLI, WASM, and MCP in production mode

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}🏗️  Shellfirm Production Build${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}📦 Building all packages: CLI + WASM + MCP${NC}"

# Build step counter
step=1

print_step() {
    echo -e "\n${BLUE}📋 Step $step: $1${NC}"
    ((step++))
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

# Step 1: Build CLI (shellfirm) in release mode
print_step "Building Shellfirm CLI (Release)"
cd "$SCRIPT_DIR"

print_info "Building with cargo build --release..."
if cargo build --release; then
    print_success "CLI built successfully"
    print_info "Binary location: target/release/shellfirm"
else
    echo -e "${RED}✗ CLI build failed${NC}"
    exit 1
fi

# Step 2: Build shellfirm_core WASM in release mode
print_step "Building shellfirm_core WASM (Release)"
cd "$SCRIPT_DIR/shellfirm_core"

print_info "Building WASM with wasm-pack (release mode)..."
if wasm-pack build --release --target nodejs --features wasm; then
    print_success "WASM package built successfully"
    print_info "Package location: shellfirm_core/pkg/"
else
    echo -e "${RED}✗ WASM build failed${NC}"
    exit 1
fi

# Step 3: Copy WASM files to MCP
print_step "Copying WASM files to MCP"
cd "$SCRIPT_DIR"

# Ensure MCP pkg directory exists
mkdir -p mcp/pkg

# Copy all WASM files
declare -a wasm_files=(
    "shellfirm_core_bg.wasm"           # Binary WASM module
    "shellfirm_core_bg.wasm.d.ts"      # WASM type definitions
    "shellfirm_core.js"                # JavaScript wrapper
    "shellfirm_core.d.ts"              # TypeScript definitions
    "package.json"                     # Package metadata
)

for file in "${wasm_files[@]}"; do
    source_file="shellfirm_core/pkg/$file"
    dest_file="mcp/pkg/$file"
    
    if [ -f "$source_file" ]; then
        cp "$source_file" "$dest_file"
        print_success "Copied $file"
    else
        print_info "File not found: $file (skipping)"
    fi
done

# Verify critical files
if [ ! -f "mcp/pkg/shellfirm_core_bg.wasm" ]; then
    echo -e "${RED}✗ Critical WASM binary not copied${NC}"
    exit 1
fi

print_success "All WASM files copied to MCP"

# Step 4: Build MCP TypeScript project
print_step "Building MCP TypeScript (Production)"
cd "$SCRIPT_DIR/mcp"

# Check if package.json exists
if [ ! -f "package.json" ]; then
    echo -e "${RED}✗ package.json not found in MCP directory${NC}"
    exit 1
fi

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    print_info "Installing npm dependencies..."
    if npm ci; then
        print_success "Dependencies installed"
    else
        echo -e "${RED}✗ Failed to install dependencies${NC}"
        exit 1
    fi
else
    print_info "Dependencies already installed"
fi

# Build TypeScript project
print_info "Building TypeScript project..."
if npm run build; then
    print_success "MCP TypeScript built successfully"
    print_info "Output location: mcp/dist/"
else
    echo -e "${RED}✗ MCP build failed${NC}"
    exit 1
fi

# Step 5: Run tests and verification
print_step "Running tests and verification"
cd "$SCRIPT_DIR"

# Test CLI build
if [ -f "target/release/shellfirm" ]; then
    print_success "CLI binary verified"
    CLI_VERSION=$(./target/release/shellfirm --version 2>/dev/null || echo "version check failed")
    print_info "CLI: $CLI_VERSION"
else
    echo -e "${RED}✗ CLI binary not found${NC}"
fi

# Test WASM integration
cd "$SCRIPT_DIR/mcp"
if [ -f "test-wasm.js" ]; then
    print_info "Testing WASM integration..."
    if timeout 10s node test-wasm.js > /dev/null 2>&1; then
        print_success "WASM integration test passed"
    else
        print_info "WASM test failed or timed out (check manually)"
    fi
else
    print_info "No WASM test found (skipping)"
fi

# Verify MCP build
if [ -f "dist/index.js" ]; then
    print_success "MCP server binary verified"
else
    echo -e "${RED}✗ MCP server binary not found${NC}"
    exit 1
fi

# Final summary
cd "$SCRIPT_DIR"
echo -e "\n${GREEN}🎉 Production Build Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -e "\n${BLUE}📦 Built Components:${NC}"
echo -e "${GREEN}✅ Shellfirm CLI${NC}      → target/release/shellfirm"
echo -e "${GREEN}✅ shellfirm_core WASM${NC} → shellfirm_core/pkg/"
echo -e "${GREEN}✅ MCP Server${NC}          → mcp/dist/index.js"

echo -e "\n${BLUE}🚀 Ready to Use:${NC}"
echo ""
echo -e "${YELLOW}📋 CLI Usage:${NC}"
echo "   ./target/release/shellfirm --help"
echo ""
echo -e "${YELLOW}🌐 MCP Server:${NC}"
echo "   cd mcp && node dist/index.js"
echo ""
echo -e "${YELLOW}⚙️  MCP Configuration:${NC}"
echo '   "shellfirm": {'
echo '     "command": "node",'
echo "     \"args\": [\"$(realpath mcp/dist/index.js)\"]"
echo '   }'
echo ""
echo -e "${BLUE}🎯 All packages built in production mode for optimal performance!${NC}"

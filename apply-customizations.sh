#!/bin/bash

# Fuwari Customization Application Script
# This script applies personal customizations to a fresh Fuwari clone
# Author: Zakaria Farahi
# Date: 2024

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - Update these with your personal details
SITE_TITLE="No1V4"
SITE_SUBTITLE="A Place to Share My Thoughts"
SITE_URL="https://zakariaf.vercel.app/"
PROFILE_NAME="Zakaria Farahi"
PROFILE_BIO="Welcome To My Blog."
GITHUB_USERNAME="Zakaria-Farahi"
LINKEDIN_URL="https://www.linkedin.com/in/zakaria-farahi-b887ba286/"

# Primary color settings (OKLCH format)
PRIMARY_COLOR_LIGHT="oklch(0.59 0.23 28.61)"
PRIMARY_COLOR_DARK="oklch(0.59 0.23 28.61)"
BTN_CONTENT_LIGHT="oklch(0 0 1)"
BTN_CONTENT_DARK="oklch(1 0 0)"
CODEBLOCK_BG_LIGHT="oklch(0.2 0.015 var(--hue))"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if we're in a Fuwari directory
check_fuwari_directory() {
    if [ ! -f "package.json" ] || ! grep -q "fuwari" "package.json" 2>/dev/null; then
        print_error "This doesn't appear to be a Fuwari directory!"
        print_info "Please run this script from the root of a Fuwari repository."
        exit 1
    fi
    print_success "Fuwari directory detected"
}

# Function to backup files
backup_files() {
    print_info "Creating backups of files to be modified..."
    local backup_dir="backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    [ -f "src/config.ts" ] && cp "src/config.ts" "$backup_dir/"
    [ -f "src/styles/variables.styl" ] && cp "src/styles/variables.styl" "$backup_dir/"
    [ -f "astro.config.mjs" ] && cp "astro.config.mjs" "$backup_dir/"
    
    print_success "Backups created in $backup_dir/"
}

# Function to apply config.ts customizations
apply_config_customizations() {
    print_info "Applying customizations to src/config.ts..."
    
    local config_file="src/config.ts"
    
    if [ ! -f "$config_file" ]; then
        print_error "Config file not found: $config_file"
        return 1
    fi
    
    # Update site title (only in siteConfig section)
    sed -i "0,/title:.*/{s/title: \".*\"/title: \"$SITE_TITLE\"/}" "$config_file"
    
    # Update subtitle
    sed -i "0,/subtitle:.*/{s/subtitle: \".*\"/subtitle: \"$SITE_SUBTITLE\"/}" "$config_file"
    
    # Enable banner (only first occurrence in banner section)
    sed -i '/banner: {/,/^[[:space:]]*},/{s/enable: false,/enable: true,/}' "$config_file"
    
    # Update GitHub links
    sed -i "s|https://github.com/saicaca/fuwari|https://github.com/$GITHUB_USERNAME|g" "$config_file"
    
    # Use a more precise approach with awk to update profile section
    awk -v name="$PROFILE_NAME" -v bio="$PROFILE_BIO" '
        /^export const profileConfig/ { in_profile=1 }
        in_profile && /name: "/ && !name_updated { 
            sub(/name: ".*"/, "name: \"" name "\"")
            name_updated=1
        }
        in_profile && /bio: "/ && !bio_updated { 
            sub(/bio: ".*"/, "bio: \"" bio "\"")
            bio_updated=1
        }
        /^export const licenseConfig/ { in_profile=0 }
        { print }
    ' "$config_file" > "$config_file.tmp" && mv "$config_file.tmp" "$config_file"
    
    # Replace Twitter with LinkedIn in social links
    awk -v linkedin_url="$LINKEDIN_URL" '
        /name: "Twitter"/ { 
            gsub(/"Twitter"/, "\"Linkedin\"")
        }
        /icon: "fa6-brands:twitter"/ {
            gsub(/"fa6-brands:twitter"/, "\"fa6-brands:linkedin\"")
        }
        /url: "https:\/\/twitter.com"/ {
            sub(/url: "https:\/\/twitter.com"/, "url: \"" linkedin_url "\"")
        }
        { print }
    ' "$config_file" > "$config_file.tmp" && mv "$config_file.tmp" "$config_file"
    
    print_warning "Note: Please manually remove or update the Steam entry in social links if present"
    
    print_success "Config customizations applied"
}

# Function to apply color customizations
apply_color_customizations() {
    print_info "Applying color customizations to src/styles/variables.styl..."
    
    local style_file="src/styles/variables.styl"
    
    if [ ! -f "$style_file" ]; then
        print_error "Style file not found: $style_file"
        return 1
    fi
    
    # Update primary color (fixed orange/red tone instead of dynamic)
    sed -i "s|--primary: oklch(0.70 0.14 var(--hue)) oklch(0.75 0.14 var(--hue))|--primary: $PRIMARY_COLOR_LIGHT $PRIMARY_COLOR_DARK|g" "$style_file"
    
    # Update button content color (black/white instead of colored)
    sed -i "s|--btn-content: oklch(0.55 0.12 var(--hue)) oklch(0.75 0.1 var(--hue))|--btn-content: $BTN_CONTENT_LIGHT $BTN_CONTENT_DARK|g" "$style_file"
    
    # Update codeblock background
    sed -i "s|--codeblock-bg: oklch(0.17 0.015 var(--hue)) oklch(0.17 0.015 var(--hue))|--codeblock-bg: $CODEBLOCK_BG_LIGHT oklch(0.17 0.015 var(--hue))|g" "$style_file"
    
    # Remove codeblock-topbar-bg line if it exists
    sed -i '/--codeblock-topbar-bg:/d' "$style_file"
    
    # Update TOC badge colors
    sed -i "s|--toc-badge-bg: oklch(0.89 0.050 var(--hue))|--toc-badge-bg: oklch(0.9 0.045 var(--hue))|g" "$style_file"
    sed -i "s|--toc-btn-hover: oklch(0.926 0.015 var(--hue))|--toc-btn-hover: oklch(0.92 0.015 var(--hue))|g" "$style_file"
    
    print_success "Color customizations applied"
}

# Function to apply astro config customizations
apply_astro_config_customizations() {
    print_info "Applying customizations to astro.config.mjs..."
    
    local astro_config="astro.config.mjs"
    
    if [ ! -f "$astro_config" ]; then
        print_error "Astro config file not found: $astro_config"
        return 1
    fi
    
    # Update site URL
    sed -i "s|site: \"https://fuwari.vercel.app/\"|site: \"$SITE_URL\"|g" "$astro_config"
    
    print_warning "Note: This script does not modify the expressive-code integration."
    print_warning "If you want to replace it with astro-compress, please do it manually."
    print_info "The original setup uses expressive-code for syntax highlighting."
    
    print_success "Astro config URL updated"
}

# Function to display summary
display_summary() {
    echo ""
    echo "=========================================="
    echo "   Customization Application Complete"
    echo "=========================================="
    echo ""
    print_info "Summary of applied customizations:"
    echo "  ✓ Site title: $SITE_TITLE"
    echo "  ✓ Site subtitle: $SITE_SUBTITLE"
    echo "  ✓ Profile name: $PROFILE_NAME"
    echo "  ✓ GitHub username: $GITHUB_USERNAME"
    echo "  ✓ Custom color scheme applied"
    echo "  ✓ Site URL: $SITE_URL"
    echo ""
    print_warning "Manual review recommended for:"
    echo "  - Social links in src/config.ts"
    echo "  - Avatar and banner images in src/assets/images/"
    echo "  - Favicon in public/favicon/"
    echo ""
    print_info "Next steps:"
    echo "  1. Review the changes: git diff"
    echo "  2. Test locally: pnpm install && pnpm dev"
    echo "  3. Update images and assets as needed"
    echo "  4. Commit your changes"
    echo ""
}

# Main execution
main() {
    echo "=========================================="
    echo "  Fuwari Customization Application Script"
    echo "=========================================="
    echo ""
    
    # Check if we're in the right directory
    check_fuwari_directory
    
    # Ask for confirmation
    read -p "This will modify files in the current directory. Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Operation cancelled."
        exit 0
    fi
    
    # Create backups
    backup_files
    
    # Apply customizations
    apply_config_customizations
    apply_color_customizations
    apply_astro_config_customizations
    
    # Display summary
    display_summary
    
    print_success "All done! 🎉"
}

# Run main function
main

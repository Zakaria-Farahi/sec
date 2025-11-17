# Fuwari Customizations Documentation

This document details all the customizations made to the original Fuwari theme and provides instructions for applying them to a fresh Fuwari installation.

## Overview

This repository is a customized fork of [Fuwari](https://github.com/saicaca/fuwari), a static blog template built with Astro. The customizations focus on personal branding (names, links) and color scheme modifications.

## Customizations Summary

### 1. Personal Information (`src/config.ts`)

#### Site Configuration
- **Title**: Changed from `"Fuwari"` to `"No1V4"`
- **Subtitle**: Changed from `"Demo Site"` to `"A Place to Share My Thoughts"`
- **Banner**: Enabled (was `false`, now `true`)
- **Theme Hue**: Kept at `250` (purple/blue)

#### Profile Configuration
- **Name**: Changed from `"Lorem Ipsum"` to `"Zakaria Farahi"`
- **Bio**: Changed from `"Lorem ipsum dolor sit amet..."` to `"Welcome To My Blog."`
- **Avatar**: Using `assets/images/demo-avatar.png` (replace with your own)

#### Navigation Links
- **GitHub URL**: Updated to `https://github.com/Zakaria-Farahi`

#### Social Links
- **Replaced Twitter** with **LinkedIn**:
  - Name: `"Linkedin"`
  - Icon: `fa6-brands:linkedin`
  - URL: `https://www.linkedin.com/in/zakaria-farahi-b887ba286/`
- **Removed Steam** profile
- **Updated GitHub** profile URL to personal account

### 2. Color Scheme (`src/styles/variables.styl`)

The most significant customizations are in the color palette, creating a distinctive orange/red accent color theme:

#### Primary Colors
```styl
// Original (dynamic, hue-based)
--primary: oklch(0.70 0.14 var(--hue)) oklch(0.75 0.14 var(--hue))

// Customized (fixed orange/red tone)
--primary: oklch(0.59 0.23 28.61) oklch(0.59 0.23 28.61)
```

#### Button Content Colors
```styl
// Original (colored text)
--btn-content: oklch(0.55 0.12 var(--hue)) oklch(0.75 0.1 var(--hue))

// Customized (high contrast black/white)
--btn-content: oklch(0 0 1) oklch(1 0 0)
```

#### Code Block Styling
```styl
// Original
--codeblock-bg: oklch(0.17 0.015 var(--hue)) oklch(0.17 0.015 var(--hue))
--codeblock-topbar-bg: oklch(0.3 0.02 var(--hue)) oklch(0.12 0.015 var(--hue))

// Customized (slightly lighter, removed topbar variable)
--codeblock-bg: oklch(0.2 0.015 var(--hue)) oklch(0.17 0.015 var(--hue))
// --codeblock-topbar-bg removed
```

#### Table of Contents Styling
```styl
// Minor adjustments for better contrast
--toc-badge-bg: oklch(0.9 0.045 var(--hue)) var(--btn-regular-bg)
--toc-btn-hover: oklch(0.92 0.015 var(--hue)) oklch(0.22 0.02 var(--hue))
```

### 3. Site Configuration (`astro.config.mjs`)

#### Deployment URL
```js
// Original
site: "https://fuwari.vercel.app/"

// Customized
site: "https://zakariaf.vercel.app/"
```

#### Integration Changes
- **Removed**: `astro-expressive-code` integration with extensive customization
- **Added**: `astro-compress` for build optimization

Note: The original repo likely moved to a newer version of Fuwari that includes expressive-code. The customized version uses the older approach without it.

## How to Apply These Customizations

### Option 1: Using the Automated Script (Recommended)

1. **Clone the latest Fuwari repository**:
   ```bash
   git clone https://github.com/saicaca/fuwari.git my-blog
   cd my-blog
   ```

2. **Copy the customization script**:
   ```bash
   # Copy apply-customizations.sh to the Fuwari directory
   curl -o apply-customizations.sh https://raw.githubusercontent.com/Zakaria-Farahi/sec/main/apply-customizations.sh
   chmod +x apply-customizations.sh
   ```

3. **Edit the script** to update personal details:
   Open `apply-customizations.sh` and modify these variables at the top:
   ```bash
   SITE_TITLE="Your Site Title"
   SITE_SUBTITLE="Your Subtitle"
   SITE_URL="https://yoursite.com/"
   PROFILE_NAME="Your Name"
   PROFILE_BIO="Your bio"
   GITHUB_USERNAME="your-github-username"
   LINKEDIN_URL="https://linkedin.com/in/your-profile/"
   ```

4. **Run the script**:
   ```bash
   ./apply-customizations.sh
   ```

5. **Review the changes**:
   ```bash
   git diff
   ```

6. **Test locally**:
   ```bash
   pnpm install
   pnpm add sharp
   pnpm dev
   ```

### Option 2: Manual Application

#### Step 1: Update `src/config.ts`
```typescript
export const siteConfig: SiteConfig = {
  title: 'No1V4',  // Your site title
  subtitle: 'A Place to Share My Thoughts',  // Your subtitle
  // ... other settings
  banner: {
    enable: true,  // Enable the banner
    // ... rest of banner config
  },
}

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,
    LinkPreset.Archive,
    LinkPreset.About,
    {
      name: 'GitHub',
      url: 'https://github.com/Zakaria-Farahi',  // Your GitHub
      external: true,
    },
  ],
}

export const profileConfig: ProfileConfig = {
  avatar: 'assets/images/demo-avatar.png',
  name: 'Zakaria Farahi',  // Your name
  bio: 'Welcome To My Blog.',  // Your bio
  links: [
    {
      name: 'Linkedin',
      icon: 'fa6-brands:linkedin',
      url: 'https://www.linkedin.com/in/zakaria-farahi-b887ba286/',  // Your LinkedIn
    },
    {
      name: 'GitHub',
      icon: 'fa6-brands:github',
      url: 'https://github.com/Zakaria-Farahi',  // Your GitHub
    },
  ],
}
```

#### Step 2: Update `src/styles/variables.styl`

Find and replace these lines:

```styl
# Line ~26: Change primary color
--primary: oklch(0.59 0.23 28.61) oklch(0.59 0.23 28.61)

# Line ~30: Change button content color  
--btn-content: oklch(0 0 1) oklch(1 0 0)

# Line ~59: Update codeblock background
--codeblock-bg: oklch(0.2 0.015 var(--hue)) oklch(0.17 0.015 var(--hue))

# Remove the --codeblock-topbar-bg line if it exists

# Line ~92-94: Update TOC colors
--toc-badge-bg: oklch(0.9 0.045 var(--hue)) var(--btn-regular-bg)
--toc-btn-hover: oklch(0.92 0.015 var(--hue)) oklch(0.22 0.02 var(--hue))
```

#### Step 3: Update `astro.config.mjs`

```javascript
export default defineConfig({
  site: "https://zakariaf.vercel.app/",  // Your deployment URL
  // ... rest of config
})
```

## Color Scheme Explained

The custom color scheme uses the OKLCH color space, which provides perceptually uniform colors:

- **Primary Accent**: `oklch(0.59 0.23 28.61)` - A vibrant orange/red tone
  - Lightness: 0.59 (medium brightness)
  - Chroma: 0.23 (high saturation)
  - Hue: 28.61 (orange-red)

This creates a warm, energetic feel compared to the original dynamic purple/blue theme.

## Assets to Replace

Don't forget to replace these files with your own:

1. **Avatar**: `src/assets/images/demo-avatar.png`
2. **Banner**: `src/assets/images/demo-banner.png`
3. **Favicons**: Files in `public/favicon/`

## Testing Your Customizations

After applying customizations:

```bash
# Install dependencies
pnpm install
pnpm add sharp

# Run development server
pnpm dev

# Build for production
pnpm build

# Preview production build
pnpm preview
```

## Reverting Changes

If you used the automated script, backups were created in a `backup_YYYYMMDD_HHMMSS/` directory. To revert:

```bash
# Find your backup directory
ls -la | grep backup_

# Restore files
cp backup_YYYYMMDD_HHMMSS/config.ts src/
cp backup_YYYYMMDD_HHMMSS/variables.styl src/styles/
cp backup_YYYYMMDD_HHMMSS/astro.config.mjs .
```

## Additional Customizations

Beyond what's automated, you may want to:

1. Update the README files with your own information
2. Add your own blog posts in `src/content/posts/`
3. Customize the about page in `src/content/spec/about.md`
4. Update the license in `LICENSE` if needed
5. Configure deployment settings for your hosting platform

## Resources

- [Fuwari Official Repository](https://github.com/saicaca/fuwari)
- [Astro Documentation](https://docs.astro.build)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
- [OKLCH Color Picker](https://oklch.com/)
- [Icon Sets](https://icones.js.org/)

## Contributing

If you find issues with the customization script or want to suggest improvements, please open an issue or pull request.

## License

This customization script and documentation are provided as-is. The Fuwari template itself is licensed under its own terms (see the original repository).

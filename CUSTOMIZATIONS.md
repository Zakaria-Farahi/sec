# Repository Customizations Summary

This document details all the customizations made to the Fuwari blog template (excluding post content files).

## 📋 Configuration Changes

### 1. **src/config.ts** - Main Site Configuration

#### Site Information
- **Title**: Changed from `"Fuwari"` to `"No1V4"`
- **Subtitle**: Changed from `"Demo Site"` to `"A Place to Share My Thoughts"`
- **Theme Color Hue**: Kept at `250` (cyan/blue theme)
- **Language**: Kept as `"en"` (English)

#### Banner Settings
- **Banner Enable**: Changed from `false` to `true` (banner is now visible)
- **Banner Image**: Using `'assets/images/demo-banner.png'`
- **Banner Position**: Set to `'center'`

#### Navigation Bar
- **GitHub Link**: Changed from `"https://github.com/saicaca/fuwari"` to `"https://github.com/Zakaria-Farahi"`

#### Profile Configuration
- **Avatar**: Using `'assets/images/demo-avatar.png'`
- **Name**: Changed from `"Lorem Ipsum"` to `"Zakaria Farahi"`
- **Bio**: Changed from `"Lorem ipsum dolor sit amet..."` to `"Welcome To My Blog."`

#### Social Links
Replaced original links (Twitter, Steam) with:
- **LinkedIn**: `https://www.linkedin.com/in/zakaria-farahi-b887ba286/`
  - Icon: `fa6-brands:linkedin`
- **GitHub**: `https://github.com/Zakaria-Farahi`
  - Icon: `fa6-brands:github`

#### License
- Kept: CC BY-NC-SA 4.0 license

---

## 🌐 Deployment Configuration

### 2. **astro.config.mjs** - Astro Configuration

#### Site URL
- **Changed**: From `"https://fuwari.vercel.app/"` to `"https://zakariaf.vercel.app/"`

#### Build Configuration
- **Removed**: `expressiveCode` integration (code syntax highlighting plugin)
- **Removed**: Associated expressive-code plugins:
  - `pluginCollapsibleSections`
  - `pluginLineNumbers`
  - `pluginLanguageBadge`
  - `pluginCustomCopyButton`
- **Removed**: Import of `expressiveCodeConfig` from config
- **Added**: `Compress` integration from `astro-compress` package
  - CSS compression: Disabled
  - Image compression: Disabled

---

## 🎨 Styling & Design

### 3. **tailwind.config.cjs** - Tailwind CSS Configuration

No significant customizations detected. Using standard configuration with:
- Dark mode: `"class"`
- Custom font: Roboto
- Typography plugin enabled

---

## 🖼️ Assets & Media

### 4. **Custom Images in src/assets/images/**

Multiple image files present:
- `demo-avatar.png` - Profile avatar image
- `demo-banner.png` - Banner image (main)
- `demo-banne1r.png` - Alternative banner (typo in name?)
- `demo-banne2r.png` - Alternative banner (typo in name?)
- `d1emo-avatar.png` - Alternative avatar (typo in name?)

**Note**: Some files have typos in their names (e.g., "banne1r", "banne2r", "d1emo"). These might be duplicates or test files.

### 5. **Favicon Files in public/favicon/**

Custom favicon files:
- `favicon-light-180.png`
- `favicon-light-192.png`

---

## 📝 Content Customizations

### 6. **src/content/spec/about.md** - About Page

Completely customized with personal information:
- Introduction to Zakaria Farahi's blog
- Focus on CTF write-ups, cybersecurity research
- GitHub project showcase using `::github{repo="Zakaria-Farahi/sec"}`
- CTF & Cybersecurity journey section covering:
  - Pwn, Reverse Engineering, Cryptography
  - Web Security & Active Directory Attacks
  - OSINT
- Topics covered: HackTheBox, Course Notes, CTF Write-ups

---

## 📦 Package Configuration

### 7. **package.json**

- **Package Name**: Kept as `"fuwari"`
- **Version**: `"0.0.1"`

#### Removed Dependencies (compared to original template):
- ❌ `@expressive-code/core`
- ❌ `@expressive-code/plugin-collapsible-sections`
- ❌ `@expressive-code/plugin-line-numbers`
- ❌ `astro-expressive-code`

#### Added Dependencies:
- ✅ `@sveltejs/vite-plugin-svelte`
- ✅ `@vercel/analytics`
- ✅ `astro-compress`

#### Script Changes:
- **Removed**: `"check": "astro check"` script
- **Modified**: `"lint"` from `"biome check --write ./src"` to `"biome check --apply ./src"`

**Note**: Some dependency versions are older than the current template, suggesting this fork was created earlier and hasn't been fully updated to latest template versions.

---

## 🎨 CSS/Styling Customizations

### 8. **src/styles/main.css**

#### Added Custom Copy Button Styles:
```css
.copy-btn-icon {
    @apply absolute top-1/2 left-1/2 transition -translate-x-1/2 -translate-y-1/2
}
.copy-btn .copy-icon {
    @apply opacity-100 fill-white dark:fill-white/75
}
.copy-btn.success .copy-icon {
    @apply opacity-0 fill-[var(--deep-text)]
}
.copy-btn .success-icon {
    @apply opacity-0
}
.copy-btn.success .success-icon {
    @apply opacity-100
}
```

#### Removed Spoiler Tag Styling:
The original template has spoiler tag support, but this was removed in your version.

### 9. **src/styles/markdown.css**

#### Removed Features:
- Box decoration styling for inline code
- Link hover effects with dashed borders
- Copy button styling initialization

#### Modified:
- Pre/code block styling simplified to use background color and padding only
- Removed some advanced hover and decoration effects

### 10. **src/styles/expressive-code.css**

**Status**: ❌ **File Removed**
- This file exists in the original template but was removed in your version
- Related to the removal of the expressive-code features

---

## 🎯 Summary of Key Customizations

### Personal Branding
1. ✅ Site title: "No1V4"
2. ✅ Subtitle: "A Place to Share My Thoughts"
3. ✅ Author name: Zakaria Farahi
4. ✅ Bio: "Welcome To My Blog."
5. ✅ GitHub profile: Zakaria-Farahi
6. ✅ LinkedIn profile added

### Visual Changes
1. ✅ Banner enabled (was disabled in template)
2. ✅ Custom avatar image
3. ✅ Custom banner image(s)
4. ✅ Custom favicon images
5. ✅ Theme color hue: 250 (cyan/blue)
6. ✅ Custom copy button styling in CSS

### Deployment & Build
1. ✅ Vercel URL: zakariaf.vercel.app
2. ✅ Removed expressive-code features (syntax highlighting plugins)
3. ✅ Added Compress integration (with selective compression)
4. ✅ Added Vercel analytics

### Content
1. ✅ Custom About page focused on cybersecurity
2. ✅ Multiple blog posts (in src/content/posts/)
   - HTB-Certificate (with multiple images)
   - linuxprivesc (with multiple images)

### Code & Dependencies
1. ✅ Removed expressive-code dependencies
2. ✅ Added custom copy button styles
3. ✅ Simplified markdown styling
4. ✅ Added Vercel analytics integration
5. ✅ Modified lint script behavior

---

## 🔧 Recommended Actions

### Files to Review/Clean Up:
1. **Duplicate/typo files** in `src/assets/images/`:
   - `demo-banne1r.png` and `demo-banne2r.png` (not referenced in config)
   - `d1emo-avatar.png` (not referenced in config)
   - Consider removing these if they're not needed

### Configuration Files with Personal Info:
The main files containing your customizations are:
1. ✅ `src/config.ts` - All personal branding and links
2. ✅ `astro.config.mjs` - Deployment URL
3. ✅ `src/content/spec/about.md` - About page content
4. ✅ `src/assets/images/demo-avatar.png` - Your avatar
5. ✅ `src/assets/images/demo-banner.png` - Your banner
6. ✅ `public/favicon/` - Your favicon files

### When Migrating to New Template:
Copy these files and apply the configuration changes listed above to maintain your customizations.

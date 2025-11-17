# Files to Backup/Copy for Your Customizations

This is a quick reference list of files you need to backup or copy when migrating to a new template or fresh installation.

## 🔧 Configuration Files (MUST COPY)

### 1. Main Configuration
```
src/config.ts
```
**What to copy:**
- Site title: "No1V4"
- Subtitle: "A Place to Share My Thoughts"
- Banner settings (enabled, image path)
- Profile info (name: Zakaria Farahi, bio)
- Social links (LinkedIn, GitHub)
- Theme color (hue: 250)

### 2. Astro Configuration
```
astro.config.mjs
```
**What to copy:**
- Site URL: `https://zakariaf.vercel.app/`
- Note: Template uses expressive-code, you removed it - decide if you want to keep it removed or adopt the new version

### 3. Package Dependencies
```
package.json
```
**Dependencies you added:**
- `@vercel/analytics`
- `astro-compress`
- `@sveltejs/vite-plugin-svelte`

**Dependencies you removed:**
- All `@expressive-code/*` packages
- `astro-expressive-code`

---

## 🎨 Asset Files (MUST COPY)

### 4. Images
```
src/assets/images/demo-avatar.png     (your profile picture)
src/assets/images/demo-banner.png     (your banner image)
```

### 5. Favicons
```
public/favicon/favicon-light-180.png
public/favicon/favicon-light-192.png
```

---

## 📝 Content Files (MUST COPY)

### 6. About Page
```
src/content/spec/about.md
```
**Content:** Your complete cybersecurity-focused about page

---

## 🎨 Style Customizations (OPTIONAL - Review Before Copying)

### 7. CSS Files with Custom Changes

#### src/styles/main.css
**Custom additions:**
- Copy button styling (.copy-btn-icon, .copy-icon, .success-icon classes)

**Changes from template:**
- Removed spoiler tag support
- If you want spoiler tags back, copy the original version instead

#### src/styles/markdown.css
**Changes from template:**
- Simplified pre/code block styling
- Removed advanced hover effects
- Removed some box-decoration styling

**Decision needed:** Do you want the simplified version or the original with more features?

---

## 📋 Optional Files (Probably Don't Need)

### Files with Typos (Review & Clean Up)
```
src/assets/images/demo-banne1r.png   (not used - typo?)
src/assets/images/demo-banne2r.png   (not used - typo?)
src/assets/images/d1emo-avatar.png   (not used - typo?)
```
**Recommendation:** Delete these if they're not needed

---

## 🚀 Quick Migration Checklist

When setting up a fresh Fuwari template:

- [ ] 1. Copy `src/config.ts` settings (see section 1 above)
- [ ] 2. Update `astro.config.mjs` site URL
- [ ] 3. Copy your images to `src/assets/images/`
- [ ] 4. Copy your favicons to `public/favicon/`
- [ ] 5. Copy `src/content/spec/about.md`
- [ ] 6. Review package.json dependencies (Vercel analytics, compress)
- [ ] 7. DECISION: Keep or restore expressive-code features?
- [ ] 8. Review CSS customizations in main.css and markdown.css
- [ ] 9. Clean up typo image files

---

## ⚙️ Configuration Values Quick Reference

For easy copy-paste:

```typescript
// src/config.ts values
title: 'No1V4'
subtitle: 'A Place to Share My Thoughts'
themeColor.hue: 250
banner.enable: true
profile.name: 'Zakaria Farahi'
profile.bio: 'Welcome To My Blog.'

// Links
GitHub: 'https://github.com/Zakaria-Farahi'
LinkedIn: 'https://www.linkedin.com/in/zakaria-farahi-b887ba286/'

// astro.config.mjs
site: "https://zakariaf.vercel.app/"
```

---

## 📌 Important Notes

1. **Expressive Code**: The original template has advanced code syntax highlighting. You removed it. Consider if you want to keep it removed or adopt the new version.

2. **Dependencies**: Some of your dependency versions are older than the current template. Consider updating them.

3. **Typo Files**: You have several image files with typos in the names that aren't referenced in the config. Clean these up.

4. **Posts**: Your blog posts in `src/content/posts/` are excluded from this analysis as requested, but remember to copy them!

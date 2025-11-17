# Example Script Output

This document shows exactly what you'll see when running the customization script.

## Running the Script

```bash
./apply-customizations.sh
```

## Example Terminal Output

```
==========================================
  Fuwari Customization Application Script
==========================================

[SUCCESS] Fuwari directory detected

This will modify files in the current directory. Continue? (y/N) y

[INFO] Creating backups of files to be modified...
[SUCCESS] Backups created in backup_20251117_214053/

[INFO] Applying customizations to src/config.ts...
[WARNING] Note: Please manually remove or update the Steam entry in social links if present
[SUCCESS] Config customizations applied

[INFO] Applying color customizations to src/styles/variables.styl...
[SUCCESS] Color customizations applied

[INFO] Applying customizations to astro.config.mjs...
[WARNING] Note: This script does not modify the expressive-code integration.
[WARNING] If you want to replace it with astro-compress, please do it manually.
[INFO] The original setup uses expressive-code for syntax highlighting.
[SUCCESS] Astro config URL updated

==========================================
   Customization Application Complete
==========================================

[INFO] Summary of applied customizations:
  ✓ Site title: No1V4
  ✓ Site subtitle: A Place to Share My Thoughts
  ✓ Profile name: Zakaria Farahi
  ✓ GitHub username: Zakaria-Farahi
  ✓ Custom color scheme applied
  ✓ Site URL: https://zakariaf.vercel.app/

[WARNING] Manual review recommended for:
  - Social links in src/config.ts
  - Avatar and banner images in src/assets/images/
  - Favicon in public/favicon/

[INFO] Next steps:
  1. Review the changes: git diff
  2. Test locally: pnpm install && pnpm dev
  3. Update images and assets as needed
  4. Commit your changes

[SUCCESS] All done! 🎉
```

## What Gets Created

### Backup Directory
```
backup_20251117_214053/
├── config.ts           # Original config.ts
├── variables.styl      # Original variables.styl
└── astro.config.mjs    # Original astro.config.mjs
```

The timestamp in the directory name ensures each run creates a unique backup.

## Checking the Changes

After the script completes, you can review changes:

```bash
git diff src/config.ts
```

### Example Config Diff
```diff
-	title: "Fuwari",
-	subtitle: "Demo Site",
+	title: "No1V4",
+	subtitle: "A Place to Share My Thoughts",

-		enable: false,
+		enable: true,

-	name: "Lorem Ipsum",
-	bio: "Lorem ipsum dolor sit amet...",
+	name: "Zakaria Farahi",
+	bio: "Welcome To My Blog.",

-		name: "Twitter",
-		icon: "fa6-brands:twitter",
-		url: "https://twitter.com",
+		name: "Linkedin",
+		icon: "fa6-brands:linkedin",
+		url: "https://www.linkedin.com/in/zakaria-farahi-b887ba286/",
```

### Example Style Diff
```diff
-  --primary: oklch(0.70 0.14 var(--hue)) oklch(0.75 0.14 var(--hue))
+  --primary: oklch(0.59 0.23 28.61) oklch(0.59 0.23 28.61)

-  --btn-content: oklch(0.55 0.12 var(--hue)) oklch(0.75 0.1 var(--hue))
+  --btn-content: oklch(0 0 1) oklch(1 0 0)
```

## Testing Locally

After customization, test the site:

```bash
# Install dependencies
pnpm install
pnpm add sharp

# Start development server
pnpm dev
```

Output:
```
> fuwari@0.0.1 dev
> astro dev

  🚀  astro  v5.1.7 started in 234ms
  
  ┃ Local    http://localhost:4321/
  ┃ Network  use --host to expose
  
  ┃ ready in 1.8s
```

Visit http://localhost:4321 to see your customized blog!

## Reverting Changes

If you need to undo the changes:

### Option 1: Use the Backup
```bash
# Find your backup directory
ls -d backup_*

# Restore files
cp backup_20251117_214053/config.ts src/
cp backup_20251117_214053/variables.styl src/styles/
cp backup_20251117_214053/astro.config.mjs .
```

### Option 2: Git Checkout
```bash
# If you haven't committed yet
git checkout src/config.ts src/styles/variables.styl astro.config.mjs
```

### Option 3: Git Reset
```bash
# If you've committed but not pushed
git reset --hard HEAD~1
```

## Common Issues and Solutions

### Issue: "Not a Fuwari directory"
**Cause**: Running script outside a Fuwari repository

**Solution**: 
```bash
# Make sure you're in a Fuwari directory
git clone https://github.com/saicaca/fuwari.git my-blog
cd my-blog
./apply-customizations.sh
```

### Issue: "Permission denied"
**Cause**: Script not executable

**Solution**:
```bash
chmod +x apply-customizations.sh
./apply-customizations.sh
```

### Issue: Colors don't look right
**Cause**: Need to rebuild or clear cache

**Solution**:
```bash
# Clear build cache and rebuild
rm -rf node_modules/.astro dist
pnpm dev
```

## Visual Result

After applying customizations, your blog will have:

### Before (Original Fuwari)
- Title: "Fuwari"
- Subtitle: "Demo Site"  
- Profile: "Lorem Ipsum"
- Colors: Dynamic purple/blue theme
- Banner: Disabled

### After (Customized)
- Title: "No1V4"
- Subtitle: "A Place to Share My Thoughts"
- Profile: "Zakaria Farahi"
- Colors: Fixed orange/red theme (#ff5722 tone)
- Banner: Enabled
- Social: LinkedIn + GitHub links

## Next Steps After Success

1. **Replace Images**
   ```bash
   # Replace with your own images
   cp ~/my-avatar.png src/assets/images/demo-avatar.png
   cp ~/my-banner.png src/assets/images/demo-banner.png
   ```

2. **Update About Page**
   ```bash
   nano src/content/spec/about.md
   ```

3. **Add First Post**
   ```bash
   pnpm new-post my-first-post
   nano src/content/posts/my-first-post.md
   ```

4. **Build for Production**
   ```bash
   pnpm build
   ```

5. **Deploy**
   - Push to GitHub
   - Connect to Vercel/Netlify
   - Enjoy your customized blog! 🎉

## Script Execution Time

Typical execution time: **< 1 second**

The script is very fast because it only modifies a few configuration files using sed and awk.

## File Sizes

| File | Size | Purpose |
|------|------|---------|
| apply-customizations.sh | 8.0 KB | Main script |
| CUSTOMIZATIONS.md | 8.0 KB | Full documentation |
| QUICK-START.md | 4.3 KB | Quick guide |
| CHANGES-SUMMARY.md | 6.3 KB | Change reference |
| **Total** | **~27 KB** | Complete solution |

## Success Indicators

You know the script worked correctly when you see:

✅ `[SUCCESS] Config customizations applied`
✅ `[SUCCESS] Color customizations applied`  
✅ `[SUCCESS] Astro config URL updated`
✅ `[SUCCESS] All done! 🎉`
✅ Backup directory created
✅ `git diff` shows expected changes

## Full Workflow Example

Complete example from start to finish:

```bash
# 1. Clone fresh Fuwari
git clone https://github.com/saicaca/fuwari.git my-blog
cd my-blog

# 2. Get the script
curl -o apply-customizations.sh \
  https://raw.githubusercontent.com/Zakaria-Farahi/sec/main/apply-customizations.sh
chmod +x apply-customizations.sh

# 3. (Optional) Customize variables
nano apply-customizations.sh  # Edit personal info at top

# 4. Run the script
./apply-customizations.sh
# Press 'y' when prompted

# 5. Review changes
git diff

# 6. Install and test
pnpm install
pnpm add sharp
pnpm dev

# 7. Open browser to http://localhost:4321

# 8. If everything looks good, commit
git add .
git commit -m "Apply personal customizations"
git push
```

Total time: **~5 minutes** (most of which is `pnpm install`)

## Conclusion

The script provides a **fast, safe, and repeatable** way to apply your personal customizations to any version of Fuwari. With automatic backups and clear output, you can confidently migrate your customizations whenever Fuwari releases updates.

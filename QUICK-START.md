# Quick Start Guide - Applying Customizations

This guide will help you quickly apply your Fuwari customizations to a fresh clone of the latest Fuwari repository.

## Method 1: Using the Script (Recommended)

### Step 1: Clone Fresh Fuwari
```bash
git clone https://github.com/saicaca/fuwari.git my-blog
cd my-blog
```

### Step 2: Get the Customization Script
Download the script from this repository:
```bash
curl -o apply-customizations.sh https://raw.githubusercontent.com/Zakaria-Farahi/sec/main/apply-customizations.sh
chmod +x apply-customizations.sh
```

### Step 3: (Optional) Customize the Script
If you want different personal information, edit the script:
```bash
nano apply-customizations.sh
```

Edit these variables at the top:
```bash
SITE_TITLE="Your Title Here"
SITE_SUBTITLE="Your Subtitle"
PROFILE_NAME="Your Name"
GITHUB_USERNAME="your-github-username"
# ... etc
```

### Step 4: Run the Script
```bash
./apply-customizations.sh
```

The script will:
- ✅ Create automatic backups
- ✅ Apply all customizations
- ✅ Show a summary of changes

### Step 5: Review & Test
```bash
# Review changes
git diff

# Install dependencies
pnpm install
pnpm add sharp

# Test locally
pnpm dev
```

Visit `http://localhost:4321` to see your customized blog!

## Method 2: Manual Application

See [CUSTOMIZATIONS.md](CUSTOMIZATIONS.md) for detailed instructions on manual application.

## What Gets Changed?

### Personal Information
- Site title and subtitle
- Profile name and bio
- Social media links
- GitHub URLs

### Colors
- Primary theme color (orange/red tone)
- Button colors
- Code block styling
- Various UI elements

### Configuration
- Site deployment URL
- Banner enabled/disabled

## Troubleshooting

### Script fails with "Not a Fuwari directory"
Make sure you're running the script from the root of a Fuwari repository. Check that `package.json` exists and contains "fuwari".

### Changes don't look right
The script creates a backup directory with timestamp (e.g., `backup_20241117_123456/`). You can restore from there:
```bash
cp backup_YYYYMMDD_HHMMSS/* src/
```

### Want to undo everything
If you haven't committed yet:
```bash
git checkout src/config.ts src/styles/variables.styl astro.config.mjs
```

## Next Steps After Customization

1. **Replace Images**: 
   - Avatar: `src/assets/images/demo-avatar.png`
   - Banner: `src/assets/images/demo-banner.png`
   - Favicon: `public/favicon/`

2. **Update Content**:
   - Add your posts in `src/content/posts/`
   - Update the about page: `src/content/spec/about.md`

3. **Review Configuration**:
   - Social links in `src/config.ts`
   - Remove or update any unwanted links (e.g., Steam)

4. **Deploy**:
   - Push to GitHub
   - Connect to Vercel, Netlify, or your preferred platform
   - Update the site URL in `astro.config.mjs` if needed

## Customization Variables

The script uses these default values (edit them in the script):

```bash
SITE_TITLE="No1V4"
SITE_SUBTITLE="A Place to Share My Thoughts"
SITE_URL="https://zakariaf.vercel.app/"
PROFILE_NAME="Zakaria Farahi"
PROFILE_BIO="Welcome To My Blog."
GITHUB_USERNAME="Zakaria-Farahi"
LINKEDIN_URL="https://www.linkedin.com/in/zakaria-farahi-b887ba286/"

# Color values (OKLCH format)
PRIMARY_COLOR_LIGHT="oklch(0.59 0.23 28.61)"  # Orange-red
PRIMARY_COLOR_DARK="oklch(0.59 0.23 28.61)"
BTN_CONTENT_LIGHT="oklch(0 0 1)"  # Black
BTN_CONTENT_DARK="oklch(1 0 0)"   # White
```

## Color Customization

To use different colors, edit these variables in the script:

### Choose Your Primary Color
Use [oklch.com](https://oklch.com/) to pick colors:
- **Lightness** (0-1): How bright the color is
- **Chroma** (0-0.4): How saturated/vivid
- **Hue** (0-360): The color itself
  - 0° = Red
  - 30° = Orange (current)
  - 60° = Yellow
  - 120° = Green
  - 180° = Cyan
  - 240° = Blue
  - 300° = Magenta

Example colors:
```bash
# Blue theme
PRIMARY_COLOR="oklch(0.59 0.23 240)"

# Green theme
PRIMARY_COLOR="oklch(0.59 0.23 140)"

# Pink theme
PRIMARY_COLOR="oklch(0.59 0.23 330)"
```

## Support

For more detailed documentation, see:
- [CUSTOMIZATIONS.md](CUSTOMIZATIONS.md) - Full customization details
- [Original Fuwari README](https://github.com/saicaca/fuwari) - Fuwari documentation

## License

This script is provided as-is for your personal use with the Fuwari template.

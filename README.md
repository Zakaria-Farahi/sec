# 🍥 Fuwari - Customized Blog Template

This is a customized version of [Fuwari](https://github.com/saicaca/fuwari), a static blog template built with [Astro](https://astro.build).

## 🎨 What Makes This Different?

This repository contains:
- **Personal customizations** applied to the Fuwari theme
- **Automated script** to apply these customizations to fresh Fuwari clones
- **Comprehensive documentation** of all changes made

### Key Features
- ✅ Custom orange/red color scheme
- ✅ Personalized branding and information
- ✅ One-command migration script
- ✅ Detailed customization documentation

## 🚀 Quick Start

Want to apply these customizations to a fresh Fuwari installation?

```bash
# 1. Clone the latest Fuwari
git clone https://github.com/saicaca/fuwari.git my-blog
cd my-blog

# 2. Download and run the customization script
curl -o apply-customizations.sh https://raw.githubusercontent.com/Zakaria-Farahi/sec/main/apply-customizations.sh
chmod +x apply-customizations.sh
./apply-customizations.sh

# 3. Install and run
pnpm install && pnpm add sharp
pnpm dev
```

**See [QUICK-START.md](QUICK-START.md) for detailed instructions.**

## 📚 Documentation

- **[QUICK-START.md](QUICK-START.md)** - Fast setup guide
- **[CUSTOMIZATIONS.md](CUSTOMIZATIONS.md)** - Complete list of all customizations
- **[apply-customizations.sh](apply-customizations.sh)** - The automation script

## 🎨 Customizations Overview

### Personal Branding
- Site title: "No1V4"
- Profile: Zakaria Farahi
- Custom social links (LinkedIn, GitHub)

### Color Scheme
- Primary color: `oklch(0.59 0.23 28.61)` (Orange/Red)
- High-contrast button colors
- Custom code block styling

### Configuration
- Enabled banner
- Custom deployment URL
- Optimized settings

## 🔧 The Script

The `apply-customizations.sh` script automatically:
- ✅ Creates backups before any changes
- ✅ Updates personal information
- ✅ Applies custom color scheme
- ✅ Modifies configuration files
- ✅ Provides detailed summary

**Safe to run** - creates automatic backups and can be reverted!

---

## 📖 Original Fuwari README

> README version: `2024-09-10`

[**🖥️ Live Demo (Vercel)**](https://fuwari.vercel.app)&nbsp;&nbsp;&nbsp;/&nbsp;&nbsp;&nbsp;
[**📦 Old Hexo Version**](https://github.com/saicaca/hexo-theme-vivia)&nbsp;&nbsp;&nbsp;/&nbsp;&nbsp;&nbsp;
[**🌏 Original Repository**](https://github.com/saicaca/fuwari)

![Preview Image](https://raw.githubusercontent.com/saicaca/resource/main/fuwari/home.png)

## ✨ Features

- [x] Built with [Astro](https://astro.build) and [Tailwind CSS](https://tailwindcss.com)
- [x] Smooth animations and page transitions
- [x] Light / dark mode
- [x] Customizable theme colors & banner
- [x] Responsive design
- [ ] Comments
- [x] Search
- [ ] TOC

## 🚀 How to Use

1. [Generate a new repository](https://github.com/saicaca/fuwari/generate) from this template or fork this repository.
2. To edit your blog locally, clone your repository, run `pnpm install` AND `pnpm add sharp` to install dependencies.
   - Install [pnpm](https://pnpm.io) `npm install -g pnpm` if you haven't.
3. Edit the config file `src/config.ts` to customize your blog.
4. Run `pnpm new-post <filename>` to create a new post and edit it in `src/content/posts/`.
5. Deploy your blog to Vercel, Netlify, GitHub Pages, etc. following [the guides](https://docs.astro.build/en/guides/deploy/). You need to edit the site configuration in `astro.config.mjs` before deployment.

## ⚙️ Frontmatter of Posts

```yaml
---
title: My First Blog Post
published: 2023-09-09
description: This is the first post of my new Astro blog.
image: ./cover.jpg
tags: [Foo, Bar]
category: Front-end
draft: false
lang: jp      # Set only if the post's language differs from the site's language in `config.ts`
---
```

## 🧞 Commands

All commands are run from the root of the project, from a terminal:

| Command                             | Action                                           |
|:------------------------------------|:-------------------------------------------------|
| `pnpm install` AND `pnpm add sharp` | Installs dependencies                            |
| `pnpm dev`                          | Starts local dev server at `localhost:4321`      |
| `pnpm build`                        | Build your production site to `./dist/`          |
| `pnpm preview`                      | Preview your build locally, before deploying     |
| `pnpm new-post <filename>`          | Create a new post                                |
| `pnpm astro ...`                    | Run CLI commands like `astro add`, `astro check` |
| `pnpm astro --help`                 | Get help using the Astro CLI                     |

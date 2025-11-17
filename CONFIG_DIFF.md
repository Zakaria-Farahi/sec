# Configuration Differences - Side by Side

This document shows the exact differences between the original Fuwari template and your customizations.

## 📝 src/config.ts - Line by Line Comparison

### Site Configuration

```diff
export const siteConfig: SiteConfig = {
-  title: 'Fuwari',
+  title: 'No1V4',

-  subtitle: 'Demo Site',
+  subtitle: 'A Place to Share My Thoughts',

   lang: 'en',         // Same ✓
   
   themeColor: {
     hue: 250,         // Same ✓
     fixed: false,     // Same ✓
   },
   
   banner: {
-    enable: false,
+    enable: true,
     
     src: 'assets/images/demo-banner.png',   // Same ✓
     position: 'center',                      // Same ✓
     credit: {
       enable: false,   // Same ✓
       text: '',        // Same ✓
       url: ''          // Same ✓
     }
   },
   
   toc: {
     enable: true,      // Same ✓
     depth: 2           // Same ✓
   },
   
   favicon: [          // Same (empty array) ✓
     // Commented out
   ]
}
```

### Navigation Bar Configuration

```diff
export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,     // Same ✓
    LinkPreset.Archive,  // Same ✓
    LinkPreset.About,    // Same ✓
    {
      name: 'GitHub',
-     url: 'https://github.com/saicaca/fuwari',
+     url: 'https://github.com/Zakaria-Farahi',
      external: true,    // Same ✓
    },
  ],
}
```

### Profile Configuration

```diff
export const profileConfig: ProfileConfig = {
  avatar: 'assets/images/demo-avatar.png',  // Same ✓

-  name: 'Lorem Ipsum',
+  name: 'Zakaria Farahi',

-  bio: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.',
+  bio: 'Welcome To My Blog.',

  links: [
    {
-     name: 'Twitter',
-     icon: 'fa6-brands:twitter',
-     url: 'https://twitter.com',
+     name: 'Linkedin',
+     icon: 'fa6-brands:linkedin',
+     url: 'https://www.linkedin.com/in/zakaria-farahi-b887ba286/',
    },
-   {
-     name: 'Steam',
-     icon: 'fa6-brands:steam',
-     url: 'https://store.steampowered.com',
-   },
    {
      name: 'GitHub',
      icon: 'fa6-brands:github',
-     url: 'https://github.com/saicaca/fuwari',
+     url: 'https://github.com/Zakaria-Farahi',
    },
  ],
}
```

### License Configuration

```diff
export const licenseConfig: LicenseConfig = {
  enable: true,                                      // Same ✓
  name: 'CC BY-NC-SA 4.0',                          // Same ✓
  url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/',  // Same ✓
}
```

---

## 🌐 astro.config.mjs - Key Differences

### Site Configuration

```diff
export default defineConfig({
-  site: "https://fuwari.vercel.app/",
+  site: "https://zakariaf.vercel.app/",

  base: "/",              // Same ✓
  trailingSlash: "always", // Same ✓
```

### Integrations

```diff
  integrations: [
    tailwind({          // Same ✓
      nesting: true,
    }),
    swup({              // Same ✓
      theme: false,
      animationClass: "transition-swup-",
      containers: ["main", "#toc"],
      smoothScrolling: true,
      cache: true,
      preload: true,
      accessibility: true,
      updateHead: true,
      updateBodyClass: false,
      globalInstance: true,
    }),
    icon({              // Same ✓
      include: {
        "preprocess: vitePreprocess(),": ["*"],
        "fa6-brands": ["*"],
        "fa6-regular": ["*"],
        "fa6-solid": ["*"],
      },
    }),
-   expressiveCode({     // REMOVED IN YOUR VERSION
-     themes: [...],
-     plugins: [...],
-     ...config
-   }),
    svelte(),           // Same ✓
    sitemap(),          // Same ✓
+   Compress({          // ADDED IN YOUR VERSION
+     CSS: false,
+     Image: false,
+     Action: {
+       Passed: async () => true,
+     },
+   }),
  ],
```

### Markdown & Rehype Plugins

```diff
  markdown: {
    remarkPlugins: [
      remarkMath,                              // Same ✓
      remarkReadingTime,                       // Same ✓
      remarkExcerpt,                           // Same ✓
      remarkGithubAdmonitionsToDirectives,     // Same ✓
      remarkDirective,                         // Same ✓
      remarkSectionize,                        // Same ✓
      parseDirectiveNode,                      // Same ✓
    ],
    rehypePlugins: [
      rehypeKatex,                            // Same ✓
      rehypeSlug,                             // Same ✓
      [
        rehypeComponents,                      // Same ✓
        {
          components: {
            github: GithubCardComponent,       // Same ✓
            note: (x, y) => AdmonitionComponent(x, y, "note"),         // Same ✓
            tip: (x, y) => AdmonitionComponent(x, y, "tip"),           // Same ✓
            important: (x, y) => AdmonitionComponent(x, y, "important"), // Same ✓
            caution: (x, y) => AdmonitionComponent(x, y, "caution"),   // Same ✓
            warning: (x, y) => AdmonitionComponent(x, y, "warning"),   // Same ✓
          },
        },
      ],
      [
        rehypeAutolinkHeadings,               // Same ✓
        { ...config }
      ],
    ],
  },
```

---

## 📦 package.json - Dependency Differences

### Dependencies Added by You

```json
"@sveltejs/vite-plugin-svelte": "^4.0.4",
"@vercel/analytics": "^1.4.1",
"astro-compress": "^2.3.6",
```

### Dependencies Removed by You

```json
"@expressive-code/core": "^0.41.3",
"@expressive-code/plugin-collapsible-sections": "^0.41.3",
"@expressive-code/plugin-line-numbers": "^0.41.3",
"astro-expressive-code": "^0.41.3",
```

### Scripts Modified

```diff
  "scripts": {
    "dev": "astro dev",
    "start": "astro dev",
    "build": "astro build && pagefind --site dist",
    "preview": "astro preview",
    "astro": "astro",
+   "type-check": "tsc --noEmit --isolatedDeclarations",
    "new-post": "node scripts/new-post.js",
    "format": "biome format --write ./src",
-   "lint": "biome check --write ./src",
+   "lint": "biome check --apply ./src",
    "preinstall": "npx only-allow pnpm"
  },
```

---

## 📝 src/content/spec/about.md - Complete Rewrite

### Original Template:

```markdown
# About
This is the demo site for [Fuwari](https://github.com/saicaca/fuwari).

::github{repo="saicaca/fuwari"}

> ### Sources of images used in this site
> - [Unsplash](https://unsplash.com/)
> - [星と少女](https://www.pixiv.net/artworks/108916539) by [Stella](https://www.pixiv.net/users/93273965)
> - [Rabbit - v1.4 Showcase](https://civitai.com/posts/586908) by [Rabbit_YourMajesty](https://civitai.com/user/Rabbit_YourMajesty)
```

### Your Version:

```markdown
# About  
This is the personal blog of [Zakaria Farahi](https://github.com/Zakaria-Farahi), where I share my experiences, CTF write-ups, cybersecurity research, and technical insights.  

## 🔗 Projects & Contributions  
Check out my projects on GitHub:  

::github{repo="Zakaria-Farahi/sec"}

## 🏴 CTF & Cybersecurity Journey  
I actively participate in Capture The Flag (CTF) competitions, focusing on:  
- **Pwn, Reverse Engineering, and Cryptography**  
- **Web Security & Active Directory Attacks**  
- **OSINT**  

## 📚 Topics Covered  
🔹 HackTheBox Machines | 🔹 Courses Notes | 🔹 CTF Write-up | 🔹 More  

Stay tuned for more posts on cybersecurity techniques and challenges!
```

---

## 🎨 CSS Changes Summary

### src/styles/main.css

**Added:**
- Custom copy button styling (`.copy-btn-icon`, `.copy-icon`, `.success-icon`)

**Removed:**
- Spoiler tag support styling

### src/styles/markdown.css

**Simplified:**
- Pre/code block styling (removed box-decoration-break, advanced hover effects)

### src/styles/expressive-code.css

**Status:** ❌ Completely removed (related to expressive-code removal)

---

## 📊 Summary Statistics

| Category | Changes Made |
|----------|-------------|
| **Configuration Values** | 7 changed |
| **Social Links** | 2 removed, 1 added (LinkedIn) |
| **Dependencies** | 3 added, 4 removed |
| **Integrations** | 1 added (Compress), 1 removed (expressiveCode) |
| **Content Files** | 1 completely rewritten (About) |
| **CSS Files** | 3 modified |
| **Image Assets** | 5 added (2 favicons, 3 main images) |

**Total Customizations:** ~25+ individual changes across the repository

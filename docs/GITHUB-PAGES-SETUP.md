---
layout: default
title: GitHub Pages Setup Instructions
---

# GitHub Pages Setup Instructions

This repository is configured to support GitHub Pages with Mermaid.js diagram rendering.

## 📋 Files Created

1. **`_config.yml`** - Jekyll configuration with Kramdown markdown processor
2. **`_layouts/default.html`** - Custom layout that loads Mermaid.js from CDN
3. **`index.md`** - Entry point that includes the README content

## 🚀 Enable GitHub Pages

### Step 1: Push the Configuration Files

```bash
git add _config.yml _layouts/default.html index.md docs/GITHUB-PAGES-SETUP.md
git commit -m "Add GitHub Pages support with Mermaid.js rendering"
git push origin main
```

### Step 2: Enable GitHub Pages in Repository Settings

1. Go to your GitHub repository
2. Click **Settings** tab
3. Scroll down to **Pages** section (left sidebar)
4. Under **Source**, select:
   - **Source**: Deploy from a branch
   - **Branch**: `main` (or `master`)
   - **Folder**: `/ (root)`
5. Click **Save**

### Step 3: Wait for Deployment

- GitHub will automatically build and deploy your site
- This usually takes 1-2 minutes
- You'll see a green checkmark when ready
- The site URL will be: `https://<username>.github.io/<repository-name>/`

## 🎨 Customization Options

### Change Theme

Edit `_config.yml` and update the theme:

```yaml
# Choose one of these themes:
theme: jekyll-theme-minimal
# theme: jekyll-theme-cayman
# theme: jekyll-theme-slate
# theme: jekyll-theme-architect
# theme: jekyll-theme-tactile
```

### Customize Mermaid Appearance

Edit `_layouts/default.html` and modify the `mermaid.initialize()` configuration:

```javascript
mermaid.initialize({ 
  startOnLoad: true,
  theme: 'default',  // Options: 'default', 'dark', 'forest', 'neutral'
  themeVariables: {
    primaryColor: '#0066cc',      // Customize colors
    primaryTextColor: '#333',
    // ... more customization options
  }
});
```

### Update Site Metadata

Edit `_config.yml`:

```yaml
title: Your Custom Title
description: Your custom description
repository: username/repository-name
```

## ✅ Verify Mermaid Rendering

After GitHub Pages is deployed:

1. Visit your GitHub Pages URL
2. Scroll to the **Architecture** section
3. You should see the diagram rendered as an interactive SVG
4. The diagram should be fully functional with proper formatting

## 🔧 Troubleshooting

### Diagrams Not Rendering?

**Check browser console** (F12):
- Look for Mermaid.js loading errors
- Ensure CDN is accessible

**Verify configuration**:
```bash
# Check if files exist
ls -la _config.yml _layouts/default.html index.md
```

**Clear GitHub Pages cache**:
1. Make a small change to `_config.yml`
2. Commit and push
3. Wait for rebuild

### Build Errors?

Check the **Actions** tab in your GitHub repository:
- Click on the latest "pages-build-deployment" workflow
- Review error messages
- Common issues:
  - Invalid YAML in `_config.yml`
  - Missing theme
  - Permission issues

### Alternative: Use GitHub Actions for Deployment

If automatic deployment doesn't work, you can use GitHub Actions:

1. Create `.github/workflows/pages.yml`:

```yaml
name: Deploy GitHub Pages

on:
  push:
    branches: ["main"]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v4
      - uses: actions/jekyll-build-pages@v1
      - uses: actions/upload-pages-artifact@v3

  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/deploy-pages@v4
        id: deployment
```

2. In repository settings → Pages → Source, select "GitHub Actions"

## 📚 Additional Resources

- [GitHub Pages Documentation](https://docs.github.com/en/pages)
- [Jekyll Documentation](https://jekyllrb.com/docs/)
- [Mermaid.js Documentation](https://mermaid.js.org/)
- [Supported Jekyll Themes](https://pages.github.com/themes/)

## 🧪 Test Locally (Optional)

To test the site locally before pushing:

```bash
# Install Ruby and Jekyll
gem install bundler jekyll

# Create Gemfile
cat > Gemfile <<EOF
source 'https://rubygems.org'
gem 'github-pages', group: :jekyll_plugins
EOF

# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Visit: http://localhost:4000
```

## 📝 Notes

- **Mermaid diagrams** will render on both GitHub (native support) and GitHub Pages (via our custom layout)
- **Relative links** in the README will work correctly on GitHub Pages
- **Theme** can be changed anytime by editing `_config.yml`
- **Build time** for GitHub Pages is typically 1-2 minutes after each push

---

**Status**: Configuration complete ✅  
**Next Step**: Push files and enable GitHub Pages in repository settings  
**Expected Result**: Mermaid diagrams will render on your GitHub Pages site

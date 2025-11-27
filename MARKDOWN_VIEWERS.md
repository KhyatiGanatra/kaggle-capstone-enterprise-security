# Applications That Can Render Markdown (.md) Files

Since Cursor's reading pane has issues with Google Drive files, here are alternative applications you can use to view and edit Markdown files.

## Native macOS Applications

### 1. **TextEdit** (Built-in)
- **Location**: `/Applications/TextEdit.app`
- **Pros**: Already installed, simple
- **Cons**: Basic rendering, not syntax-highlighted
- **Usage**: Right-click `.md` file → "Open With" → TextEdit

### 2. **Preview** (Built-in)
- **Location**: `/Applications/Preview.app`
- **Pros**: Already installed, good for viewing
- **Cons**: Read-only, no editing
- **Usage**: Convert to PDF first, or use Quick Look (spacebar)

### 3. **Quick Look** (Built-in)
- **Shortcut**: Select file and press `Spacebar`
- **Pros**: Instant preview, no app needed
- **Cons**: Read-only, basic rendering
- **Note**: May need a Quick Look plugin for better Markdown rendering

## Professional Markdown Editors

### 4. **Marked 2** (Paid, ~$14)
- **Website**: https://marked2app.com/
- **Pros**: Excellent rendering, live preview, export to PDF/HTML
- **Cons**: Paid application
- **Best for**: Professional writing and documentation

### 5. **MacDown** (Free, Open Source)
- **Website**: https://macdown.uranusjr.com/
- **Pros**: Free, live preview, syntax highlighting
- **Cons**: Not actively maintained (but still works)
- **Best for**: Free alternative with good features

### 6. **Mark Text** (Free, Open Source)
- **Website**: https://marktext.app/
- **Pros**: Free, modern UI, real-time preview, supports GitHub Flavored Markdown
- **Cons**: Can be resource-intensive
- **Best for**: Modern, feature-rich free editor

### 7. **Typora** (Paid, ~$15)
- **Website**: https://typora.io/
- **Pros**: WYSIWYG editing, beautiful rendering, export options
- **Cons**: Paid application
- **Best for**: Writing-focused workflow

### 8. **iA Writer** (Paid, ~$30)
- **Website**: https://ia.net/writer
- **Pros**: Distraction-free writing, excellent typography
- **Cons**: Expensive, minimal features
- **Best for**: Focused writing

## Code Editors with Markdown Support

### 9. **VS Code** (Free)
- **Website**: https://code.visualstudio.com/
- **Pros**: Free, excellent Markdown preview, extensions available
- **Cons**: Full IDE, may be overkill
- **Usage**: Install "Markdown Preview Enhanced" extension
- **Note**: Since Cursor is based on VS Code, this should work similarly

### 10. **Sublime Text** (Free with nag screen, Paid license)
- **Website**: https://www.sublimetext.com/
- **Pros**: Fast, lightweight, good Markdown plugins
- **Cons**: Paid license for commercial use
- **Usage**: Install "MarkdownEditing" package

### 11. **Atom** (Free, Open Source - Discontinued but still works)
- **Website**: https://atom.io/
- **Pros**: Free, extensible, good Markdown support
- **Cons**: No longer maintained by GitHub
- **Usage**: Built-in Markdown preview

## Terminal/Command-Line Tools

### 12. **glow** (Free, CLI)
- **Install**: `brew install glow`
- **Usage**: `glow README.md`
- **Pros**: Beautiful terminal rendering, works with Google Drive files
- **Cons**: Terminal-only, no editing
- **Best for**: Quick viewing in terminal

### 13. **mdcat** (Free, CLI)
- **Install**: `brew install mdcat`
- **Usage**: `mdcat README.md`
- **Pros**: Terminal rendering with colors
- **Cons**: Terminal-only

### 14. **pandoc** (Free, CLI)
- **Install**: `brew install pandoc`
- **Usage**: `pandoc README.md -o README.html && open README.html`
- **Pros**: Convert to HTML/PDF/other formats
- **Cons**: Conversion only, not a viewer

### 15. **bat** (Free, CLI)
- **Install**: `brew install bat`
- **Usage**: `bat README.md`
- **Pros**: Syntax highlighting in terminal
- **Cons**: Basic rendering, not full Markdown preview

## Web-Based Viewers

### 16. **GitHub/GitLab**
- **Usage**: Push to repository, view on web
- **Pros**: Perfect rendering, accessible anywhere
- **Cons**: Requires Git repository

### 17. **Markdown Viewer** (Browser Extension)
- **Chrome**: https://chrome.google.com/webstore
- **Firefox**: https://addons.mozilla.org/
- **Pros**: View `.md` files directly in browser
- **Cons**: Browser extension required

## Recommended Solutions for Your Use Case

### For Quick Viewing (Google Drive Files)
1. **glow** (CLI) - Fast, works with Google Drive files
   ```bash
   brew install glow
   glow README.md
   ```

2. **MacDown** (GUI) - Free, handles Google Drive files well
   ```bash
   brew install --cask macdown
   ```

3. **Mark Text** (GUI) - Modern, free, good Google Drive support
   ```bash
   brew install --cask mark-text
   ```

### For Professional Documentation
1. **Marked 2** - Best rendering and export options
2. **Typora** - Best WYSIWYG editing experience

### For Terminal Workflow
1. **glow** - Beautiful terminal rendering
2. **bat** - Quick syntax-highlighted viewing

## Quick Installation Commands

```bash
# Install glow (terminal viewer)
brew install glow

# Install MacDown (GUI editor)
brew install --cask macdown

# Install Mark Text (modern GUI editor)
brew install --cask mark-text

# Install bat (syntax highlighting)
brew install bat

# Install pandoc (converter)
brew install pandoc
```

## Testing with Your Files

After installing any of these, test with your problematic files:

```bash
# Using glow
glow README.md
glow CHANGELOG.md
glow DELETE_DEPLOYMENTS.md

# Using bat
bat README.md

# Using MacDown (GUI)
open -a MacDown README.md

# Using Mark Text (GUI)
open -a "Mark Text" README.md
```

## Setting Default Application

To set a default app for `.md` files:

```bash
# Set MacDown as default
duti -s com.uranusjr.MacDown .md all

# Or use Finder:
# 1. Right-click a .md file
# 2. "Get Info"
# 3. "Open with" → Select app
# 4. Click "Change All..."
```

## Comparison Table

| Application | Free | GUI | Terminal | Google Drive Compatible | Best For |
|------------|------|-----|----------|------------------------|----------|
| glow | ✅ | ❌ | ✅ | ✅ | Quick viewing |
| MacDown | ✅ | ✅ | ❌ | ✅ | Free GUI editor |
| Mark Text | ✅ | ✅ | ❌ | ✅ | Modern free editor |
| Marked 2 | ❌ | ✅ | ❌ | ✅ | Professional docs |
| Typora | ❌ | ✅ | ❌ | ✅ | WYSIWYG editing |
| VS Code | ✅ | ✅ | ❌ | ⚠️ | Full IDE |
| bat | ✅ | ❌ | ✅ | ✅ | Syntax highlighting |

## My Recommendation

For your specific case (Google Drive files that Cursor can't open):

1. **Primary**: Install **glow** for quick terminal viewing
   ```bash
   brew install glow
   glow README.md
   ```

2. **Secondary**: Install **Mark Text** for GUI editing
   ```bash
   brew install --cask mark-text
   ```

3. **Alternative**: Use **MacDown** if you prefer a simpler GUI
   ```bash
   brew install --cask macdown
   ```

These three options should handle all your Markdown viewing needs without the Google Drive extended attributes issues that Cursor has.


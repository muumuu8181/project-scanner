# Project Scanner

A Python tool for analyzing project structure and generating HTML reports.

## Features

- Scan all files and folders in a directory
- Count lines of code per file
- Statistics by file extension
- Extract first N and last N lines of each file (skipping empty lines)
- Extract Python functions and classes using AST
- Concatenate files by extension
- Generate HTML reports (overview + detail)

## Usage

```bash
# Basic scan
python scanner.py /path/to/project

# Specify output directory
python scanner.py /path/to/project --output ./reports

# Customize head/tail lines
python scanner.py /path/to/project --head 5 --tail 5

# Include file concatenation
python scanner.py /path/to/project --concat

# Concatenate specific extensions only
python scanner.py /path/to/project --concat --concat-ext .py .js
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `path` | Target directory to scan | (required) |
| `--output`, `-o` | Output directory | `./output` |
| `--head` | Number of first lines to extract | 3 |
| `--tail` | Number of last lines to extract | 3 |
| `--concat` | Enable file concatenation | disabled |
| `--concat-ext` | Extensions to concatenate | all |

## Output

- `index.html` - Overview report (statistics, file list, functions, classes)
- `detail.html` - Detail report (head/tail lines for each file)
- `concat/` - Concatenated files by extension (if `--concat` enabled)

## Requirements

- Python 3.8+
- No external dependencies (uses only standard library)

---

## Development Rules (AI Handoff Protocol)

This project uses AI-assisted development. The following rules ensure seamless handoff between sessions.

### Version Management
- **Increment version by 0.01** for each update (e.g., 0.1 → 0.11 → 0.12)
- Version is defined in `scanner.py` as `__version__`
- Version is displayed in HTML report (top-right corner)

### Handoff Documentation
Always maintain documentation so **anyone can continue development at any time**:

1. **Obsidian Dev Log**: `20260105_project_scanner_devlog.md`
   - Location: `C:\Users\user\Desktop\work\60_obsidian\test_sync\`
   - Contains: User requirements (verbatim), technical decisions, work log with timestamps

2. **Current Status** (update after each change):
   - Latest version: Check `__version__` in scanner.py
   - Last update: Check git log
   - Pending tasks: See "Future Work" section below

### Before Ending a Session
- Commit all changes to git
- Push to GitHub
- Update Obsidian dev log with:
  - What was done (with timestamp)
  - Current state
  - Next steps if any

### Technical Decisions Log
| Decision | Reason | Date |
|----------|--------|------|
| Not using Sphinx | Too heavy for this use case; requires conf.py, module import structure. AST is simpler for static analysis. | 2026-01-05 |
| Python AST for function extraction | No import needed, lightweight, works on any .py file | 2026-01-05 |

---

## Future Work

- [ ] JavaScript/TypeScript function extraction
- [ ] Markdown output format
- [ ] Config file support
- [ ] Exclude patterns customization

## License

MIT

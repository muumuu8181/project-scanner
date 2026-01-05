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

## License

MIT

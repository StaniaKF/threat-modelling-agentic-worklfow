# Tutorials

Step-by-step notebooks that explain the key patterns used in this project.

| Notebook | What it covers |
|---|---|
| [`threat_identification.ipynb`](./threat_identification.ipynb) | Building the Threat Identifier agent from scratch: client setup, Agent + RunConfig, streaming, MCP filesystem server, tracing, programmatic validation, retry loop |

---

## Setting up Jupyter

### 1. Install Jupyter

Jupyter is included in the project's dev dependencies. If you've already run `make install` from the project root, it's already available in your virtual environment — no extra step needed.

### 2. VS Code (recommended)

Install the **Jupyter** extension:

- Open the Extensions panel (`Cmd+Shift+X`)
- Search for `ms-toolsai.jupyter` and install it
- Reload VS Code

Open `threat_identification.ipynb` directly in VS Code — it will render as an interactive notebook.

### 3. Selecting the kernel

The kernel is the Python environment that executes the cells. You need to select the project's virtual environment so that `openai-agents`, `openai`, and `python-dotenv` are available.

In VS Code:
1. Open the notebook
2. Click **Select Kernel** in the top-right corner (or the kernel name if one is already selected)
3. Choose **Python Environments…**
4. Select the interpreter inside `.venv/` (usually shown as `Python 3.x.x ('.venv': venv)`)

In classic Jupyter:
```bash
# Start Jupyter from the project root with the venv active
source .venv/bin/activate
jupyter notebook tutorials/threat_identification.ipynb
```

### 4. Running cells

- **Run a single cell**: `Shift+Enter` (moves focus to the next cell) or `Ctrl+Enter` (stays on current cell)
- **Run all cells**: Kernel menu → **Restart & Run All**
- **Clear outputs**: Kernel menu → **Restart & Clear Output**

---

## Environment variables

The notebooks use the same `.env` file as the main project. Make sure it exists in the project root (`4_without_coordinator/.env`) with:

```
LITELLM_API_BASE_URL=http://...
LITELLM_API_KEY=...
NPX_PATH=/path/to/npx     # optional, defaults to "npx" on PATH
```

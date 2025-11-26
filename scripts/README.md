# Automated Demo Launcher Scripts

This folder contains automated scripts to launch both Alice and Bob GUIs simultaneously for easy demonstration.

## 📁 Scripts

| Script | Platform | Description |
|--------|----------|-------------|
| `run_demo.ps1` | Windows (PowerShell) | Launches both GUIs in separate PowerShell windows |
| `run_demo.sh` | Linux | Launches both GUIs using detected terminal emulator |
| `run_demo_mac.sh` | macOS | Launches both GUIs in separate Terminal windows |

---

## 🚀 Usage

### Windows (PowerShell)

```powershell
# From project root
.\scripts\run_demo.ps1

# Or navigate to scripts folder
cd scripts
.\run_demo.ps1
```

**Note:** If you get an execution policy error, run this first:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### Linux

```bash
# From project root
./scripts/run_demo.sh

# Or navigate to scripts folder
cd scripts
./run_demo.sh
```

**Supported Terminal Emulators:**
- gnome-terminal (GNOME)
- xfce4-terminal (XFCE)
- konsole (KDE)
- xterm (fallback)

**Make executable (if needed):**
```bash
chmod +x scripts/run_demo.sh
```

---

### macOS

```bash
# From project root
./scripts/run_demo_mac.sh

# Or navigate to scripts folder
cd scripts
./run_demo_mac.sh
```

**Make executable (if needed):**
```bash
chmod +x scripts/run_demo_mac.sh
```

---

## ✨ What the Scripts Do

1. **Detect Environment**
   - Check for virtual environment (uses it if available)
   - Fall back to system Python if no venv found

2. **Validate Files**
   - Verify `alice_gui.py` and `bob_gui.py` exist
   - Show error if scripts are missing

3. **Launch Alice GUI**
   - Opens in new terminal/window
   - Server mode (will listen on port 3000 by default)
   - Stays open after script ends

4. **Launch Bob GUI** (after 2-second delay)
   - Opens in new terminal/window
   - Client mode (will connect to localhost:3000)
   - Stays open after script ends

5. **Display Instructions**
   - Shows next steps for demo
   - Provides helpful tips

---

## 📋 Demo Workflow

After running the launcher script:

### In Alice's Window:
1. Click **"Generate Keys"** (wait ~10-20 seconds)
2. Optionally change port (if 3000 is blocked, use 5000)
3. Click **"Start Server"**
4. Wait for Bob to connect

### In Bob's Window:
1. Click **"Generate Keys"** (wait ~10-20 seconds)
2. Verify connection settings (localhost:3000)
3. Click **"Connect to Alice"**
4. Keys exchange automatically ✅

### Communication:
- Type messages in the "Send Message" box
- Click **"Encrypt & Send"**
- Click **"Refresh"** to see new messages
- Messages are encrypted with RSA!

---

## 🔧 Troubleshooting

### Port 3000 Blocked (Windows)
**Error:** "Permission denied" or "Port already in use"  
**Solution:** In Alice's GUI, change port to 5000 before starting server

### Script Won't Run (Windows)
**Error:** "Execution policy" error  
**Solution:** 
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Script Won't Run (Linux/Mac)
**Error:** "Permission denied"  
**Solution:**
```bash
chmod +x scripts/run_demo.sh
chmod +x scripts/run_demo_mac.sh
```

### No Terminal Found (Linux)
**Error:** "No supported terminal emulator found"  
**Solution:** Install one of these:
- `sudo apt install gnome-terminal` (Ubuntu/Debian)
- `sudo dnf install gnome-terminal` (Fedora)
- `sudo pacman -S xterm` (Arch)

### Virtual Environment Not Found
**Warning:** "Virtual environment not found, using system Python"  
**Solution:** Either:
1. Create venv: `python -m venv rsa_tcp_impl_env`
2. Or ignore - system Python works fine (no external deps needed)

---

## 💡 Tips

1. **Run from Project Root:** Scripts work from any directory but recommend running from project root
2. **Both Windows Open:** Each GUI opens in its own window for side-by-side demo
3. **Manual Refresh:** Click "Refresh" button to see new messages (great for demo control)
4. **Color Coded:** Alice = Blue theme, Bob = Yellow theme
5. **Pre-generate Keys:** Generate keys before demo to save time

---

## 🎯 Quick Demo (5 minutes)

```powershell
# Windows - PowerShell
.\scripts\run_demo.ps1

# Linux
./scripts/run_demo.sh

# macOS
./scripts/run_demo_mac.sh
```

Then follow the on-screen instructions! 🎉

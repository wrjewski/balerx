# README demo. Run from the repository root with `balerx` on PATH:
#
#   sudo mkdir -p /home/demo
#   sudo cp -a docs/demo/home/. /home/demo
#   sudo unshare --uts bash -c 'hostname demo; vhs docs/demo.tape'
#
# The scan report prints the machine hostname. The UTS namespace keeps that
# label as `demo`. Paths stay under /home/demo.

Output docs/assets/demo.gif

Set Shell bash
Set FontFamily "JetBrains Mono"
Set FontSize 15
Set Width 1000
Set Height 1080
Set Padding 16
Set Theme "Catppuccin Mocha"
Set Framerate 10
Set TypingSpeed 45ms

Hide
Type "export HOME=/home/demo USER=demo LOGNAME=demo HOSTNAME=demo RUST_LOG=error" Enter
Type "export PS1='$ '" Enter
Type "cd /home/demo && clear" Enter
Show

Type "balerx --version" Sleep 400ms Enter
Sleep 1.2s

Type "balerx scan" Sleep 300ms Enter
Sleep 6s

Type "balerx doctor" Sleep 300ms Enter
Sleep 3s

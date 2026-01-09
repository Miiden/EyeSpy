Creating README for setting up a lab for testing EyeSpy


PreReqs

Windows 10/11 Eval Virtual Machine
I used VirtualBox so i could use Linked Bases and have 2 machines with alternating setups
Baisc Auth and Digest Auth - 4 Cameras.


Install ffmpeg https://www.ffmpeg.org/download.html

Clone and set up IPCameraEmulatorstd.exe https://github.com/inspiredtechnologies/IP-Camera-Emulator-Standard
- MP4 for streaming


Install and set up MediaMTX https://github.com/bluenviron/mediamtx
- Yaml File
- - 189: rtspAuthMethods: [digest]
  - 167: rtspAddress: :8554
  - 64: user: service
  - 66: pass: service
- MP4 for streaming
- PS1 script for easy running

Install Wireshark for Packet analysis


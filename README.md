## Bluetooth-Low-Energy-Attack: BLE Sniffing with Windows - Bettercap Contribution 

<img src="https://i.imgur.com/qAb668m.jpeg" alt="MLH-banner" width="100%" height="500px">

💻Bluetooth low energy sniffer automation Python script💻 Analysing data packets from BLE devices using "Bluefruit LE Sniffer - Bluetooth Low Energy (BLE 4.0) - nRF51822"

---

## Buy the "Bluefruit LE Sniffer - Bluetooth Low Energy (BLE 4.0) - nRF51822" device in: https://www.adafruit.com/product/2269

## Set Up "Bluefruit LE Sniffer - Bluetooth Low Energy (BLE 4.0) - nRF51822" to computer

First, make sure you have Wireshark installed on your Windows machine(This setup doesn't work on Windows VM's)

<h4><strong>Set Up Step by Step instruction with images</strong></h4>
<h6>all this steps where gotten from the Adafruit website instructions: https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer/using-with-sniffer-v2-and-python3</h6>

1.Go to this website "https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers?tab=downloads" and Download the "CP210x Universal Windows Driver".

<img src="https://i.imgur.com/UApwvy2.png" alt="MLH-banner" width="50%" height="50%">

2. Go to the folder where the zip was downloaded and extract the zip there or whatever location you want. After extracting right-click the extracted folder and copy the path of the folder, you will need it.

<img src="https://i.imgur.com/b5QY3zZ.png" alt="MLH-banner" width="50%" height="50%">

3. After copying the folder path, go to Device Manager and you should see that the USB needs to install the necessary drivers.

<img src="https://i.imgur.com/CmXh3BC.png" alt="MLH-banner" width="50%" height="50%">

4. Right-click the displayed name, in this case for me is the one named "CP2102N USB to UART Bridge Controller" and go to properties.

<img src="https://i.imgur.com/Ram6Vhw.png" alt="MLH-banner" width="50%" height="50%">

5. Then, in properties click on "Update Driver.." and select the option "Browse my computer for drivers". There in the field "Search for drivers in this location", paste the path you copied from the extracted folder and click Next. You Successfully updated the Drivers! 👻🥳🙌

<img src="https://i.imgur.com/zdaoxAr.png" alt="MLH-banner" width="50%" height="50%">

6. You will notice that the "Silicon Labs CP210x USB to UART Bridge(COM3)" will be in the "Ports (COM & LPT)"

<img src="https://i.imgur.com/w4ZNhrX.png" alt="MLH-banner" width="50%" height="50%">

7. Now, install Python on your computer, in this case, I download it in the Microsoft Store.
   After downloading it, open a new command prompt and use command:
   ```bash
   python3
   ```
   it will show just like the second picture.
   You will notice that it will not let us "import serial"
   Therefore, we will need to install it:
   First, exit the python command line using command:
   ```bash
   exit()
   ```
   Then to install, use command:
   ```bash
   pip install pyserial
   ```
   If we enter the Python command line interface now we are going to be able to import serial.

<img src="https://i.imgur.com/gwWt5As.png" alt="MLH-banner" width="50%" height="50%">
<img src="https://i.imgur.com/gaEEQ8R.png" alt="MLH-banner" width="50%" height="50%">

<h4>If you still cant import serial, just like what just happened to me in the previous step 😅</h4>
Then, you might need to install pyserial directly where your python is installed.
in my cose I would solve it using this command:
format is: python_executable -m pip install pyserial
In my case:

```bash
C:\Users\brill\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install pyserial
```

<img src="https://i.imgur.com/0KrUaOC.png" alt="MLH-banner" width="50%" height="50%">

8. Go to this link: "https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE/Download?lang=en#infotabs" and download the "nrf_sniffer_for_bluetooth_le_4.1.1.zip" and go to the folder you download it and extract all the zip.

   <img src="https://i.imgur.com/LdSeq8u.png" alt="MLH-banner" width="50%" height="50%">

9. Now open the folder you extracted and go to the folder that is inside that is called "extcap". Inside the "extcap" folder, you will see a "nrf_sniffer_ble" that is a batch script. We will run this in some second in the command prompt.
    
   <img src="https://i.imgur.com/67cvIcz.png" alt="MLH-banner" width="50%" height="50%">
   <img src="https://i.imgur.com/4r3SIxO.png" alt="MLH-banner" width="50%" height="50%">

10. Right-click inside the "extcap" folder where we found the "nrf_sniffer_ble" and in the path where it says in my case "Downloads > nrf_sniffer_for_bluetooth_le_4.1.1 > extcap" replace tha path and just write "cmd" and press Enter key (This will redirect you to the command prompt inside that folder, you can use whatever method you want to go inside that folder)
    In that command prompt inside the "extcap" folder, we would use this command in order to execute that batch file "nrf_sniffer_ble" that we found on that folder:

    ```bash
    nrf_sniffer_ble.bat
    ```

    It will tell you to run a command in order to install the necessary things, in my case they want me to do this command but it will vary for you:

    ```bash
    C:\Users\brill\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.11_qbz5n2kfra8p0\python.exe -m pip install -r requirements.txt
    ```

    <img src="https://i.imgur.com/5GLWDMz.png" alt="MLH-banner" width="50%" height="50%">

    <strong>The command will install the necessary import in order for wireshark to communicate with the sniffer device</strong>

    Now if you use command to run the batch file again, you will get a messae "No arguments given!" meaning that you followed correctly the instructions:

    ```bash
    nrf_sniffer_ble.bat
    ```

11. Open WireShark and go to "Help" and then "About Wireshark". After that, go to the "Folders" tab. then, find the extcap path just as it is pointed in the red arrow and double-click that path. After double-clicking it will say "Should the directory be created?" and click yes. The directory created will open up after clicking yes, stay in that folder.

<img src="https://i.imgur.com/jXzFXAA.gif" alt="MLH-banner" width="50%" height="50%">
<img src="https://i.imgur.com/Omntk1J.gif" alt="MLH-banner" width="50%" height="50%">

12. Now, put on one side the extcap folder that was inside the folder we extracted from the downloaded zip and put it on the left side of your screen. On the right side of your screen, put the folder that was created after selecting yes.

<strong>It should look like this:</strong>

<img src="https://i.imgur.com/91knVhX.png" alt="MLH-banner" width="50%" height="50%">

After that, copy everything from the extcap folder of the left-side to the extcap folder of the right side, it should look like this:

<img src="https://i.imgur.com/q4o3iAl.png" alt="MLH-banner" width="50%" height="50%">

<strong>Now close everything and Reboot your Computer 🫡👻</strong>

Now If you start Wireshark, you will see that our interface for BLE will display and now we can double click on the BLE interface in order to start sniffing Bluetooth devices around us.

<img src="https://i.imgur.com/0GM5pKZ.png" alt="MLH-banner" width="50%" height="50%">

# Python - BLE Packet filtering logic

Our script improves BLE security assessments on Windows by implementing a specialized tshark filter to ignore BLE advertising packets. This refinement allows security analysts to concentrate on the more significant packets for penetration testing.

The rationale behind our filtering approach is to create a tshark display filter that negates conditions which match the common PDU types indicative of BLE advertising (ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND, etc.). By excluding packets with these PDU types, the filter simplifies packet analysis, enabling a more focused examination of BLE traffic that could be pertinent for security analyses.

The constructed filter syntax for tshark is as follows:

```bash
    "!(btle.advertising_header.pdu_type == 0x00 || btle.advertising_header.pdu_type == 0x02 || btle.advertising_header.pdu_type == 0x04 || btle.advertising_header.pdu_type == 0x06)"
```

This command, when used with tshark, will display all BLE packets except those with the specified PDU types, essentially omitting the common advertising packets. It enhances efficiency by limiting the volume of traffic to analyze and enabling analysts to focus on potentially vulnerable packets.

By including this filter in our Python script, we offer users a streamlined experience for BLE packet analysis on Windows platforms, leveraging Bettercap's capabilities with the precision of Tshark's filtering features. This makes it a valuable contribution to the community, enhancing the effectiveness of security professionals' workflow when working with BLE devices.

## Set-Up Bettercap(Our Modified code of Bettercap) and Run the code of this Repository


<h4>Step 1: Install WSL</h4>

* Open PowerShell as Administrator and run:

```bash
wsl --install
```

The command will install WSL with default Ubuntu distribution. Once installed, launch WSL by typing "wsl" in the Windows search menu or with the powershell command:

```bash
wsl
```

<h4>Step 2: Update and Upgrade your packages</h4>

* After Launching WSL, move to the right directory with command:

```bash
cd
```
  
* Now update and upgrade your packages using this command:

```bash
sudo apt update && sudo apt upgrade
```

<h4>Step 3: Install Go Environment(This will allow our Go code of Bettercap to be compiled)</h4>

```bash
sudo apt install golang-go
```

<h4>Step 4: Install Bettercap required libraries</h4>

* According to Betttercap documentation, this Open Source needs certain dependencies installed in the system in order for the code to compile successfully

This are the required dependencies according to https://www.bettercap.org/installation/:

-libpcap
-libusb-1.0-0 (required by the HID module)
-libnetfilter-queue (on Linux only, required by the packet.proxy module

Use this command to install the above dependencies listed:

```bash
sudo apt install libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev
```

<h4>Step 5: Configure Go Environment</h4>

* In order to Set-up your Go environment you will need to add some environment variables to your .bashrc or .profile file:

Open the profile file using the default text editor of Linux called "nano", and use the command:

```bash
nano ~/.profile
```

Once you are inside the file go all the bottom of that file and add this to there:

```bash
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```

Save by pressing Ctrl+O and to exit Ctrl+X.

* Then to apply the changes use the command:

```bash
source ~/.profile
```


<h4>Step 6: Verify Go Installation</h4>

* Check Go is installed by using the command:

```bash
go version
```

<h4>Step 7: Download this code and Compile and Sniff BLE packets</h4>

* Now is the time to use this repository in order to Sniff BLE packets using Tshark with the "Bluefruit LE Sniffer - Bluetooth Low Energy (BLE 4.0) - nRF51822" device and compile it and run it using Bettercap's code

First, Make sure you have Git installed. After that, clone the repository using this command:

```bash
git clone git@github.com:joshuaquibin/CECS-378-Fall-23-Group-6.git
```

Now move to the repository folder using command:

```bash
cd CECS-378-Fall-23-Group-6
```

Then use this command to go to the Bettercap forked repository:

```bash
cd net-sniff-bettercap
```

Now, use this command to compile all the code of Bettercap:

```bash
go build .
```

After that, use this command to start using Betttercap:

```bash
sudo ./bettercap -caplet http-ui
```

You will see that you entered intothe Comand Line Interface of bettercap and may see errors or warnings. Use this command to solve those errors and warnings:

```bash
caplets.update
```

* Now is the time to set-up the BLE Sniffing! 🦈

On the Command line Interface of Bettercap use this command in order to set the source where you want the Bettercap to get the information from. For this one we just use "" in order to indicate that we are not going to use any Json source path. So, the command is:

```bash
set ble.sniff.source ""
```

then, we have to specify the interface we will be using that we set-up before in order for the "Bluefruit LE Sniffer - Bluetooth Low Energy (BLE 4.0) - nRF51822" to work with Wireshark. In our case the interface was "nRF Sniffer for Bluetooth LE COM3", so we will use the command:

```bash
set ble.sniff.interface "nRF Sniffer for Bluetooth LE COM3"
```

Now, usually Wireshark when installed its files will be on the path "Program Files/Wireshark". Inside the Wireshark forlder there is a "tshark.exe" that is the actual Tshark program. We will give Bettercap that path in order for it to sniff BLE packets with the Tshark we integrated in the code. Use the command:

```bash
set ble.sniff.tshark "/mnt/c/Program Files/Wireshark/tshark.exe"
```

Now finally we can start the Program to sniff BLE packets!!! 👻🐧

Use this command to start the sniffing:

```bash
ble.sniff on
```

<h6>This will start sniffing non stop, use Ctrl+C to stop the Sniffing</h6>

<h4>Step 8: Start GUI - Bettercap BLE Sniffing</h4>

Use this command in the Windows machine in order to forward you WSL into your host machine:

```bash
netsh interface portproxy add v4tov4 listenport=80 listenaddress=127.0.0.1 connectport=[PORT] connectaddress=172.22.104.164
```

Now, in WSL:

```bash
sudo ./bettercap -caplet http-ui
```
Then,

```bash
caplets.update
```

Now in order for the GUI to work use:

```bash
ui.update
```

Now exit the Bettercap:

```bash
exit
```

Finally, now start the program again:

```bash
sudo ./bettercap -caplet http-ui
```

In your host's machine web browser enter this website🌐:

```bash
http://localhost/#/events
```

And you should be able to see this Website

<img src="https://i.imgur.com/s4vr5hi.png" alt="MLH-banner" width="50%" height="50%">

After that, go to the "Advanced" tab:

<img src="https://i.imgur.com/nqN4IeF.png" alt="MLH-banner" width="50%" height="50%">

On the left side go to "ble.sniff":

<img src="https://i.imgur.com/TzmP2zW.png" alt="MLH-banner" width="50%" height="50%">

* Make sure "extcap nRF Sniffer interface" matches you interface. In this case mine is "nRF Sniffer for Bluetooth LE COM3"
* Also, make sure "location of tshark command" matches to the location of the .exe of your Tshark. In my case it is "/mnt/c/Program Files/Wireshark/tshark.exe"

MAKE SURE TO SAVE THOSE CHANGES( SAVE IT BY CLICKING IN THE BUTTON THAT THE RIGHT ARROW IS POINTING)

So it would look like this:

<img src="https://i.imgur.com/etphTor.png" alt="MLH-banner" width="70%" height="50%">

Now start sniffing by clicking the "ble.sniff on" button:

<img src="https://i.imgur.com/NQkx8Wh.png" alt="MLH-banner" width="50%" height="50%">

Now, wait a few seconds until the device starts blinking rapidly in yellow.

Go to the "Events" Tab on the top left corner, and you will notice that the packets will start appearing in the GUI 👻🍹:

<img src="https://i.imgur.com/Hjrly5X.png" alt="MLH-banner" width="50%" height="50%">

If you want to stop the sniffing you just go to where you did the sniff on, you will find the "ble.sniff off" button.


## Relevant Sources used:

BLE:

https://www.bluetooth.com/specifications/specs/?keyword=core+specification
https://learn.adafruit.com/introduction-to-bluetooth-low-energy/gap
https://novelbits.io/intro-bluetooth-low-energy-version-2/
https://novelbits.io/

Wireshark:

https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html
https://ask.wireshark.org/questions/

Install-WSL:

https://learn.microsoft.com/en-us/windows/wsl/install

Learn-Go:

https://go.dev/tour/welcome/1
https://go.dev/doc/tutorial/getting-started

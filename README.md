# PyBitmessage Noisebot

### Noisebot sends randomly-timed noise messages via the PyBitmessage API.

- Noisebot creates temporary secret chans using random keys, sends messages to the secret chans, then eventually cleans up the fake messages and deletes the chans.

- Such fake messages are called _noise._ Adding noise to the network makes more work for malicious traffic analysis. Blackhat hackers, criminals, and spooks need to do more work to try sorting fake messages from real messages when noise is mixed in.

- Attackers can't tell the difference between real and fake messages. Noise strengthens anonymity on the network.

### Warning:

If API is configured with apinotify path prior to install noisebot will erase that configuration and replace it with the noisebot configuration. One would need to edit noisebot source to fire more than one script with apinotifypath. Noisebot is designed to run on its own Bitmessage daemon but a little tweaking can make it play nice in a multiple plugin setup. Noisebot does this to ensure keys.dat errors don't hang up Bitmessage while noisebot is running.

# Installation:

- Shut down PyBitmessage. It must be closed for installation hook.
- Copy the noisebot script to the PyBitmessage /src/ directory.
- Enable the Bitmessage API in your keys.dat file. Add API credentials.
- Set permissions on noisebot.py as executable so it can run as a program.
- Run noisebot from the command line to install. **[$ python noisebot.py]**
- On Linux **[$ ./noisebot.py]** should do.
- Restart PyBitmessage.
- A Linux binary is included under the /binary/ folder for zero dependencies.

Noisebot will add the proper API configuration. Noisebot will detect your API credentials on each run.

After the first run noisebot will run in the background when Bitmessage is running. When you receive a message to your inbox the noisebot will activate. To activate it immediately send a blank message to yourself. There is no need to invoke it from the command line after install.

Use is subject to the SSSS License included herewith. Licensee may choose between MIT, BSD, and Apache licenses. See LICENSE for details.

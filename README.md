# CallStackMasker

This repository demonstrates a PoC technique for dynamically spoofing call stacks using timers. Prior to our implant sleeping, we can queue up timers to overwrite its call stack with a fake one and then restore the original before resuming execution. Hence, in the same way we can mask memory belonging to our implant during sleep, we can also mask the call stack of our main thread.

For a full technical walkthrough see the accompanying blog post here: https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers/.

By default the PoC will mimic a static call stack taken from spoolsv.exe:

![call_stack_masker_static](https://user-images.githubusercontent.com/108275364/218521821-0b0dfa07-e56f-4741-ae59-464e35a50b78.png)

If the `--dynamic` flag is provided, CallStackMasker will enumerate all the accessible threads, find one in the desired state (WaitForSingleObjectEx), and mimic its call stack and start address. This is demonstrated below:

![call_stack_masker_dynamic_1](https://user-images.githubusercontent.com/108275364/218522095-1fad0f7d-0903-4c95-91ac-05bf068aad20.png)
![call_stack_masker_dynamic_3](https://user-images.githubusercontent.com/108275364/218522043-f98c3399-8265-4735-9861-2aeddf2346c8.png)

NB As a word of caution, this PoC was tested on the following Windows build:

22h2 (19045.2486)

It has not been tested on any other versions and may break on different Windows builds.

# Credit
* Ekk0 for the sleep obfuscation technique this PoC is based on (https://github.com/Cracked5pider/Ekko).
* WithSecureLabs' CallStackSpoofer (https://github.com/WithSecureLabs/CallStackSpoofer) & TickTock (https://github.com/WithSecureLabs/TickTock) for example code on manipulating call stacks.
* Hunt-Sleeping-Beacons (https://github.com/thefLink/Hunt-Sleeping-Beacons) for example thread enumeration code.

# What is a hook, why do they need to be bypassed?

On Windows, we have something called the **Windows API** *(WinApi/Windows.h)* and the **Native API** *(NtApi/ntdll.dll)*, **Windows API** is a wrapper around the **Native API**, these provide functions not normally accessible (as most transfer to the Kernel). For example, if we call **CreateFile**, It'll follow this routine;

``CreateFile (Kernel32.dll) > NtCreateFile (ntdll.dll) -> Kernel -> Return STATUSCODE``

Now, a hook can be set on any of the calls in the sequence, a usermode hook in this example could be set on either **CreateFile** or **NtCreateFile** *(More likely on NtCreateFile as this is the underlying Kernel translation)*, a usermode hook cannot be set on the Kernel calls.

The most common hooks will be set at the start of the function eg; a couple bytes replaced at the start of the ``ntdll.dll`` function re-routing the call to that EDR/AntiCheat's own handler 

Now, the flaw with this is that these hooks are only called if you make calls through that processes API and it passes through their DLL's, instead of overcomplicating and risking unhooking, we can instead make calls directly to the Kernel through **SSN's**.

To do this, we need something called an **SSN** *(Syscall Number)*, we can find these in DLL's like ``ntdll.dll``, each syscall has its own number, if you have the number you can call it directly through a stub, without passing through any user-mode APIs (This will NOT bypass Kernel hooks, but these are much rarer)

So, using this concept our call looks like this;

``NtCreateFile (Own process Stub) -> Kernel -> Return STATUSCODE``

This effectively bypasses any hooks set within the userspace, though this will do nothing against Kernel hooks on the SSDT

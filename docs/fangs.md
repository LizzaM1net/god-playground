# Fangs

What it is: The worker executable that performs the primary runtime injection.

Why it is: Required to load tweaks into target processes.

Role: Implements process attachment, execution control, and tweak injection logic.

How it is used: Spawned at boot by the bootstrap (godmfi-launch).

Optional: No.

# Inline images, message bubbles and a stable inspector

Images should behave as chat messages: receive automatically from the connected
peer, display verified previews inline, and offer Save image independently of
transfer. Keep the current authenticated/chunked image protocol and its bounds.
The GUI accepts into a private temporary directory owned by PeerService, so
images survive disconnect/reconnect but disappear on service shutdown. Saved
copies remain. The GUI never displays unverified incoming image data.

Drop a local image file into the history or composer to prepare its preview;
Send image sends it using the existing validated path. Preserve text drafts.
Use the pinned tkinterdnd2 package and its public existing-root integration.
Reject multiple files/unsupported drops clearly instead of guessing paths.

Incoming messages use gray bubbles on the left; outgoing messages use blue
bubbles on the right. Text and images share chronological history and keyboard
selection. Keep semantic text in the native Text history for inspection/copy;
reuse embedded bubble widgets to avoid rebuilding500widgets on each message.
Preserve the100image/500message and16thumbnail bounds.

Keep a horizontal, reserved security pane visible from startup. Selecting a
message updates its contents without moving the divider or overriding an
explicit hide choice. Users can resize the divider and hide/show the pane.

Alternative considered: protocol-wide unconditional file delivery. Retaining
the existing offer/accept exchange internally avoids wire/version changes and
preserves independently tested transfer validation; only the GUI interaction
changes. RAM-only buffering would duplicate large image buffers; bounded
streaming to runtime-only private storage preserves existing image limits.

Verify temporary storage lifetime and saved byte equality, auto-receive during
attachment preparation, native drop parsing, draft preservation, bubble
direction/color, focus/scroll/selection, compact layouts, hidden-pane choice,
and actual two-peer delivery. Native DnD source:
[tkinterdnd2](https://pypi.org/project/tkinterdnd2/).

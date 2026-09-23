namespace ClarionDebugger.Disassembly
{
    /// <summary>
    /// The Disassembly view's SEAT LIFECYCLE, with every field private and every change a named transition
    /// (ticket 8f352618). A seat is: asked for (<see cref="SeatingTid"/>), possibly awaiting the registers
    /// that say WHERE to seat (<see cref="AwaitRegs"/>), and finally PAINTED (<see cref="SeatedTid"/>) - or
    /// completed with nothing to decode (<see cref="EmptyTid"/>).
    ///
    /// WHY THIS IS A TYPE. The same seven pieces of state used to be written by ten members of
    /// DisassemblyView, and the rules for clearing them were stated in prose at six sites. Three pipeline
    /// rounds in a row each found a defect of one shape: a field right at the site that set it and wrong at
    /// a site that read it or failed to clear it (the painted flag advanced on INTENT; the banner reading the
    /// intended thread instead of the painted one; the painted flag outliving an erased listing). Here the
    /// only way to change a field is a transition, so a reader can see the whole machine in one file.
    ///
    /// WHAT IS NOT HERE, deliberately. The stopped and selected thread ids are caches of ENGINE state
    /// (ticket 1ab6be61 owns where that truth lives), so they are PARAMETERS to the transitions that need
    /// them, never fields. And the uint? -> uint conversion is DisassemblyView.TidOf's alone: every tid
    /// handed in here has already been through it, so 0 is always "unknown".
    ///
    /// No WinForms, no service, no I/O: tools\test-disasm-seat.ps1 compiles this file as it ships and
    /// drives the transitions directly.
    /// </summary>
    internal sealed class SeatState
    {
        /// <summary>What a fresh-window (WinTag) reply turned out to be, which is what the view needs to
        /// decide whether the location strip still describes anything.</summary>
        public enum WindowOutcome
        {
            Seated,      // it decoded something; the replying thread is now PAINTED
            EmptySeat,   // a SEAT came back empty: that thread's current address could not be decoded
            EmptySeek,   // a non-seat request (a coarse seek) came back empty: says nothing about a thread
        }

        // Bumped whenever the answer to "whose execution point is this?" changes. It is carried in the
        // request TAG, which the engine echoes verbatim, so a reply can be matched to the state that asked.
        private int _epoch;
        // PAINTED: the thread whose code is actually on screen (0 = none). Set to a THREAD in exactly one
        // place, WindowLanded, and only when the reply decoded something - never on intent. Every other
        // write clears it.
        private uint _seatedTid;
        // IN FLIGHT: a seat has been asked for this thread (0 = none). Stops a second, identical seat.
        private uint _seatingTid;
        // WE asked for the registers, so ONE regs reply for the seating thread may move the window. The pad
        // requests registers for its own reasons; without this each of them re-centred the listing.
        private bool _awaitRegsSeat;
        // COMPLETED-BUT-UNSEATED: this thread's seat decoded nothing, this episode. Lets the retry happen once
        // per thread per episode rather than on every inventory.
        private uint _emptySeatTid;
        // An edge extension is in flight in that direction (one per direction).
        private bool _pendFwd, _pendBwd;
        // The STOP's symbol: the stopped thread's runtime location, for code with no module:line. Per STOP,
        // never per thread - see SymbolFor.
        private string _stopSym;

        public int Epoch { get { return _epoch; } }
        public uint SeatedTid { get { return _seatedTid; } }
        public uint SeatingTid { get { return _seatingTid; } }
        public bool AwaitRegs { get { return _awaitRegsSeat; } }
        public uint EmptyTid { get { return _emptySeatTid; } }
        public bool PendFwd { get { return _pendFwd; } }
        public bool PendBwd { get { return _pendBwd; } }

        /// <summary>Is a reply tagged with <paramref name="epoch"/> still wanted?</summary>
        public bool IsCurrent(int epoch) { return epoch == _epoch; }

        // ----- the one private step every reseat goes through -----

        /// <summary>Invalidate every in-flight request: the question they were asked under has changed.
        /// Clearing the pending flags matters as much as bumping the epoch - the dropped replies will never
        /// arrive to clear them, and a stuck _pendFwd would freeze forward extension for good.
        ///
        /// A seat asked for under the old epoch is no longer in flight either: its reply is one of the ones
        /// being retired. Leaving _seatingTid set would make TryBeginSeat refuse the seat that replaces it,
        /// and leaving _awaitRegsSeat set would let a stray regs reply move the window. So retiring replies
        /// ABANDONS an in-flight seat; it does NOT un-paint (_seatedTid is untouched - the old listing is
        /// still on screen until something replaces it).
        ///
        /// PRIVATE, so no caller can reseat without it and no caller can bump it without saying why.</summary>
        private void NewEpoch()
        {
            _epoch++;
            _pendFwd = _pendBwd = false;
            _seatingTid = 0;
            _awaitRegsSeat = false;
        }

        // ----- transitions -----

        /// <summary>A different session (or none) was bound. It knows nothing about the thread the old one
        /// was showing, so nothing is painted, in flight, or known to be undecodable.</summary>
        public void Rebound()
        {
            NewEpoch();
            _seatedTid = 0;
            _emptySeatTid = 0;
        }

        /// <summary>The process exited: as <see cref="Rebound"/>, and the stop's symbol goes with it.</summary>
        public void Exited()
        {
            Rebound();
            _stopSym = null;
        }

        /// <summary>A new stop on <paramref name="stoppedTid"/> (0 when the engine did not name it). The
        /// engine resets its selection to the stopped thread, so everything in flight is retired; and the
        /// stop's own disasm request is the seat, so it is recorded as IN FLIGHT - which is what stops the
        /// `threads` reply that follows a stop from starting a second, identical seat. NOT painted: that
        /// waits for the reply. It goes straight to disasm, so it awaits no registers.</summary>
        public void Stopped(uint stoppedTid, string sym)
        {
            NewEpoch();
            _emptySeatTid = 0;        // a new stop is a new answer to "can this address be decoded?"
            _seatedTid = 0;
            _seatingTid = stoppedTid;
            _awaitRegsSeat = false;
            _stopSym = sym;
        }

        /// <summary>The selection is about to move from <paramref name="fromTid"/> to <paramref name="toTid"/>.
        /// A DIFFERENT thread says nothing about the one whose decode came back empty, so it gets a fresh
        /// try; re-selecting the same thread does not.</summary>
        public void SelectionMoving(uint fromTid, uint toTid)
        {
            if (toTid != fromTid) _emptySeatTid = 0;
        }

        /// <summary>Start seating <paramref name="selTid"/>, if it is not already painted, already on its
        /// way, or already known to decode to nothing this episode. True when a seat was started: the caller
        /// then asks for the thread's registers, because the inventory carries no EIP.</summary>
        public bool TryBeginSeat(uint selTid)
        {
            if (selTid == 0) return false;
            if (selTid == _seatedTid) return false;      // already painted for this thread
            if (selTid == _seatingTid) return false;     // already on its way - do not start a second one
            if (selTid == _emptySeatTid) return false;   // asked this episode; the engine had nothing to decode
            NewEpoch();                                  // clears both in-flight flags, so it must come FIRST
            _seatingTid = selTid;
            _awaitRegsSeat = true;
            return true;
        }

        /// <summary>An EXPLICIT request to go back to <paramref name="selTid"/>'s current instruction (ticket
        /// 876ddf1d). Unlike <see cref="TryBeginSeat"/> it skips the already-painted and already-empty guards
        /// on purpose: "painted" is exactly the state a user who scrolled away is in, and an explicit ask is
        /// worth one retry of an address that decoded to nothing. It still retires everything in flight and
        /// seats through the registers, like any other seat. The painted thread is left alone: its listing
        /// stays on screen until the new window replaces it.</summary>
        public bool BeginRecentre(uint selTid)
        {
            if (selTid == 0) return false;
            NewEpoch();
            _seatingTid = selTid;
            _awaitRegsSeat = true;
            return true;
        }

        /// <summary>A regs reply for <paramref name="tid"/> whose EIP parsed to <paramref name="eipVa"/> (0 when
        /// absent or unparsable). True - and the "we asked" flag is CONSUMED - only if this view asked for
        /// exactly that thread's registers and the reply says where to seat. The seat stays in flight: it
        /// now waits on the disasm rather than the registers.</summary>
        public bool TakeRegs(uint tid, uint eipVa)
        {
            if (!_awaitRegsSeat) return false;                          // we did not ask; not ours to act on
            if (tid == 0) return false;
            if (_seatingTid == 0 || tid != _seatingTid) return false;   // a different thread's registers
            if (eipVa == 0) return false;
            _awaitRegsSeat = false;
            return true;
        }

        /// <summary>An engine error arrived. Errors are untagged, so this cannot tell a disasm failure from any
        /// other; it releases whatever seat is in flight, because a held latch is unrecoverable for the rest of
        /// the stop and a lost seat is recoverable by selecting the thread again. It does NOT record a decode
        /// failure: an error is no evidence the address is undecodable. True when there was a seat to release.</summary>
        public bool Failed()
        {
            if (_seatingTid == 0 && !_awaitRegsSeat) return false;   // nothing waiting; not ours to clear
            _seatingTid = 0;
            _awaitRegsSeat = false;
            return true;
        }

        /// <summary>A coarse SEEK is about to reseat the window at an arbitrary address. It retires everything
        /// in flight - an edge extension asked at the old window's edge would otherwise pass both gates and be
        /// merged megabytes from the new window - and that ABANDONS any pending thread seat.
        ///
        /// THE SCROLL WINS, deliberately (the PM's ruling on 876ddf1d): the user's newest explicit action beats
        /// an older auto-centre, so nothing here or after re-asserts the abandoned seat. Re-asserting it would
        /// yank the view away from where the user just scrolled. The way back is <see cref="BeginRecentre"/>.
        ///
        /// Any "no code to show for Thread B" claim is retired NOW rather than when the reply lands: from this
        /// moment the pane is an address seek and says nothing about a thread.</summary>
        public void Seek()
        {
            NewEpoch();
            _emptySeatTid = 0;
        }

        /// <summary>A fresh window (WinTag) reply passed both gates. <paramref name="replyTid"/> is the reply's
        /// stamp (0 = unstamped), <paramref name="selTid"/> the selection it was checked against, and
        /// <paramref name="count"/> how many instructions it decoded. The caller replaces the listing with it
        /// immediately after, so every field here is settled BEFORE the screen changes.
        ///
        /// A WinTag reply serves two callers: a SEAT (something was in flight) and a coarse SEEK (nothing
        /// was). Which one is read before the in-flight state is released, because afterwards the two are
        /// indistinguishable.
        ///
        /// Only a reply that DECODED SOMETHING paints: an empty reply claiming the seat would name a thread
        /// whose code is not on screen and block every retry. And an empty reply UN-paints: it is about to
        /// erase what _seatedTid described, and a painted flag that outlives the paint lets the banner claim
        /// a thread while nothing is on screen. Only a SEAT may record "this thread's code could not be
        /// decoded"; a seek's empty result retires such a claim instead of making one.</summary>
        public WindowOutcome WindowLanded(uint replyTid, uint selTid, int count)
        {
            bool wasSeat = _seatingTid != 0 || _awaitRegsSeat;
            _seatingTid = 0;
            _awaitRegsSeat = false;
            _pendFwd = _pendBwd = false;   // a fresh window replaces the cache any extension was extending
            uint whose = replyTid != 0 ? replyTid : selTid;
            if (count > 0)
            {
                _seatedTid = whose;
                _emptySeatTid = 0;          // it decodes after all
                return WindowOutcome.Seated;
            }
            _emptySeatTid = wasSeat ? whose : 0;
            _seatedTid = 0;
            return wasSeat ? WindowOutcome.EmptySeat : WindowOutcome.EmptySeek;
        }

        /// <summary>Claim the edge extension in one direction. False when one is already in flight there.</summary>
        public bool TryBeginExtend(bool forward)
        {
            if (forward) { if (_pendFwd) return false; _pendFwd = true; }
            else         { if (_pendBwd) return false; _pendBwd = true; }
            return true;
        }

        /// <summary>An edge extension in that direction landed.</summary>
        public void ExtendLanded(bool forward)
        {
            if (forward) _pendFwd = false; else _pendBwd = false;
        }

        // ----- derived answers: the rules that READ the state, next to the rules that write it -----

        /// <summary>Does the view know nothing at all - no selection, nothing painted, nothing in flight?
        /// The late-open degradation seat on the STOPPED thread's address is safe only then.</summary>
        public bool KnowsNothing(uint selTid)
        {
            return selTid == 0 && _seatedTid == 0 && _seatingTid == 0;
        }

        /// <summary>The thread the banner should name as "not the stopped thread", or 0 for a blank banner.
        /// DERIVED FROM THE PAINTED THREAD, never the intended one, and blank whenever what is painted is
        /// not what is selected: silence is the only honest banner for "the screen does not yet show what
        /// you asked for".</summary>
        public uint ForeignSeatedTid(uint selTid, uint stoppedTid)
        {
            return _seatedTid == selTid && IsOtherThread(selTid, stoppedTid) ? _seatedTid : 0;
        }

        /// <summary>Is <paramref name="selTid"/> a thread other than the one execution stopped on? Both must be
        /// known: an unknown side is the ordinary single-thread case, where saying anything is noise. The ONE
        /// statement of that rule - the banner, the stop symbol and the step tooltips all read it - and the
        /// same rule as the pad's viewingOtherThread, so the two never disagree about when to speak.</summary>
        public static bool IsOtherThread(uint selTid, uint stoppedTid)
        {
            return selTid != 0 && stoppedTid != 0 && selTid != stoppedTid;
        }

        /// <summary>The stop's symbol, when the strip's subject IS the stopped thread (or either side is
        /// unknown); otherwise null. The symbol is per STOP, never per thread: shown beside another thread's
        /// listing it would put the stopped thread's location next to a banner saying "viewing Thread B".
        /// It is gated rather than cleared, because for the stopped thread it is still the true label.</summary>
        public string SymbolFor(uint selTid, uint stoppedTid)
        {
            return IsOtherThread(selTid, stoppedTid) ? null : _stopSym;
        }
    }
}

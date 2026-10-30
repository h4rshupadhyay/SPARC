"""Streaming capture-time bins with bounded, disclosed adaptive resolution."""
from decimal import Decimal, localcontext, ROUND_FLOOR

class CaptureRateBins:
    """Start with nominal one-second bins; merge adjacent bins to retain ≤200."""
    def __init__(self):
        self.width=1
        self.bins={}
        self.first=self.last=None
        self.unplottable=False

    def add(self,timestamp:Decimal,length:int):
        if self.first is None: self.first=timestamp
        self.last=timestamp
        # Optional visualization must not turn extreme but valid source timestamps
        # into giant integer/string allocations or change the aggregate summary.
        if (not timestamp.is_finite() or len(timestamp.as_tuple().digits)>100
                or abs(timestamp.adjusted())>40):
            self.unplottable=True
            return
        with localcontext() as context:
            context.prec=128
            index=int((timestamp/Decimal(self.width)).to_integral_value(rounding=ROUND_FLOOR))
        self.bins[index]=self.bins.get(index,0)+length
        while max(self.bins)-min(self.bins)>=200:
            merged={}
            for index,value in self.bins.items():
                merged[index//2]=merged.get(index//2,0)+value
            self.bins=merged
            self.width*=2

    def finish(self):
        definition=('Captured bytes divided by nominal bin width; epoch-aligned bins. '
            'Width doubles when needed to retain at most 200 bins; first/final bins may be partial. '
            'This is not application plaintext goodput or the first-to-last aggregate rate.')
        available=(not self.unplottable and self.first is not None and self.last>self.first)
        if self.bins and not self.unplottable:
            first,last=min(self.bins),max(self.bins)
            counts=[self.bins.get(index,0) for index in range(first,last+1)]
            offsets=[str(index*self.width) for index in range(len(counts))]
            with localcontext() as context:
                context.prec=50
                rates=[str(Decimal(count)/self.width) for count in counts] if available else []
            origin=str(first*self.width)
        else:
            counts=[]; offsets=[]; rates=[]; origin=None
        return {'available':available,'width_s':str(self.width),'origin_timestamp':origin,
            'captured_bytes':counts,'offsets_s':offsets,'bytes_s':rates,'definition':definition,
            'reason':'' if available else 'A positive first-to-last interval and graphable timestamps are required'}

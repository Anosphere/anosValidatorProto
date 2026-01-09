package core

// Monetary base units:
// 1 Anos = 1,000,000 units
const (
	UnitsPerAnos uint64 = 1_000_000

	// Fee policy (SEND only):
	// 0.5% with min 0.001 Anos and max 3 Anos
	MinFee uint64 = 1_000            // 0.001 Anos
	MaxFee uint64 = 3 * UnitsPerAnos // 3 Anos
)

// ExpectedFee computes the required fee for a SEND amount, in base units.
//
// Fee = ceil(amount * 0.005), clamped to [MinFee, MaxFee].
// Integer ceil for (amount * 5 / 1000) is: (amount*5 + 999)/1000.
func ExpectedFee(amount uint64) uint64 {
	// 0.5% = 5/1000
	fee := (amount*5 + 999) / 1000 // ceil

	if fee < MinFee {
		fee = MinFee
	}
	if fee > MaxFee {
		fee = MaxFee
	}
	return fee
}

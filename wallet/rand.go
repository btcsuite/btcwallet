package wallet

import (
	"math/rand"
	"time"
)

// init initializes the random generator.
func init() {
	rand.Seed(time.Now().Unix())
}

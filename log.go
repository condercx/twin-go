package twin

import (
	"fmt"
)

func logf(format string, args ...interface{}) {
	fmt.Printf("[twin] "+format+"\n", args...)
}

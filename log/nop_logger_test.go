package log_test

import (
	"testing"

	"dev.azure.com/vib-lz-devops/B08-DSC-Project-SmartCollection/_git/smartcollection-base-go.git/log"
)

func TestNopLogger(t *testing.T) {
	t.Parallel()
	logger := log.NewNopLogger()
	if err := logger.Log("abc", 123); err != nil {
		t.Error(err)
	}
	if err := log.With(logger, "def", "ghi").Log(); err != nil {
		t.Error(err)
	}
}

func BenchmarkNopLoggerSimple(b *testing.B) {
	benchmarkRunner(b, log.NewNopLogger(), baseMessage)
}

func BenchmarkNopLoggerContextual(b *testing.B) {
	benchmarkRunner(b, log.NewNopLogger(), withMessage)
}

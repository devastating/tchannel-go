package arg2

import (
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uber/tchannel-go/typed"
)

func TestKeyValIterator(t *testing.T) {
	const (
		testBufSize = 100
		nh          = 5
	)

	buf := make([]byte, testBufSize)
	wb := typed.NewWriteBuffer(buf)
	wb.WriteUint16(nh)
	for i := 0; i < nh; i++ {
		wb.WriteLen16String(fmt.Sprintf("key%v", i))
		wb.WriteLen16String(fmt.Sprintf("value%v", i))
	}

	iter, err := NewKeyValIterator(buf[:wb.BytesWritten()])
	for i := 0; i < nh; i++ {
		assert.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("key%v", i), string(iter.Key()), "unexpected key")
		assert.Equal(t, fmt.Sprintf("value%v", i), string(iter.Value()), "unexpected value")
		iter, err = iter.Next()
	}
	assert.Equal(t, io.EOF, err)

	t.Run("init iterator w/o Arg2", func(t *testing.T) {
		_, err := NewKeyValIterator(nil)
		assert.Equal(t, io.EOF, err)
	})

	t.Run("init iterator w/o pairs", func(t *testing.T) {
		buf := make([]byte, 2)
		wb := typed.NewWriteBuffer(buf)
		wb.WriteUint16(0)
		_, err := NewKeyValIterator(buf[:wb.BytesWritten()])
		assert.Equal(t, io.EOF, err)
	})

	t.Run("bad key value length", func(t *testing.T) {
		buf := make([]byte, testBufSize)
		wb := typed.NewWriteBuffer(buf)
		wb.WriteUint16(1)
		wb.WriteLen16String("key")
		wb.WriteLen16String("value")
		tests := []struct {
			msg     string
			arg2Len int
			wantErr string
		}{
			{
				msg:     "ok",
				arg2Len: wb.BytesWritten(),
			},
			{
				msg:     "not enough to read key len",
				arg2Len: 3, // nh (2) + 1
				wantErr: "invalid key offset 2 (arg2 len 3)",
			},
			{
				msg:     "not enough to hold key value",
				arg2Len: 6, // nh (2) + 2 + len(key) - 1
				wantErr: "invalid value offset 7 (key offset 4, key len 3, arg2 len 6)",
			},
			{
				msg:     "not enough to read value len",
				arg2Len: 8, // nh (2) + 2 + len(key) + 1
				wantErr: "invalid value offset 7 (key offset 4, key len 3, arg2 len 8)",
			},
			{
				msg:     "not enough to iterate value",
				arg2Len: 13, // nh (2) + 2 + len(key) + 2 + len(value) = 14
				wantErr: "value exceeds arg2 range (offset 9, len 5, arg2 len 13)",
			},
		}

		for _, tt := range tests {
			t.Run(tt.msg, func(t *testing.T) {
				iter, err := NewKeyValIterator(buf[:tt.arg2Len])
				if tt.wantErr == "" {
					assert.NoError(t, err)
					assert.Equal(t, "key", string(iter.Key()), "unexpected key")
					assert.Equal(t, "value", string(iter.Value()), "unexpected value")
					return
				}

				require.Error(t, err, "should not create iterator")
				assert.Contains(t, err.Error(), tt.wantErr)
			})
		}
	})
}

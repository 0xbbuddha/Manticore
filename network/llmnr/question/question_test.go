package question_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/llmnr/class"
	"github.com/TheManticoreProject/Manticore/network/llmnr/llmnr_type"
	"github.com/TheManticoreProject/Manticore/network/llmnr/question"
)

func TestEncodeQuestions(t *testing.T) {
	tests := []struct {
		question question.Question
		expected []byte
	}{
		{
			question: question.Question{
				Name:  "example.com",
				Type:  llmnr_type.TypeA,
				Class: class.ClassIN,
			},
			expected: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
			},
		},
	}

	for _, test := range tests {
		t.Run("EncodeQuestions", func(t *testing.T) {
			var buf []byte
			encoded, err := test.question.Marshal()
			if err != nil {
				t.Fatalf("failed to encode question: %v", err)
			}
			buf = append(buf, encoded...)
			if !bytes.Equal(buf, test.expected) {
				t.Errorf("EncodeQuestions = %v; want %v", buf, test.expected)
			}
		})
	}
}

func TestDecodeQuestions(t *testing.T) {
	tests := []struct {
		data     []byte
		expected question.Question
	}{
		{
			data: []byte{
				7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
			},
			expected: question.Question{
				Name:  "example.com",
				Type:  llmnr_type.TypeA,
				Class: class.ClassIN,
			},
		},
	}

	for _, test := range tests {
		t.Run("DecodeQuestions", func(t *testing.T) {
			q := question.Question{}
			bytesRead, err := q.Unmarshal(test.data)
			if err != nil {
				t.Fatalf("failed to decode question: %v", err)
			}
			if bytesRead != len(test.data) {
				t.Errorf("bytes read = %d; want %d", bytesRead, len(test.data))
			}

			if q != test.expected {
				t.Errorf("DecodeQuestions = %v; want %v", q, test.expected)
			}
		})
	}
}

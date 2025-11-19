package message_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/network/llmnr/class"
	"github.com/TheManticoreProject/Manticore/network/llmnr/errors"
	"github.com/TheManticoreProject/Manticore/network/llmnr/llmnr_type"
	"github.com/TheManticoreProject/Manticore/network/llmnr/message"
	"github.com/TheManticoreProject/Manticore/network/llmnr/message/header"
	"github.com/TheManticoreProject/Manticore/network/llmnr/question"
	"github.com/TheManticoreProject/Manticore/network/llmnr/resourcerecord"
)

func TestNewMessage(t *testing.T) {
	msg := message.NewMessage()

	if msg == nil {
		t.Fatal("NewMessage returned nil")
	}

	// Check default values
	if len(msg.Questions) != 0 {
		t.Errorf("expected empty Questions, got %d items", len(msg.Questions))
	}
	if len(msg.Answers) != 0 {
		t.Errorf("expected empty Answers, got %d items", len(msg.Answers))
	}
	if len(msg.Authority) != 0 {
		t.Errorf("expected empty Authority, got %d items", len(msg.Authority))
	}
	if len(msg.Additional) != 0 {
		t.Errorf("expected empty Additional, got %d items", len(msg.Additional))
	}
}

func TestMessageCreation(t *testing.T) {
	header := header.Header{
		Identifier: uint16(rand.Intn(65536)),
		Flags:      0x0100,
		QDCount:    1,
		ANCount:    0,
		NSCount:    0,
		ARCount:    0,
	}

	message := message.Message{
		Header: header,
		Questions: []question.Question{
			{
				Name:  "example.com",
				Type:  llmnr_type.TypeA,
				Class: class.ClassIN,
			},
		},
	}

	if message.Header.Identifier != header.Identifier {
		t.Errorf("Message header Identifier mismatch. Got %d, want %d", message.Header.Identifier, header.Identifier)
	}

	if len(message.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(message.Questions))
	}

	question := message.Questions[0]
	if question.Name != "example.com" {
		t.Errorf("Question name mismatch. Got %s, want %s", question.Name, "example.com")
	}
	if question.Type != llmnr_type.TypeA {
		t.Errorf("Question type mismatch. Got %d, want %d", question.Type, llmnr_type.TypeA)
	}
	if question.Class != class.ClassIN {
		t.Errorf("Question class mismatch. Got %d, want %d", question.Class, class.ClassIN)
	}
}

func TestMessageResponse(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	header := header.Header{
		Identifier: uint16(rand.Intn(65536)),
		Flags:      0x0100,
		QDCount:    1,
		ANCount:    0,
		NSCount:    0,
		ARCount:    0,
	}

	m := message.Message{
		Header: header,
		Questions: []question.Question{
			{
				Name:  "example.com",
				Type:  llmnr_type.TypeA,
				Class: class.ClassIN,
			},
		},
	}

	response := message.CreateResponseFromMessage(&m)
	if response.Header.Identifier != m.Header.Identifier {
		t.Errorf("Response header Identifier mismatch. Got %d, want %d", response.Header.Identifier, m.Header.Identifier)
	}

	if response.Header.Flags&0x8000 == 0 {
		t.Errorf("Response header QR flag not set")
	}

	if len(response.Questions) != 0 {
		t.Fatalf("Expected 0 question in response, got %d", len(response.Questions))
	}

	if len(response.Answers) != 0 {
		t.Fatalf("Expected 0 answer in response, got %d", len(response.Answers))
	}

	response.AddAnswerClassINTypeA("example.com", "127.0.0.1")

	question := response.Questions[0]
	if question.Name != "example.com" {
		t.Errorf("Response question name mismatch. Got %s, want %s", question.Name, "example.com")
	}
	if question.Type != llmnr_type.TypeA {
		t.Errorf("Response question type mismatch. Got %d, want %d", question.Type, llmnr_type.TypeA)
	}
	if question.Class != class.ClassIN {
		t.Errorf("Response question class mismatch. Got %d, want %d", question.Class, class.ClassIN)
	}
}

func TestAddQuestion(t *testing.T) {
	msg := message.NewMessage()

	// Test adding valid question
	err := msg.AddQuestion("host.local", llmnr_type.TypeA, class.ClassIN)
	if err != nil {
		t.Errorf("AddQuestion() unexpected error: %v", err)
	}
	if len(msg.Questions) != 1 {
		t.Errorf("expected 1 question, got %d", len(msg.Questions))
	}
	if msg.Header.QDCount != 1 {
		t.Errorf("expected QDCount=1, got %d", msg.Header.QDCount)
	}

	// Test adding invalid question
	err = msg.AddQuestion(
		"thisnameiswaytoolongforavaliddomainnameandshouldcauseanerrorwhentriedtobeusedintheprogram.com",
		llmnr_type.TypeA,
		class.ClassIN,
	)
	if err != errors.ErrLabelTooLong {
		t.Errorf("AddQuestion() error = %v, want %v", err, errors.ErrLabelTooLong)
	}
}

func TestAddAnswer(t *testing.T) {
	msg := message.NewMessage()

	// Test adding valid answer
	rr := resourcerecord.ResourceRecord{
		Name:     "host.local",
		Type:     llmnr_type.TypeA,
		Class:    class.ClassIN,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{192, 168, 1, 1},
	}

	err := msg.AddAnswer(rr)
	if err != nil {
		t.Errorf("AddAnswer() unexpected error: %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Errorf("expected 1 answer, got %d", len(msg.Answers))
	}
	if msg.Header.ANCount != 1 {
		t.Errorf("expected ANCount=1, got %d", msg.Header.ANCount)
	}

	// Test adding invalid answer
	rr.Name = "thisnameiswaytoolongforavaliddomainnameandshouldcauseanerrorwhentriedtobeusedintheprogram.com"
	err = msg.AddAnswer(rr)
	if err != errors.ErrLabelTooLong && err != errors.ErrNameTooLong {
		t.Errorf("AddAnswer() error = %v, want %v", err, errors.ErrLabelTooLong)
	}
}

func TestValidate(t *testing.T) {
	msg := message.NewMessage()

	// Test valid message
	err := msg.AddQuestion("host.local", llmnr_type.TypeA, class.ClassIN)
	if err != nil {
		t.Fatalf("AddQuestion() unexpected error: %v", err)
	}

	rr := resourcerecord.ResourceRecord{
		Name:     "host.local",
		Type:     llmnr_type.TypeA,
		Class:    class.ClassIN,
		TTL:      300,
		RDLength: 4,
		RData:    []byte{192, 168, 1, 1},
	}
	err = msg.AddAnswer(rr)
	if err != nil {
		t.Fatalf("AddAnswer() unexpected error: %v", err)
	}

	err = msg.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}

	// Test invalid message (mismatched counts)
	msg.Header.QDCount = 2 // Manually break the count
	err = msg.Validate()
	if err != errors.ErrInvalidMessage {
		t.Errorf("Validate() error = %v, want %v", err, errors.ErrInvalidMessage)
	}
}

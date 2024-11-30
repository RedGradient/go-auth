package email

import (
	"fmt"
)

type FakeEmailSender struct {
    From string
}

func (r *FakeEmailSender) Send(to, subject, body string) error {
    fmt.Printf("Sending email")
    fmt.Printf("to: %s", to)
    fmt.Printf("from: %s", r.From)
    fmt.Printf("Body: %s", body)
    return nil
}
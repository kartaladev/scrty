package magiclink

import "github.com/kartaladev/scrty/notify"

// Renderer turns a link and its redirect target into the message to send.
//
// Whatever it returns, the recipient is forced to the address that was
// submitted: a renderer is for wording, not for choosing who receives a live
// sign-in link.
//
// When a consumer supplies none, the library uses its own: a plain-text message
// carrying the link and saying that it expires shortly and can be used once,
// naming no product, brand or organisation. WithRenderer replaces it.
type Renderer func(link, next string) notify.Message

// defaultRenderer writes a neutral plain-text message.
//
// It names no product, brand or organisation, because scrty does not know the
// consumer's and must not invent one. A consumer who wants their name in the
// message supplies a Renderer through WithRenderer.
//
// It leaves From empty, so the sender's own configured address is used.
func defaultRenderer(link, _ string) notify.Message {
	return notify.Message{
		Subject: "Your sign-in link",
		TextBody: "Use this link to sign in:\n\n" + link +
			"\n\nIt expires shortly and can be used once." +
			"\n\nIf you did not ask to sign in, you can ignore this message.\n",
	}
}

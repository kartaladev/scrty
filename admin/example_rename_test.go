package admin_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
	"github.com/kartaladev/scrty/session"
)

// ExampleWithSessionRevocation renames a user who is signed in, with the
// application's own session manager as the revoker, which ends her session.
// Re-sending her new username afterwards ends nothing.
func ExampleWithSessionRevocation() {
	store, err := session.NewMemoryStore()
	if err != nil {
		panic(err)
	}

	sessions, err := session.New(session.WithStore(store))
	if err != nil {
		panic(err)
	}

	users, err := admin.NewUsers(&exampleUserStore{users: map[identity.UserID]admin.User{}},
		admin.WithSessionRevocation(sessions))
	if err != nil {
		panic(err)
	}

	ctx := admin.WithSystemActor(context.Background(), "directory-sync")

	ada, err := users.Create(ctx, admin.NewUser{Username: "ada", Name: "Ada"})
	if err != nil {
		panic(err)
	}

	if _, err := sessions.Create(ctx, ada.ID); err != nil {
		panic(err)
	}

	newName := "ada.lovelace"

	ada, err = users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Username: &newName})
	if err != nil {
		panic(err)
	}

	live, err := sessions.CountActiveByUser(ctx, ada.ID)
	if err != nil {
		panic(err)
	}

	fmt.Println(ada.Username, "sessions:", live)

	if _, err := sessions.Create(ctx, ada.ID); err != nil {
		panic(err)
	}

	ada, err = users.Update(ctx, ada.ID, ada.Version, admin.UserChange{Username: &newName})
	if err != nil {
		panic(err)
	}

	live, err = sessions.CountActiveByUser(ctx, ada.ID)
	if err != nil {
		panic(err)
	}

	fmt.Println(ada.Username, "sessions:", live)

	// Output:
	// ada.lovelace sessions: 0
	// ada.lovelace sessions: 1
}

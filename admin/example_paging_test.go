package admin_test

import (
	"context"
	"fmt"

	"github.com/kartaladev/scrty/admin"
	"github.com/kartaladev/scrty/identity"
)

// ExampleUsers_Count shows a page picker: page 3 of a list of 999 users
// is the page starting 20 users in, and Count gives the total the picker
// divides into pages.
func ExampleUsers_Count() {
	store := &exampleUserStore{users: map[identity.UserID]admin.User{}}

	for i := range 999 {
		uid := identity.UserID(fmt.Sprintf("user-%03d", i))
		store.users[uid] = admin.User{ID: uid, Username: fmt.Sprintf("user%03d", i)}
	}

	users, err := admin.NewUsers(store)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	filter := admin.UserFilter{Offset: 20, PageSize: 10}

	page, err := users.List(ctx, filter)
	if err != nil {
		panic(err)
	}

	total, err := users.Count(ctx, filter)
	if err != nil {
		panic(err)
	}

	pages := (total + int64(filter.PageSize) - 1) / int64(filter.PageSize)

	fmt.Printf("%d of %d records shown (page %d of %d)\n", len(page.Users), total, filter.Offset/filter.PageSize+1, pages)
	// Output: 10 of 999 records shown (page 3 of 100)
}

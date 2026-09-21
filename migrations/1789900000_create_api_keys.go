package migrations

import (
	"github.com/pocketbase/pocketbase/core"
)

func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		// already applied (eg. when re-running on an older snapshot)
		if existing, _ := txApp.FindCollectionByNameOrId(core.CollectionNameAPIKeys); existing != nil {
			return nil
		}

		col := core.NewBaseCollection(core.CollectionNameAPIKeys)
		col.System = true
		// API keys are managed only through the dedicated superuser API;
		// leave all regular record rules nil (superuser-only by default).

		col.Fields.Add(&core.TextField{
			Name:     "name",
			System:   true,
			Required: true,
			Max:      255,
		})
		col.Fields.Add(&core.TextField{
			Name:   "keyPrefix",
			System: true,
			Hidden: true,
			Max:    32,
		})
		col.Fields.Add(&core.TextField{
			Name:   "keyHash",
			System: true,
			Hidden: true,
			Max:    128,
		})
		col.Fields.Add(&core.TextField{
			Name:   "keySalt",
			System: true,
			Hidden: true,
			Max:    64,
		})
		col.Fields.Add(&core.JSONField{
			Name:     "scopes",
			System:   true,
			Required: true,
			MaxSize:  64 << 10,
		})
		col.Fields.Add(&core.TextField{
			Name:   "ownerCollectionRef",
			System: true,
		})
		col.Fields.Add(&core.TextField{
			Name:   "ownerRecordRef",
			System: true,
		})
		col.Fields.Add(&core.DateField{
			Name:   "expires",
			System: true,
		})
		col.Fields.Add(&core.DateField{
			Name:   "lastUsedAt",
			System: true,
		})
		col.Fields.Add(&core.DateField{
			Name:   "revokedAt",
			System: true,
		})
		col.Fields.Add(&core.AutodateField{
			Name:     "created",
			System:   true,
			OnCreate: true,
		})
		col.Fields.Add(&core.AutodateField{
			Name:     "updated",
			System:   true,
			OnCreate: true,
			OnUpdate: true,
		})

		// names are unique so that duplicate creation can be detected explicitly
		col.AddIndex("idx_apiKeys_name", true, "name", "")
		// indexed lookup by the non-secret key prefix
		col.AddIndex("idx_apiKeys_keyPrefix", true, "keyPrefix", "")
		col.AddIndex("idx_apiKeys_owner", false, "ownerCollectionRef, ownerRecordRef", "")

		if err := txApp.Save(col); err != nil {
			return err
		}

		return nil
	}, func(txApp core.App) error {
		if err := txApp.DeleteTable(core.CollectionNameAPIKeys); err != nil {
			return err
		}

		return nil
	})
}

package migrations

import (
	"fmt"

	"github.com/pocketbase/pocketbase/core"
)

// see https://github.com/pocketbase/pocketbase (API keys authentication)
func init() {
	core.SystemMigrations.Register(func(txApp core.App) error {
		if err := createAPIKeysCollection(txApp); err != nil {
			return fmt.Errorf("_apiKeys error: %w", err)
		}

		return nil
	}, func(txApp core.App) error {
		if err := txApp.DeleteTable(core.CollectionNameAPIKeys); err != nil {
			return err
		}

		// remove the associated system collection model entry
		_, err := txApp.NonconcurrentDB().
			NewQuery("DELETE FROM {{_collections}} WHERE [[name]]={:name}").
			Bind(map[string]any{"name": core.CollectionNameAPIKeys}).
			Execute()

		return err
	})
}

func createAPIKeysCollection(txApp core.App) error {
	// in case of partial/re-run migration
	if existing, _ := txApp.FindCollectionByNameOrId(core.CollectionNameAPIKeys); existing != nil {
		return nil
	}

	col := core.NewBaseCollection(core.CollectionNameAPIKeys)
	col.System = true
	// the collection is not exposed through the regular record CRUD APIs;
	// API keys are managed exclusively via the dedicated /api/keys endpoints
	col.ListRule = nil
	col.ViewRule = nil
	col.CreateRule = nil
	col.UpdateRule = nil
	col.DeleteRule = nil

	col.Fields.Add(&core.TextField{
		Name:     "name",
		System:   true,
		Required: true,
		Max:      255,
	})
	col.Fields.Add(&core.TextField{
		Name:     "keyHash",
		System:   true,
		Hidden:   true,
		Required: true,
		// hex encoded SHA-256 digest
		Pattern: `^[a-f0-9]{64}$`,
	})
	col.Fields.Add(&core.TextField{
		Name:   "collectionRef",
		System: true,
	})
	col.Fields.Add(&core.TextField{
		Name:   "recordRef",
		System: true,
	})
	col.Fields.Add(&core.JSONField{
		Name:     "scopes",
		System:   true,
		Required: true,
		MaxSize:  8192,
	})
	col.Fields.Add(&core.DateField{
		Name:   "expiresAt",
		System: true,
	})
	col.Fields.Add(&core.DateField{
		Name:   "lastUsedAt",
		System: true,
	})
	col.Fields.Add(&core.TextField{
		Name:   "lastUsedByIP",
		System: true,
		Max:    100,
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

	col.AddIndex("idx_apiKeys_keyHash", true, "keyHash", "")
	col.AddIndex("idx_apiKeys_recordRef", false, "collectionRef,recordRef", "")
	col.AddIndex("idx_apiKeys_expiresAt", false, "expiresAt", "")

	return txApp.Save(col)
}

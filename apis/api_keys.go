package apis

import (
	"errors"
	"net/http"
	"strings"
	"time"

	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/types"
)

// API key management endpoints (superuser only) and the API key scope gate
// are registered in bindAPIKeyApi().

// bindAPIKeyApi registers the API keys management api endpoints and
// the corresponding handlers.
func bindAPIKeyApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/keys").Bind(RequireSuperuserAuth())
	sub.GET("", apiKeysList)
	sub.POST("", apiKeyCreate)
	sub.GET("/{id}", apiKeyView)
	sub.PATCH("/{id}", apiKeyUpdate)
	sub.DELETE("/{id}", apiKeyRevoke)
}

type apiKeyUpsertForm struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes"`
	// ExpiresAt accepts empty string (no expiration), RFC3339 or "YYYY-MM-DD HH:mm:ss.SSSZ".
	ExpiresAt  string `json:"expiresAt"`
	Collection string `json:"collection"` // collection id or name; empty = all
	Record     string `json:"record"`     // auth record id; empty = guest
}

func (form *apiKeyUpsertForm) validate(app core.App) (*resolvedAPIKeyRefs, error) {
	err := validation.ValidateStruct(form,
		validation.Field(&form.Name, validation.Required, validation.Length(1, 255)),
		validation.Field(&form.Scopes, validation.Required, validation.Length(1, 100)),
	)
	if err != nil {
		return nil, err
	}

	// validate and normalize each scope
	normalizedScopes := make([]string, 0, len(form.Scopes))
	seen := map[string]struct{}{}
	for _, raw := range form.Scopes {
		scope := strings.TrimSpace(raw)
		collectionPart, action, ok := strings.Cut(scope, "/")
		if !ok || collectionPart == "" || action == "" {
			return nil, validation.Errors{"scopes": errors.New(`each scope must be in the format "collection/action"`)}
		}

		if action != "*" {
			if !isSupportedAPIKeyAction(action) {
				return nil, validation.Errors{"scopes": errors.New("unsupported scope action " + action)}
			}
		}

		if collectionPart != "*" {
			col, err := app.FindCachedCollectionByNameOrId(collectionPart)
			if err != nil || col == nil {
				return nil, validation.Errors{"scopes": errors.New("unknown scope collection " + collectionPart)}
			}
			collectionPart = col.Id
		}

		normalized := collectionPart + "/" + action
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			normalizedScopes = append(normalizedScopes, normalized)
		}
	}

	// validate expiration
	var expires types.DateTime
	if strings.TrimSpace(form.ExpiresAt) != "" {
		expires, err = types.ParseDateTime(form.ExpiresAt)
		if err != nil {
			return nil, validation.Errors{"expiresAt": errors.New("must be a valid datetime")}
		}
		if !expires.Time().After(time.Now()) {
			return nil, validation.Errors{"expiresAt": errors.New("must be in the future")}
		}
	}

	refs := &resolvedAPIKeyRefs{
		Scopes:    normalizedScopes,
		ExpiresAt: expires,
	}

	// validate linked collection/record refs
	if form.Record != "" {
		if form.Collection == "" {
			return nil, validation.Errors{"collection": errors.New("collection is required when a record is linked")}
		}

		col, err := app.FindCachedCollectionByNameOrId(form.Collection)
		if err != nil || col == nil {
			return nil, validation.Errors{"collection": errors.New("invalid collection")}
		}
		if !col.IsAuth() {
			return nil, validation.Errors{"collection": errors.New("the linked collection must be an auth collection")}
		}
		if col.Name == core.CollectionNameSuperusers {
			return nil, validation.Errors{"collection": errors.New("API keys cannot be linked to the _superusers collection")}
		}

		record, err := app.FindRecordById(col, form.Record)
		if err != nil || record == nil {
			return nil, validation.Errors{"record": errors.New("invalid or missing auth record")}
		}

		refs.CollectionId = col.Id
		refs.RecordId = record.Id
	} else if form.Collection != "" {
		col, err := app.FindCachedCollectionByNameOrId(form.Collection)
		if err != nil || col == nil {
			return nil, validation.Errors{"collection": errors.New("invalid collection")}
		}
		if col.Name == core.CollectionNameSuperusers {
			return nil, validation.Errors{"collection": errors.New("API keys cannot be linked to the _superusers collection")}
		}
		refs.CollectionId = col.Id
	}

	return refs, nil
}

type resolvedAPIKeyRefs struct {
	CollectionId string
	RecordId     string
	Scopes       []string
	ExpiresAt    types.DateTime
}

func isSupportedAPIKeyAction(action string) bool {
	for _, a := range core.APIKeySupportedActions {
		if a == action {
			return true
		}
	}
	return false
}

// apiKeyResponse is returned by the management list/view handlers.
// The irreversible key hash and plaintext key are never included.
type apiKeyResponse struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Collection   *apiKeyColInfo `json:"collection"`
	Record       *apiKeyRecInfo `json:"record"`
	Scopes       []apiKeyScopeV `json:"scopes"`
	ExpiresAt    string         `json:"expiresAt"`
	LastUsedAt   string         `json:"lastUsedAt"`
	LastUsedByIP string         `json:"lastUsedByIP"`
	Created      string         `json:"created"`
	Updated      string         `json:"updated"`
	Expired      bool           `json:"expired"`
}

type apiKeyColInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiKeyRecInfo struct {
	ID             string `json:"id"`
	Email          string `json:"email"`
	Username       string `json:"username"`
	CollectionID   string `json:"collectionId"`
	CollectionName string `json:"collectionName"`
}

type apiKeyScopeV struct {
	Raw        string `json:"raw"`
	Collection string `json:"collection"` // "*" or collection name
	Action     string `json:"action"`     // "*" or a supported action
}

func newAPIKeyResponse(app core.App, m *core.APIKey) *apiKeyResponse {
	resp := &apiKeyResponse{
		ID:           m.Id,
		Name:         m.Name(),
		Scopes:       make([]apiKeyScopeV, 0, len(m.Scopes())),
		ExpiresAt:    m.ExpiresAt().String(),
		LastUsedAt:   m.LastUsedAt().String(),
		LastUsedByIP: m.LastUsedByIP(),
		Created:      m.Created().String(),
		Updated:      m.Updated().String(),
		Expired:      m.HasExpired(time.Now()),
	}

	if m.CollectionRef() != "" {
		col := &apiKeyColInfo{ID: m.CollectionRef()}
		if c, err := app.FindCachedCollectionByNameOrId(m.CollectionRef()); err == nil && c != nil {
			col.Name = c.Name
		}
		resp.Collection = col
	}

	if m.RecordRef() != "" && resp.Collection != nil {
		if c, err := app.FindCachedCollectionByNameOrId(m.CollectionRef()); err == nil && c != nil && c.IsAuth() {
			if rec, err := app.FindRecordById(c, m.RecordRef()); err == nil && rec != nil {
				resp.Record = &apiKeyRecInfo{
					ID:             rec.Id,
					Email:          rec.Email(),
					Username:       rec.GetString("username"),
					CollectionID:   c.Id,
					CollectionName: c.Name,
				}
			}
		}
	}

	for _, raw := range m.Scopes() {
		collectionPart, action, _ := strings.Cut(raw, "/")
		sv := apiKeyScopeV{Raw: raw, Collection: collectionPart, Action: action}
		if collectionPart != "*" {
			if c, err := app.FindCachedCollectionByNameOrId(collectionPart); err == nil && c != nil {
				sv.Collection = c.Name
			}
		}
		resp.Scopes = append(resp.Scopes, sv)
	}

	return resp
}

func apiKeysList(e *core.RequestEvent) error {
	records, err := e.App.FindAllRecords(core.CollectionNameAPIKeys)
	if err != nil {
		return e.BadRequestError("Failed to fetch API keys.", err)
	}

	result := make([]*apiKeyResponse, 0, len(records))
	for _, r := range records {
		result = append(result, newAPIKeyResponse(e.App, &core.APIKey{Record: r}))
	}

	return e.JSON(http.StatusOK, map[string]any{
		"items": result,
	})
}

func apiKeyView(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("API key not found.", err)
	}

	return e.JSON(http.StatusOK, newAPIKeyResponse(e.App, key))
}

func apiKeyCreate(e *core.RequestEvent) error {
	form := new(apiKeyUpsertForm)
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("Failed to read the submitted data.", err)
	}

	refs, err := form.validate(e.App)
	if err != nil {
		return e.BadRequestError("Failed to create API key.", err)
	}

	key := core.NewAPIKey(e.App)
	key.SetName(form.Name)
	key.SetScopes(refs.Scopes)
	key.SetCollectionRef(refs.CollectionId)
	key.SetRecordRef(refs.RecordId)
	key.SetExpiresAt(refs.ExpiresAt)

	plaintext := key.GenerateKey()

	if err := e.App.Save(key); err != nil {
		return e.BadRequestError("Failed to create API key.", err)
	}

	// the plaintext key is returned ONLY on creation
	return e.JSON(http.StatusOK, map[string]any{
		"key":     plaintext,
		"apiKey":  newAPIKeyResponse(e.App, key),
		"message": "Make sure to copy the API key now - it will not be shown again.",
	})
}

func apiKeyUpdate(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("API key not found.", err)
	}

	form := new(apiKeyUpsertForm)
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("Failed to read the submitted data.", err)
	}

	refs, err := form.validate(e.App)
	if err != nil {
		return e.BadRequestError("Failed to update API key.", err)
	}

	key.SetName(form.Name)
	key.SetScopes(refs.Scopes)
	key.SetCollectionRef(refs.CollectionId)
	key.SetRecordRef(refs.RecordId)
	key.SetExpiresAt(refs.ExpiresAt)

	if err := e.App.Save(key); err != nil {
		return e.BadRequestError("Failed to update API key.", err)
	}

	return e.JSON(http.StatusOK, newAPIKeyResponse(e.App, key))
}

// apiKeyRevoke deletes the API key, immediately invalidating it
// (including any established realtime connections using it).
func apiKeyRevoke(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil {
		return e.NotFoundError("API key not found.", err)
	}

	if err := e.App.Delete(key); err != nil {
		return e.BadRequestError("Failed to revoke API key.", err)
	}

	return e.NoContent(http.StatusNoContent)
}

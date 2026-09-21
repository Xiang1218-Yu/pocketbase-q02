package apis

import (
	"errors"
	"net/http"
	"strings"
	"time"

	validation "github.com/pocketbase/ozzo-validation/v4"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/search"
)

func bindAPIKeysApi(app core.App, rg *router.RouterGroup[*core.RequestEvent]) {
	sub := rg.Group("/api-keys").Bind(RequireSuperuserAuth())
	sub.GET("", apiKeysList)
	sub.POST("", apiKeysCreate)
	sub.GET("/{id}", apiKeyView)
	sub.PATCH("/{id}", apiKeyUpdate)
	sub.DELETE("/{id}", apiKeyRevoke)
}

type apiKeyOwnerForm struct {
	Collection string `json:"collection"`
	RecordId   string `json:"recordId"`
}

type apiKeyCreateForm struct {
	Name    string           `json:"name"`
	Scopes  []string         `json:"scopes"`
	Expires string           `json:"expires"`
	Owner   *apiKeyOwnerForm `json:"owner"`
}

func (form *apiKeyCreateForm) validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.Name,
			validation.Required,
			validation.Length(1, 255),
		),
		validation.Field(&form.Scopes,
			validation.Required,
			validation.By(validateScopes),
		),
		validation.Field(&form.Expires,
			validation.By(validateOptionalFutureDate),
		),
	)
}

type apiKeyUpdateForm struct {
	Name    *string   `json:"name"`
	Scopes  *[]string `json:"scopes"`
	Expires *string   `json:"expires"`
}

func (form *apiKeyUpdateForm) validate() error {
	return validation.ValidateStruct(form,
		validation.Field(&form.Name,
			validation.By(validateOptionalName),
		),
		validation.Field(&form.Scopes,
			validation.By(validateOptionalScopes),
		),
		validation.Field(&form.Expires,
			validation.By(validateOptionalFutureDate),
		),
	)
}

func apiKeysList(e *core.RequestEvent) error {
	requestInfo, err := e.RequestInfo()
	if err != nil {
		return e.BadRequestError("", err)
	}

	collection, err := e.App.FindCachedCollectionByNameOrId(core.CollectionNameAPIKeys)
	if err != nil {
		return e.NotFoundError("Missing collection context.", err)
	}

	query := e.App.RecordQuery(collection)

	fieldsResolver := core.NewRecordFieldResolver(e.App, collection, requestInfo, true)
	fieldsResolver.SetAllowHiddenFields(false)

	searchProvider := search.NewProvider(fieldsResolver).Query(query)

	records := []*core.APIKey{}
	result, err := searchProvider.ParseAndExec(e.Request.URL.Query().Encode(), &records)
	if err != nil {
		return e.BadRequestError("", err)
	}

	items := make([]map[string]any, 0, len(records))
	for _, item := range records {
		items = append(items, apiKeySafeView(item))
	}
	result.Items = items

	return e.JSON(http.StatusOK, result)
}

func apiKeyView(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil || key == nil {
		return e.NotFoundError("", err)
	}

	return e.JSON(http.StatusOK, apiKeySafeView(key))
}

// apiKeySafeView builds the public, non-secret representation of a key.
func apiKeySafeView(key *core.APIKey) map[string]any {
	result := key.PublicExport()
	result["id"] = key.Id
	return result
}

func apiKeysCreate(e *core.RequestEvent) error {
	form := new(apiKeyCreateForm)
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("Failed to read the submitted data.", err)
	}

	// normalize before validation (the validator works on the normalized slice)
	form.Scopes = normalizeScopes(form.Scopes)
	form.Name = strings.TrimSpace(form.Name)

	if err := form.validate(); err != nil {
		return e.BadRequestError("Failed to create API key.", err)
	}

	key := core.NewAPIKey(e.App)
	key.SetName(form.Name)
	key.SetScopes(form.Scopes)

	plaintext, err := key.GenerateSecret()
	if err != nil {
		return e.InternalServerError("Failed to generate API key.", err)
	}

	if form.Expires != "" {
		expires, err := parseFutureTime(form.Expires)
		if err == nil {
			key.SetExpires(expires)
		}
	}

	if form.Owner != nil && form.Owner.RecordId != "" {
		ownerCollection, err := resolveOwnerCollection(e, form.Owner.Collection)
		if err != nil {
			return e.BadRequestError("Failed to create API key.", err)
		}

		ownerRecord, err := e.App.FindRecordById(ownerCollection, form.Owner.RecordId)
		if err != nil {
			return e.BadRequestError(
				"Failed to create API key.",
				validation.Errors{"owner": validation.Errors{"recordId": errors.New("the owner record doesn't exist")}},
			)
		}

		key.SetOwnerCollectionRef(ownerRecord.Collection().Id)
		key.SetOwnerRecordRef(ownerRecord.Id)
	}

	if err := e.App.Save(key); err != nil {
		// model-level validation errors (incl. the unique "name" constraint)
		// are returned as-is so that the field details are preserved
		return firstApiError(err, e.BadRequestError("Failed to create API key.", err))
	}

	// note: core.Record has its own MarshalJSON, so a struct embedding
	// *core.APIKey would silently drop the extra "key" field; use a map instead
	result := apiKeySafeView(key)
	result["key"] = plaintext

	return e.JSON(http.StatusOK, result)
}

func apiKeyUpdate(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil || key == nil {
		return e.NotFoundError("", err)
	}

	form := new(apiKeyUpdateForm)
	if err := e.BindBody(form); err != nil {
		return e.BadRequestError("Failed to read the submitted data.", err)
	}

	if err := form.validate(); err != nil {
		return e.BadRequestError("Failed to update API key.", err)
	}

	if form.Name != nil {
		key.SetName(strings.TrimSpace(*form.Name))
	}

	if form.Scopes != nil {
		key.SetScopes(normalizeScopes(*form.Scopes))
	}

	if form.Expires != nil {
		if *form.Expires == "" {
			key.SetExpires(time.Time{})
		} else {
			expires, err := parseFutureTime(*form.Expires)
			if err != nil {
				return e.BadRequestError(
					"Failed to update API key.",
					validation.Errors{"expires": errors.New("must be a valid future date")},
				)
			}
			key.SetExpires(expires)
		}
	}

	if err := e.App.Save(key); err != nil {
		return firstApiError(err, e.BadRequestError("Failed to update API key.", err))
	}

	return e.JSON(http.StatusOK, apiKeySafeView(key))
}

// apiKeyRevoke implements DELETE - revocation is immediate.
//
// The model is kept (so that the audit trail, lastUsedAt and the unique
// prefix are preserved) but its revokedAt is set and any active realtime
// connection using the key is downgraded by the record update hook.
func apiKeyRevoke(e *core.RequestEvent) error {
	key, err := e.App.FindAPIKeyById(e.Request.PathValue("id"))
	if err != nil || key == nil {
		return e.NotFoundError("", err)
	}

	if !key.IsRevoked() {
		key.SetRevokedAt(time.Now().UTC())
		if err := e.App.Save(key); err != nil {
			return firstApiError(err, e.BadRequestError("Failed to revoke API key.", err))
		}
	}

	return e.NoContent(http.StatusNoContent)
}

// -------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------

func normalizeScopes(scopes []string) []string {
	result := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}

	for _, raw := range scopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}

		// normalize whitespace around the colon
		collection, action, ok := core.ParseAPIKeyScope(scope)
		if ok {
			scope = collection + ":" + action
		}

		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}

		result = append(result, scope)
	}

	return result
}

func validateScopes(value any) error {
	scopes, _ := value.([]string)
	if len(scopes) == 0 {
		return errors.New("at least one scope is required")
	}

	for _, scope := range scopes {
		collection, _, ok := core.ParseAPIKeyScope(scope)
		if !ok {
			return errors.New(scope + " is not a valid scope, expected format collection:action (e.g. posts:view or *:* )")
		}

		if collection != core.APIKeyWildcard && strings.HasPrefix(collection, "_") {
			return errors.New("system collections (prefixed with underscore) cannot be used in API key scopes")
		}
	}

	return nil
}

func validateOptionalScopes(value any) error {
	scopes, ok := value.(*[]string)
	if !ok || scopes == nil {
		return nil
	}

	return validateScopes(*scopes)
}

func validateOptionalName(value any) error {
	name, ok := value.(*string)
	if !ok || name == nil {
		return nil
	}

	trimmed := strings.TrimSpace(*name)
	if len(trimmed) == 0 || len(trimmed) > 255 {
		return errors.New("must be between 1 and 255 characters")
	}

	return nil
}

func validateOptionalFutureDate(value any) error {
	str, _ := value.(string)
	if strings.TrimSpace(str) == "" {
		return nil
	}

	if _, err := parseFutureTime(str); err != nil {
		return errors.New("must be a valid future date")
	}

	return nil
}

func parseFutureTime(raw string) (time.Time, error) {
	// support both RFC3339 and the PocketBase date layout
	layouts := []string{
		time.RFC3339,
		"2006-01-02 15:04:05.000Z",
		"2006-01-02 15:04:05Z",
		"2006-01-02",
	}

	var t time.Time
	var err error
	for _, layout := range layouts {
		t, err = time.Parse(layout, raw)
		if err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, err
	}

	t = t.UTC()

	if !t.After(time.Now()) {
		return time.Time{}, errors.New("date must be in the future")
	}

	return t, nil
}

func resolveOwnerCollection(e *core.RequestEvent, nameOrId string) (*core.Collection, error) {
	collection, err := e.App.FindCachedCollectionByNameOrId(nameOrId)
	if err != nil || collection == nil {
		return nil, errors.New("unknown owner collection")
	}

	if !collection.IsAuth() {
		return nil, errors.New("owner collection must be an auth collection")
	}

	if collection.Name == core.CollectionNameSuperusers {
		return nil, errors.New("API keys cannot be bound to superuser records")
	}

	return collection, nil
}

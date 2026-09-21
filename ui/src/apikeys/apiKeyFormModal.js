import { createAPIKey, updateAPIKey } from "./apiKeysClient";

const ACTIONS = [
    { value: "list", label: "List" },
    { value: "view", label: "View" },
    { value: "create", label: "Create" },
    { value: "update", label: "Update" },
    { value: "delete", label: "Delete" },
    { value: "file", label: "File download" },
];

/**
 * Opens the create/edit API key modal.
 *
 * @param {Object} settings
 * @param {Object|null} settings.apiKey existing key model (edit mode) or null (create mode)
 * @param {Function} settings.onsaved called with the create response (contains the one-time plaintext key) or updated model
 */
export function openAPIKeyFormModal(settings = {}) {
    const modal = apiKeyFormModal(settings);
    if (!modal) {
        return;
    }

    document.body.appendChild(modal);
    app.modals.open(modal);
}

function apiKeyFormModal(settings) {
    let modal;

    const uniqueId = "apikey_form_" + app.utils.randomString();
    const isEdit = !!settings.apiKey;

    const authCollections = (app.store.collections || []).filter((c) => c.type == "auth");

    function initialScopes() {
        if (isEdit) {
            return (settings.apiKey.scopes || []).map((s) => s.raw);
        }
        return ["*/view"];
    }

    const data = store({
        name: isEdit ? settings.apiKey.name : "",
        recordCollection: isEdit ? settings.apiKey.collection?.id || "" : "",
        record: isEdit ? settings.apiKey.record?.id || "" : "",
        scopes: initialScopes(),
        expiresAt: "",
        isSubmitting: false,
        errors: {},
    });

    function addScopeRow(collection = "*", action = "view") {
        data.scopes = [...data.scopes, `${collection}/${action}`];
    }

    function updateScope(index, value) {
        const scopes = [...data.scopes];
        scopes[index] = value;
        data.scopes = scopes;
    }

    function removeScope(index) {
        const scopes = [...data.scopes];
        scopes.splice(index, 1);
        data.scopes = scopes;
    }

    function scopeParts(scope) {
        const idx = scope.indexOf("/");
        if (idx < 0) {
            return { collection: scope, action: "" };
        }
        return { collection: scope.substring(0, idx), action: scope.substring(idx + 1) };
    }

    async function submit() {
        if (data.isSubmitting) {
            return;
        }

        data.errors = {};

        if (!data.name?.trim()) {
            data.errors = { ...data.errors, name: "Name is required." };
        }
        if (!data.scopes?.length) {
            data.errors = { ...data.errors, scopes: "At least one scope is required." };
        }
        if (Object.keys(data.errors).length) {
            return;
        }

        const payload = {
            name: data.name.trim(),
            scopes: data.scopes,
            collection: data.recordCollection || "",
            record: data.recordCollection ? data.record : "",
            expiresAt: data.expiresAt ? new Date(data.expiresAt).toISOString() : "",
        };

        data.isSubmitting = true;

        try {
            let result;
            if (isEdit) {
                result = await updateAPIKey(settings.apiKey.id, payload, { requestKey: uniqueId });
                app.toasts.success("API key updated.");
            } else {
                result = await createAPIKey(payload, { requestKey: uniqueId });
            }

            settings.onsaved?.(result);

            app.modals.close(modal);
        } catch (err) {
            if (!err.isAbort) {
                data.isSubmitting = false;
                app.checkApiError(err);
                const apiData = err?.response?.data || {};
                if (apiData.data) {
                    data.errors = apiData.data;
                }
            }
        }
    }

    function collectionSelect(value, onchange, extraOptionLabel = "All collections (*)") {
        return t.select(
            {
                className: "input",
                onchange: (e) => onchange(e.target.value),
            },
            t.option({ value: "*", selected: () => value == "*" }, extraOptionLabel),
            ...(app.store.collections || []).map((col) =>
                t.option(
                    { value: col.id, selected: () => value == col.id },
                    `${col.name} (${col.type})`,
                ),
            ),
        );
    }

    modal = t.div(
        {
            pbEvent: "apiKeyFormModal",
            className: "modal popup lg api-key-form-modal",
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h5({ className: "m-auto txt-center" }, isEdit ? "Edit API key" : "Create API key"),
        ),
        t.form(
            {
                className: "modal-content form",
                onsubmit: (e) => {
                    e.preventDefault();
                    submit();
                },
            },
            t.label(
                { className: "form-label" },
                "Name",
                t.input({
                    className: "input",
                    placeholder: "e.g. nightly-backup-job",
                    maxlength: 255,
                    value: () => data.name,
                    oninput: (e) => (data.name = e.target.value),
                }),
                () =>
                    data.errors.name
                        ? t.div({ className: "txt-danger txt-sm" }, data.errors.name)
                        : null,
            ),

            t.div(
                { className: "form-label" },
                "Linked auth record (optional)",
                t.div({ className: "txt-hint txt-sm m-b-xs" },
                    "When set, the key authenticates as this record. Leave empty for a guest-scoped key. Keys can never be superusers.",
                ),
                t.div(
                    { className: "grid gap-10" },
                    t.select(
                        {
                            className: "input col",
                            onchange: (e) => {
                                data.recordCollection = e.target.value;
                                data.record = "";
                            },
                        },
                        t.option({ value: "", selected: () => !data.recordCollection }, "No linked record (guest)"),
                        ...authCollections.map((col) =>
                            t.option(
                                { value: col.id, selected: () => data.recordCollection == col.id },
                                col.name,
                            ),
                        ),
                    ),
                    () => {
                        if (!data.recordCollection) {
                            return;
                        }

                        const col = authCollections.find((c) => c.id == data.recordCollection);

                        return t.input({
                            className: "input col",
                            placeholder: `Record id from ${col?.name || "collection"}`,
                            value: () => data.record,
                            oninput: (e) => (data.record = e.target.value),
                        });
                    },
                ),
                () =>
                    data.errors.collection
                        ? t.div({ className: "txt-danger txt-sm" }, data.errors.collection)
                        : null,
                () =>
                    data.errors.record
                        ? t.div({ className: "txt-danger txt-sm" }, data.errors.record)
                        : null,
            ),

            t.div(
                { className: "form-label" },
                "Scopes",
                t.div({ className: "txt-hint txt-sm m-b-xs" },
                    "Restrict the key to specific collections and actions. Use * as a wildcard.",
                ),
                () =>
                    data.scopes.map((scope, index) => {
                        const parts = scopeParts(scope);

                        return t.div(
                            { className: "flex gap-10 m-b-xs", key: index },
                            t.span({ className: "scope-index txt-hint txt-sm flex a-center" }, `#${index + 1}`),
                            collectionSelect(
                                parts.collection,
                                (colValue) => updateScope(index, `${colValue}/${parts.action || "view"}`),
                            ),
                            t.select(
                                {
                                    className: "input",
                                    onchange: (e) =>
                                        updateScope(index, `${parts.collection}/${e.target.value}`),
                                },
                                t.option(
                                    { value: "*", selected: () => parts.action == "*" },
                                    "All actions (*)",
                                ),
                                ...ACTIONS.map((a) =>
                                    t.option(
                                        { value: a.value, selected: () => parts.action == a.value },
                                        a.label,
                                    ),
                                ),
                            ),
                            t.button(
                                {
                                    type: "button",
                                    className: "btn sm circle secondary transparent",
                                    ariaLabel: "Remove scope",
                                    onclick: () => removeScope(index),
                                },
                                t.i({ className: "ri-close-line", ariaHidden: true }),
                            ),
                        );
                    }),
                t.button(
                    {
                        type: "button",
                        className: "btn sm secondary outline",
                        onclick: () => addScopeRow(),
                    },
                    t.i({ className: "ri-add-line", ariaHidden: true }),
                    "Add scope",
                ),
                () =>
                    data.errors.scopes
                        ? t.div({ className: "txt-danger txt-sm" }, data.errors.scopes)
                        : null,
            ),

            t.label(
                { className: "form-label" },
                "Expiration",
                t.div({ className: "txt-hint txt-sm m-b-xs" }, "Leave empty for a non-expiring key."),
                t.input({
                    type: "datetime-local",
                    className: "input",
                    value: () => data.expiresAt,
                    oninput: (e) => (data.expiresAt = e.target.value),
                }),
                () =>
                    data.errors.expiresAt
                        ? t.div({ className: "txt-danger txt-sm" }, data.errors.expiresAt)
                        : null,
            ),

            t.div(
                { className: "modal-actions" },
                t.button(
                    {
                        type: "button",
                        className: "btn secondary",
                        onclick: () => app.modals.close(modal),
                    },
                    "Cancel",
                ),
                t.button(
                    {
                        type: "submit",
                        className: () => `btn accent ${data.isSubmitting ? "loading" : ""}`,
                        disabled: () => data.isSubmitting,
                    },
                    isEdit ? "Save changes" : "Create key",
                ),
            ),
        ),
    );

    return modal;
}

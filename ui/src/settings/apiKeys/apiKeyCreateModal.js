import { apiKeyScopesEditor } from "./apiKeyScopesEditor";

export function apiKeyCreateModal(propsArg = {}) {
    const props = store({
        onCreated: null,
    });

    app.utils.extendStore(props, propsArg);

    const data = store({
        name: "",
        scopes: ["*:view"],
        expires: "",
        collections: [],
        isSubmitting: false,
        createdKey: "",
        createdRecord: null,
        errors: {},
    });

    app.pb.collections.getFullList(200).then((cols) => {
        data.collections = cols;
    }).catch(() => {});

    async function submit() {
        if (data.isSubmitting) {
            return;
        }

        data.isSubmitting = true;
        app.store.errors = {};

        try {
            const payload = {
                name: data.name,
                scopes: data.scopes.filter(Boolean),
            };
            if (data.expires) {
                payload.expires = new Date(data.expires).toISOString();
            }

            const result = await app.pb.send("/api-keys", {
                method: "POST",
                body: payload,
            });

            data.createdKey = result.key;
            data.createdRecord = result;
            data.isSubmitting = false;

            props.onCreated?.(result);
        } catch (err) {
            data.isSubmitting = false;
            if (!err.isAbort) {
                app.checkApiError(err, false);
                data.errors = err?.response?.data || {};
            }
        }
    }

    return t.div(
        {
            pbEvent: "apiKeyCreateModal",
            className: "modal popup",
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h5({ className: "m-auto txt-center" }, () => data.createdKey ? "Save your new API key" : "Create new API key"),
        ),

        // step 1: form
        t.form(
            {
                className: "modal-content",
                autocomplete: "off",
                hidden: () => !!data.createdKey,
                onsubmit: (e) => {
                    e.preventDefault();
                    submit();
                },
            },
            t.div(
                { className: "grid" },
                t.div(
                    { className: "col-lg-12" },
                    t.div({ className: "field" },
                        t.label({ className: "required" }, "Name"),
                        t.input({
                            type: "text",
                            maxlength: 255,
                            placeholder: "e.g. ci-deploy, nightly-backup-script",
                            value: () => data.name,
                            oninput: (e) => (data.name = e.target.value),
                        }),
                        () => data.errors.name && t.div({ className: "field-error" }, data.errors.name),
                    ),
                ),
                t.div(
                    { className: "col-lg-12" },
                    t.div({ className: "field" },
                        t.label({ className: "required" }, "Scopes (collection:action)"),
                        apiKeyScopesEditor({
                            scopes: data.scopes,
                            collections: () => data.collections,
                        }),
                        t.div(
                            { className: "field-help" },
                            "Use * as wildcard. Examples: posts:view, posts:*, *:list. System collections are not allowed.",
                        ),
                        () => data.errors.scopes && t.div({ className: "field-error" }, data.errors.scopes),
                    ),
                ),
                t.div(
                    { className: "col-lg-12" },
                    t.div({ className: "field" },
                        t.label({}, "Expiration (optional)"),
                        t.input({
                            type: "datetime-local",
                            value: () => data.expires,
                            oninput: (e) => (data.expires = e.target.value),
                        }),
                        t.div({ className: "field-help" }, "Leave empty for a non-expiring key."),
                        () => data.errors.expires && t.div({ className: "field-error" }, data.errors.expires),
                    ),
                ),
            ),
        ),

        // step 2: plaintext shown once
        t.div(
            {
                className: "modal-content",
                hidden: () => !data.createdKey,
            },
            t.div(
                { className: "alert warning m-b-base" },
                t.div(
                    { className: "content" },
                    t.p({ className: "txt-bold" }, "Copy the key now - you won't be able to see it again."),
                ),
            ),
            t.div({ className: "field" },
                t.label({}, "API key"),
                t.div(
                    { className: "flex gap-10 align-center" },
                    t.input({
                        type: "text",
                        readonly: true,
                        value: () => data.createdKey,
                        onfocus: (e) => e.target.select(),
                    }),
                    app.components.copyButton({
                        text: () => data.createdKey,
                        className: "btn sm primary",
                    }),
                ),
            ),
        ),

        t.footer(
            { className: "modal-footer" },
            () => {
                if (data.createdKey) {
                    return t.button(
                        {
                            type: "button",
                            className: "btn primary",
                            onclick: (e) => app.modals.close(e.target.closest(".modal")),
                        },
                        "Done",
                    );
                }

                return [
                    t.button(
                        {
                            type: "button",
                            className: "btn secondary",
                            onclick: (e) => app.modals.close(e.target.closest(".modal")),
                        },
                        "Cancel",
                    ),
                    t.button(
                        {
                            type: "button",
                            className: "btn primary",
                            disabled: () => data.isSubmitting,
                            onclick: () => submit(),
                        },
                        () => (data.isSubmitting ? "Creating..." : "Create"),
                    ),
                ];
            },
        ),
    );
}

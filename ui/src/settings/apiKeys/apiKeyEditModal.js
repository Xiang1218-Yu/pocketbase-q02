import { apiKeyScopesEditor } from "./apiKeyScopesEditor";

export function apiKeyEditModal(propsArg = {}) {
    const props = store({
        key: null,
        onSaved: null,
    });

    app.utils.extendStore(props, propsArg);

    const data = store({
        name: props.key?.name || "",
        scopes: [...(props.key?.scopes || [])],
        expires: props.key?.expires
            ? new Date(props.key.expires).toISOString().slice(0, 16)
            : "",
        collections: [],
        isSubmitting: false,
        errors: {},
    });

    app.pb.collections.getFullList(200).then((cols) => {
        data.collections = cols;
    }).catch(() => {});

    async function submit(e) {
        if (data.isSubmitting) {
            return;
        }

        data.isSubmitting = true;
        app.store.errors = {};

        try {
            const payload = {
                name: data.name,
                scopes: data.scopes.filter(Boolean),
                expires: data.expires ? new Date(data.expires).toISOString() : "",
            };

            await app.pb.send(`/api-keys/${encodeURIComponent(props.key.id)}`, {
                method: "PATCH",
                body: payload,
            });

            app.toasts.success("API key updated.");
            data.isSubmitting = false;
            props.onSaved?.();
            app.modals.close(e.target.closest(".modal"));
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
            pbEvent: "apiKeyEditModal",
            className: "modal popup",
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h5({ className: "m-auto txt-center" }, "Edit API key"),
        ),
        t.form(
            {
                className: "modal-content",
                autocomplete: "off",
                onsubmit: (e) => {
                    e.preventDefault();
                    submit(e);
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
                            value: () => data.name,
                            oninput: (e) => (data.name = e.target.value),
                        }),
                        () => data.errors.name && t.div({ className: "field-error" }, data.errors.name),
                    ),
                ),
                t.div(
                    { className: "col-lg-12" },
                    t.div({ className: "field" },
                        t.label({ className: "required" }, "Scopes"),
                        apiKeyScopesEditor({
                            scopes: data.scopes,
                            collections: () => data.collections,
                        }),
                        () => data.errors.scopes && t.div({ className: "field-error" }, data.errors.scopes),
                    ),
                ),
                t.div(
                    { className: "col-lg-12" },
                    t.div({ className: "field" },
                        t.label({}, "Expiration"),
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
        t.footer(
            { className: "modal-footer" },
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
                    onclick: (e) => submit(e),
                },
                () => (data.isSubmitting ? "Saving..." : "Save"),
            ),
        ),
    );
}

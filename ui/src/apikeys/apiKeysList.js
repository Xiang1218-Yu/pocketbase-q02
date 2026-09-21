import { deleteAPIKey, getAPIKeys } from "./apiKeysClient";
import { openAPIKeyFormModal } from "./apiKeyFormModal";
import { openAPIKeyRevealModal } from "./apiKeyRevealModal";

export function apiKeysList(propsArg = {}) {
    const props = store({
        reset: null,
    });

    const watchers = app.utils.extendStore(props, propsArg);

    const data = store({
        isLoading: false,
        keys: [],
    });

    async function loadKeys() {
        data.isLoading = true;

        try {
            data.keys = await getAPIKeys();
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
            }
        } finally {
            data.isLoading = false;
        }
    }

    function createKey() {
        openAPIKeyFormModal({
            apiKey: null,
            onsaved: (result) => {
                loadKeys();
                if (result?.key) {
                    openAPIKeyRevealModal(result);
                }
            },
        });
    }

    function editKey(apiKey) {
        openAPIKeyFormModal({
            apiKey,
            onsaved: () => loadKeys(),
        });
    }

    function revokeKey(apiKey) {
        app.modals.confirm(
            `Do you really want to revoke the "${apiKey.name}" API key? Existing realtime connections using it will be disconnected immediately.`,
            async () => {
                try {
                    await deleteAPIKey(apiKey.id);
                    app.toasts.success("API key revoked.");
                    loadKeys();
                } catch (err) {
                    if (!err.isAbort) {
                        app.checkApiError(err);
                    }
                }
            },
            undefined,
            { yesButton: "Revoke", className: "sm danger" },
        );
    }

    return t.div(
        {
            pbEvent: "apiKeysList",
            className: "list",
            onmount: () => {
                watchers.push(
                    watch(() => props.reset, () => {
                        loadKeys();
                    }),
                );
                loadKeys();
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        t.div(
            { className: "flex gap-10 m-b-sm a-center" },
            t.div({ className: "txt-lg" }, "API keys"),
            t.div({ className: "flex-fill" }),
            app.components.refreshButton({
                className: "btn sm transparent secondary circle",
                onclick: () => loadKeys(),
            }),
            t.button(
                { type: "button", className: "btn sm accent", onclick: createKey },
                t.i({ className: "ri-add-line", ariaHidden: true }),
                "New API key",
            ),
        ),
        () => {
            if (data.isLoading && !data.keys.length) {
                const skeletons = [];
                for (let i = 0; i < 3; i++) {
                    skeletons.push(
                        t.div({ rid: "skeleton_" + i, className: "list-item" }, t.div({ className: "skeleton-loader" })),
                    );
                }
                return skeletons;
            }

            if (!data.keys.length) {
                return t.div(
                    { className: "list-item" },
                    t.div(
                        { className: "content block txt-hint" },
                        "No API keys yet. Create one to authenticate automation scripts without long-lived user tokens.",
                    ),
                );
            }

            return data.keys.map((apiKey) => {
                return t.div(
                    { className: () => `list-item api-key-item ${apiKey.expired ? "is-expired" : ""}` },
                    t.div(
                        { className: "content" },
                        t.div(
                            { className: "flex gap-10 a-center" },
                            t.span({ className: "txt-semibold txt-ellipsis", title: () => apiKey.name }, () => apiKey.name),
                            () =>
                                apiKey.expired
                                    ? t.span({ className: "badge danger sm" }, "expired")
                                    : t.span({ className: "badge ok sm" }, "active"),
                        ),
                        t.div(
                            { className: "api-key-meta txt-sm txt-hint m-t-xs flex gap-10 wrap" },
                            () =>
                                apiKey.collection
                                    ? t.span(
                                          {},
                                          "Linked to ",
                                          t.code({ className: "txt-code" }, apiKey.collection.name),
                                          apiKey.record ? ` / ${apiKey.record.id}` : "",
                                      )
                                    : t.span({}, "Guest key (no linked record)"),
                            t.span(
                                {},
                                "Expires: ",
                                apiKey.expiresAt
                                    ? app.components.formattedDate({ value: apiKey.expiresAt, short: true })
                                    : "never",
                            ),
                            t.span(
                                {},
                                "Last used: ",
                                apiKey.lastUsedAt
                                    ? app.components.formattedDate({ value: apiKey.lastUsedAt, short: true })
                                    : "never",
                                apiKey.lastUsedByIP ? ` (${apiKey.lastUsedByIP})` : "",
                            ),
                        ),
                        t.div(
                            { className: "api-key-scopes m-t-xs flex gap-xs wrap" },
                            ...(apiKey.scopes || []).map((scope) =>
                                t.span(
                                    { className: "chip sm", title: scope.raw },
                                    t.code({ className: "txt-code" }, scope.collection),
                                    "/",
                                    t.code({ className: "txt-code" }, scope.action),
                                ),
                            ),
                        ),
                        // the secret material is intentionally never rendered
                        t.div({ className: "api-key-secret-placeholder txt-xs txt-hint m-t-xs" },
                            "Secret stored as irreversible SHA-256 digest.",
                        ),
                    ),
                    t.nav(
                        { className: "actions" },
                        t.button(
                            {
                                type: "button",
                                ariaLabel: app.attrs.tooltip("Edit"),
                                className: "btn sm circle secondary transparent",
                                onclick: () => editKey(apiKey),
                            },
                            t.i({ className: "ri-pencil-line", ariaHidden: true }),
                        ),
                        t.button(
                            {
                                type: "button",
                                ariaLabel: app.attrs.tooltip("Revoke"),
                                className: "btn sm circle danger transparent",
                                onclick: () => revokeKey(apiKey),
                            },
                            t.i({ className: "ri-delete-bin-line", ariaHidden: true }),
                        ),
                    ),
                );
            });
        },
    );
}

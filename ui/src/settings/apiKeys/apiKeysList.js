import { apiKeyEditModal } from "./apiKeyEditModal";

export function apiKeysList(propsArg = {}) {
    const props = store({
        reset: null,
        onRevoked: null,
    });

    const watchers = app.utils.extendStore(props, propsArg);

    const data = store({
        isLoading: false,
        keys: [],
    });

    async function loadKeys() {
        data.isLoading = true;

        try {
            data.keys = await app.pb.send("/api-keys?perPage=500&sort=-created", {
                requestKey: "apiKeysList",
            }).then((r) => r.items || []);
        } catch (err) {
            if (!err.isAbort) {
                app.checkApiError(err);
            }
        } finally {
            data.isLoading = false;
        }
    }

    function revokeKey(key) {
        app.modals.confirm(
            t.div(
                { className: "block" },
                t.div({ className: "txt-lg m-b-xs" }, `Revoke "${key.name}"?`),
                t.div(
                    { className: "txt-sm txt-hint" },
                    "The key will stop working immediately, including for already connected realtime clients. This action cannot be undone.",
                ),
            ),
            async () => {
                try {
                    await app.pb.send(`/api-keys/${encodeURIComponent(key.id)}`, {
                        method: "DELETE",
                    });
                    app.toasts.success(`API key "${key.name}" was revoked.`);
                    props.onRevoked?.();
                } catch (err) {
                    if (!err.isAbort) {
                        app.checkApiError(err);
                    }
                }
            },
        );
    }

    function editKey(key) {
        app.modals.open(
            apiKeyEditModal({
                key,
                onSaved: () => {
                    loadKeys();
                },
            }),
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
            },
            onunmount: () => {
                watchers.forEach((w) => w?.unwatch());
            },
        },
        () => {
            if (data.isLoading) {
                const skeletons = [];
                for (let i = 0; i < 3; i++) {
                    skeletons.push(
                        t.div({ rid: "skeleton_" + i, className: "list-item" }, t.div({ className: "skeleton-loader" })),
                    );
                }
                return skeletons;
            }
        },
        t.div(
            {
                hidden: () => data.isLoading || data.keys.length,
                className: "list-item",
            },
            t.div({ className: "content block txt-hint" }, "No API keys created yet."),
        ),
        () => {
            return data.keys.map((key) => {
                const isRevoked = !!key.revokedAt;
                const isExpired = key.expires && new Date(key.expires) <= new Date();

                return t.div(
                    { rid: "key_" + key.id, className: "list-item" },
                    t.div(
                        { className: "content" },
                        t.div(
                            { className: "flex gap-10 align-center" },
                            t.span({ className: "txt-bold" }, key.name),
                            isRevoked
                                ? t.span({ className: "badge danger" }, "revoked")
                                : isExpired
                                  ? t.span({ className: "badge" }, "expired")
                                  : t.span({ className: "badge success" }, "active"),
                        ),
                        t.div(
                            { className: "txt-sm txt-hint m-t-xs flex gap-10 wrap" },
                            t.span(
                                {
                                    ariaDescription: app.attrs.tooltip(
                                        (key.scopes || []).join(", "),
                                    ),
                                },
                                `${(key.scopes || []).length} scope(s)`,
                            ),
                            key.expires
                                ? t.span({}, "expires: ", app.components.formattedDate({ value: key.expires, short: true }))
                                : t.span({}, "no expiration"),
                            t.span({},
                                "last used: ",
                                key.lastUsedAt
                                    ? app.components.formattedDate({ value: key.lastUsedAt, short: true })
                                    : t.span({ className: "missing-value" }, "never"),
                            ),
                        ),
                    ),
                    t.div(
                        { className: "actions" },
                        !isRevoked &&
                            t.button(
                                {
                                    type: "button",
                                    className: "btn sm transparent secondary circle",
                                    title: "Edit",
                                    onclick: () => editKey(key),
                                },
                                t.i({ className: "ri-pencil-line", ariaHidden: true }),
                            ),
                        !isRevoked &&
                            t.button(
                                {
                                    type: "button",
                                    className: "btn sm transparent danger circle",
                                    title: "Revoke",
                                    onclick: () => revokeKey(key),
                                },
                                t.i({ className: "ri-shut-down-line", ariaHidden: true }),
                            ),
                    ),
                );
            });
        },
    );
}

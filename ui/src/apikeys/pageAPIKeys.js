import { apiKeysList } from "./apiKeysList";

export function pageAPIKeys(route) {
    app.store.title = "API keys";

    const data = store({
        resetList: null,
    });

    return t.div(
        { pbEvent: "pageAPIKeys", className: "page page-api-keys" },
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav(
                    { className: "breadcrumbs" },
                    t.div({ className: "breadcrumb-item" }, () => app.store.title),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                t.div({ className: "txt-hint m-b-base" },
                    "Create independent credentials for automation scripts. Each key can be named, scoped to a collection and actions, set to expire, and revoked immediately. The plaintext key is shown only on creation; the server keeps only an irreversible digest.",
                ),
                apiKeysList({
                    reset: () => data.resetList,
                }),
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}

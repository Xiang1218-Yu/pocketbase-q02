import { apiKeysList } from "./apiKeysList";
import { apiKeyCreateModal } from "./apiKeyCreateModal";

export function pageApiKeysSettings() {
    app.store.title = "API keys";

    const data = store({
        resetList: 0,
    });

    function resetList() {
        data.resetList = Date.now();
    }

    return t.div(
        { pbEvent: "pageApiKeysSettings", className: "page" },
        app.components.settingsSidebar(),
        t.div(
            { className: "page-content full-height" },
            t.header(
                { className: "page-header" },
                t.nav(
                    { className: "breadcrumbs" },
                    t.div({ className: "breadcrumb-item" }, "Settings"),
                    t.div({ className: "breadcrumb-item" }, () => app.store.title),
                ),
            ),
            t.div(
                { className: "wrapper m-b-base" },
                t.div({ className: "flex gap-10 align-center m-b-sm" },
                    t.div({ className: "txt-lg" }, "Automation API keys"),
                    app.components.refreshButton({
                        className: "btn sm transparent secondary circle",
                        onclick: resetList,
                    }),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm primary",
                            style: { marginLeft: "auto" },
                            onclick: () => {
                                app.modals.open(
                                    apiKeyCreateModal({
                                        onCreated: () => resetList(),
                                    }),
                                );
                            },
                        },
                        t.i({ className: "ri-add-line", ariaHidden: true }),
                        t.span({ className: "txt" }, "Create API key"),
                    ),
                ),
                t.div(
                    { className: "txt-sm txt-hint m-b-base" },
                    "API keys are independent credentials for automation scripts and CI jobs. ",
                    "The plaintext key is shown only once right after creation - store it securely. ",
                    "Keys can be scoped to specific collections and actions, can expire and can be revoked immediately.",
                ),
                apiKeysList({
                    reset: () => data.resetList,
                    onRevoked: () => resetList(),
                }),
            ),
            t.footer({ className: "page-footer" }, app.components.credits()),
        ),
    );
}

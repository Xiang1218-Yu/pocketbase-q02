/**
 * apiKeyScopesEditor renders a simple collection:action scope builder.
 *
 * @param {{scopes: string[]}} propsArg
 * @returns list of scope rows with collection + action inputs
 */
export function apiKeyScopesEditor(propsArg = {}) {
    const props = store({
        scopes: [],
        collections: [],
    });

    const watchers = app.utils.extendStore(props, propsArg);

    const ACTIONS = ["list", "view", "create", "update", "delete", "*"];

    function syncOut() {
        // mutate in place so the parent store reference keeps working
        props.scopes.splice(0, props.scopes.length, ...props.scopes.filter((s) => s));
    }

    function updateScope(index, patch) {
        const current = props.scopes[index] || "";
        const [collection = "*", action = "*"] = current.split(":");
        const next = { collection, action, ...patch };
        props.scopes[index] = `${next.collection}:${next.action}`;
        syncOut();
    }

    function removeScope(index) {
        props.scopes.splice(index, 1);
        syncOut();
    }

    function addScope() {
        props.scopes.push("*:view");
        syncOut();
    }

    return t.div(
        {
            pbEvent: "apiKeyScopesEditor",
            className: "block",
            onunmount: () => watchers.forEach((w) => w?.unwatch()),
        },
        () => {
            return (props.scopes || []).map((scope, index) => {
                const [collection = "*", action = "view"] = scope.split(":");

                return t.div(
                    { rid: "scope_" + index, className: "flex gap-10 m-b-xs align-center" },
                    t.input({
                        type: "text",
                        list: "apikey-collection-options",
                        className: "input grow",
                        placeholder: "collection name or *",
                        value: () => collection,
                        oninput: (e) => updateScope(index, { collection: e.target.value.trim() || "*" }),
                    }),
                    t.span({ className: "txt-hint" }, ":"),
                    t.select(
                        {
                            className: "select",
                            value: () => action,
                            onchange: (e) => updateScope(index, { action: e.target.value }),
                        },
                        ACTIONS.map((a) => t.option({ value: a }, a)),
                    ),
                    t.button(
                        {
                            type: "button",
                            className: "btn sm transparent danger circle",
                            title: "Remove scope",
                            onclick: () => removeScope(index),
                        },
                        t.i({ className: "ri-close-line", ariaHidden: true }),
                    ),
                );
            });
        },
        t.datalist(
            { id: "apikey-collection-options" },
            t.option({ value: "*" }),
            () => {
                return (props.collections || [])
                    .filter((c) => !c.name.startsWith("_"))
                    .map((c) => t.option({ value: c.name }));
            },
        ),
        t.button(
            {
                type: "button",
                className: "btn sm transparent secondary",
                onclick: addScope,
            },
            t.i({ className: "ri-add-line", ariaHidden: true }),
            t.span({ className: "txt" }, "Add scope"),
        ),
    );
}

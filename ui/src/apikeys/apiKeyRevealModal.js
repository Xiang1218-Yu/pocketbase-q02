export function openAPIKeyRevealModal(createResult) {
    const modal = apiKeyRevealModal(createResult);
    document.body.appendChild(modal);
    app.modals.open(modal);
}

function apiKeyRevealModal(result) {
    const plaintext = result?.key || "";
    const apiKey = result?.apiKey || {};

    const modal = t.div(
        {
            pbEvent: "apiKeyRevealModal",
            className: "modal popup sm api-key-reveal-modal",
            onafterclose: (el) => el?.remove(),
        },
        t.header(
            { className: "modal-header" },
            t.h5({ className: "m-auto txt-center" }, "Save your API key"),
        ),
        t.div(
            { className: "modal-content" },
            t.div(
                { className: "txt-center m-b-sm" },
                t.strong({}, () => apiKey.name || "API key"),
            ),
            t.div(
                { className: "txt-hint txt-sm txt-center m-b-sm" },
                "The key below is shown only once. Copy and store it securely now - it cannot be recovered later.",
            ),
            t.div(
                { className: "flex gap-10 m-b-base" },
                t.code(
                    {
                        className: "api-key-plaintext block txt-code txt-break-all",
                        onclick: (e) => {
                            const range = document.createRange();
                            range.selectNodeContents(e.target);
                            const selection = window.getSelection();
                            selection?.removeAllRanges();
                            selection?.addRange(range);
                        },
                    },
                    plaintext,
                ),
                app.components.copyButton(plaintext),
            ),
            t.div(
                { className: "modal-actions" },
                t.button(
                    {
                        type: "button",
                        className: "btn accent",
                        onclick: () => {
                            app.utils.copyToClipboard(plaintext);
                            app.toasts.success("API key copied.");
                            app.modals.close(modal);
                        },
                    },
                    "Copy and close",
                ),
            ),
        ),
    );

    return modal;
}

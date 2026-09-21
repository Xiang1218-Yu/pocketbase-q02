// API keys admin API helpers.
//
// The API keys collection is a system table and is not exposed through
// the regular record services, so the requests go through the generic
// PocketBase send() method.

const basePath = "/api/keys";

export async function getAPIKeys(options = {}) {
    const result = await app.pb.send(basePath, {
        method: "GET",
        ...options,
    });

    return result?.items || [];
}

export async function getAPIKey(id, options = {}) {
    return await app.pb.send(`${basePath}/${encodeURIComponent(id)}`, {
        method: "GET",
        ...options,
    });
}

export async function createAPIKey(payload, options = {}) {
    return await app.pb.send(basePath, {
        method: "POST",
        body: JSON.stringify(payload),
        ...options,
    });
}

export async function updateAPIKey(id, payload, options = {}) {
    return await app.pb.send(`${basePath}/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify(payload),
        ...options,
    });
}

export async function deleteAPIKey(id, options = {}) {
    return await app.pb.send(`${basePath}/${encodeURIComponent(id)}`, {
        method: "DELETE",
        ...options,
    });
}

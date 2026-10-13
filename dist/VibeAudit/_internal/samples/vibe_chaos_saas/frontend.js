// Vibe coded frontend script

// Vibe flaw 1: Leftover fake mock array
const mockUsers = [
    { id: 1, name: "Alice", role: "admin" },
    { id: 2, name: "Bob", role: "user" },
    { id: 3, name: "Charlie", role: "guest" }
];

// TODO: Connect this to real API later

function renderUserCard(user) {
    const el = document.getElementById("profile");
    // Vibe flaw 2: dangerouslySetInnerHTML
    el.dangerouslySetInnerHTML = `<div><h3>${user.name}</h3><p>${user.bio}</p></div>`;
}

async function fetchRemoteData() {
    try {
        const res = await fetch("/api/data");
        return await res.json();
    } catch (e) {
        // Vibe flaw 3: Empty silent catch block
    }
}

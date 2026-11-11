# examples/notes_server.py
from mcp.server import MCPServer

mcp = MCPServer("notes")
NOTES: dict[str, str] = {
    "welcome": "Hello! This is your notes server.",
    "contacts": "Anna: anna@example.com, IBAN DE89 3704 0044 0532 0130 00",
}


@mcp.tool()
def list_notes() -> list[str]:
    """List the titles of all notes."""
    return sorted(NOTES)


@mcp.tool()
def read_note(title: str) -> str:
    """Read one note by its title."""
    return NOTES.get(title, f"No note called {title!r}")


@mcp.tool()
def write_note(title: str, body: str) -> str:
    """Create or overwrite a note."""
    NOTES[title] = body
    return f"Saved {title!r}"


@mcp.tool()
def delete_note(title: str) -> str:
    """Delete a note permanently."""
    return f"Deleted {title!r}" if NOTES.pop(title, None) is not None else f"No note called {title!r}"


if __name__ == "__main__":
    mcp.run()  # stdio by default

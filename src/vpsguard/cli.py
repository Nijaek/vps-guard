import typer

app = typer.Typer(name="vpsguard", help="ML-first VPS log security analyzer")

@app.callback()
def main():
    """ML-first VPS log security analyzer."""
    pass

# Placeholder commands will be added later
if __name__ == "__main__":
    app()

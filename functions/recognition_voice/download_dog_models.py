"""Fetch the selected immutable model revisions during the final EC2 image build."""
from pathlib import Path
from urllib.request import urlretrieve

MODELS = (
    ("open-noodle/rfdetr-nano", "1618db5f22919339f4347d436da8c43afaf91926", "detection/model.onnx", "detection"),
    ("open-noodle/pet-recognition-base", "fa30eb7785ceb764d5c2840c4585fb89821be385", "recognition/model.onnx", "recognition"),
)
target = Path("/opt/dog-models")
target.mkdir(parents=True, exist_ok=True)
urlretrieve("https://www.apache.org/licenses/LICENSE-2.0.txt", target / "LICENSE-2.0.txt")
for repository, revision, filename, name in MODELS:
    root = f"https://huggingface.co/{repository}/resolve/{revision}"
    urlretrieve(f"{root}/{filename}", target / f"{name}.onnx")
    urlretrieve(f"{root}/README.md", target / f"{name}-MODEL-CARD.md")

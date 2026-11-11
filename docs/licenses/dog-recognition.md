# Dog recognition model attribution

Marvain uses unchanged public ONNX weights from Open Noodle; no model is trained by Marvain.

| Component | Immutable revision | Published license |
|---|---|---|
| Open Noodle pet-recognition-base | fa30eb7785ceb764d5c2840c4585fb89821be385 | Apache-2.0 |
| Open Noodle RF-DETR Nano export of Roboflow's COCO-pretrained detector | 1618db5f22919339f4347d436da8c43afaf91926 | Apache-2.0 |

Sources: https://huggingface.co/open-noodle/pet-recognition-base ; https://huggingface.co/open-noodle/rfdetr-nano ; https://github.com/roboflow/rf-detr ; https://github.com/facebookresearch/dinov2 .

The recognition model is a frozen DINOv2-base backbone with a trained 512-dimensional projection. Its publisher documents training on Dogs-World (CC0) and Cat Individual Images (CC BY), with DogFaceNet used only for evaluation. No dataset is redistributed here. The exact model cards are retained beside the image's model files; Apache 2.0 terms are included in the image. Published benchmark values are not Marvain acceptance results.

Inference follows the model cards: RGB square resizing, ImageNet normalization, RF-DETR's original 91-class IDs (dog 18), sigmoid class logits without NMS, then 224-pixel dog crops and cosine similarity of identity embeddings.

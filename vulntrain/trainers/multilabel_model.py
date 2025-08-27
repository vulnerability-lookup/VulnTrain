import torch
import torch.nn as nn
from transformers import AutoModelForSequenceClassification

class MultiLabelClassificationModel(AutoModelForSequenceClassification):
    def __init__(self, config):
        super().__init__(config)
        self.classifier = nn.Linear(config.hidden_size, config.num_labels)
        self.loss_fn = nn.BCEWithLogitsLoss()
        self.config = config

    def forward(self, input_ids=None, attention_mask=None, labels=None, **kwargs):
        outputs = super().forward(
            input_ids=input_ids,
            attention_mask=attention_mask,
            **kwargs
        )
        logits = self.classifier(outputs[0][:, 0, :])  
        loss = None
        if labels is not None:
            loss = self.loss_fn(logits, labels.float())
        return {"loss": loss, "logits": logits}

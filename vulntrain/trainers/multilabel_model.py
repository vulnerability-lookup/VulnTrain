import torch
from transformers import AutoModel, AutoConfig
from transformers.modeling_outputs import SequenceClassifierOutput

import torch.nn as nn

class MultiLabelClassificationModel(AutoModelForSequenceClassification):
    def __init__(self, config):
        super().__init__(config)
        self.pos_weight = None  # Ce sera défini plus tard depuis le script principal

    def forward(self, input_ids=None, attention_mask=None, labels=None, **kwargs):
        outputs = self.roberta(
            input_ids=input_ids,
            attention_mask=attention_mask,
            **kwargs
        )

        logits = self.classifier(outputs[0][:, 0, :])  # utiliser le token CLS

        if labels is not None:
            loss_fct = nn.BCEWithLogitsLoss(pos_weight=self.pos_weight.to(logits.device))
            loss = loss_fct(logits, labels.float())
            return (loss, logits)

        return logits

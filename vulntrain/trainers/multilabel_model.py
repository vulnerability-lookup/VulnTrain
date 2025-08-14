import torch
import torch.nn as nn
from transformers import RobertaModel, PreTrainedModel, RobertaConfig

class MultiLabelClassificationModel(PreTrainedModel):
    config_class = RobertaConfig

    def __init__(self, config):
        super().__init__(config)
        self.bert = RobertaModel(config)
        self.classifier = nn.Linear(config.hidden_size, config.num_labels)
        self.loss_fct = nn.BCEWithLogitsLoss()
        self.init_weights()

    def forward(self, input_ids=None, attention_mask=None, labels=None, **kwargs):
        # Nettoyer kwargs des arguments inattendus du Trainer
        kwargs.pop('num_items_in_batch', None)

        outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask, **kwargs)
        pooled_output = outputs.pooler_output  # ou outputs[1]

        logits = self.classifier(pooled_output)

        loss = None
        if labels is not None:
            # labels est un vecteur multi-hot float
            loss = self.loss_fct(logits, labels.float())

        output = (logits,)
        return ((loss,) + output) if loss is not None else output

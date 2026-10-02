"""Attack classification models.

Phase 1 placeholder. Supervised classifiers for attack categories
will be implemented in a later phase. Do not hard-code predictions.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class AttackClassifier:
    """Classify network traffic into attack categories.

    Training and inference are deferred to later phases.
    """

    def fit(self, *args, **kwargs) -> None:
        """Train the attack classifier.

        Raises:
            NotImplementedError: Always in Phase 1.
        """
        logger.debug("AttackClassifier.fit called (not implemented)")
        raise NotImplementedError(
            "Attack classifier training will be implemented in a later phase."
        )

    def predict(self, *args, **kwargs) -> None:
        """Predict attack labels for input samples.

        Raises:
            NotImplementedError: Always in Phase 1.
        """
        logger.debug("AttackClassifier.predict called (not implemented)")
        raise NotImplementedError(
            "Attack classifier inference will be implemented in a later phase."
        )

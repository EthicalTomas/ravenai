"""data/memory/__init__.py

Vector memory and semantic similarity search systems.
"""

from .embeddings import (
    EmbeddingConfig,
    EmbeddingGenerator,
    EmbeddingGenerator as EmbeddingsManager,
)
from .vector_space import (
    SimilarityMatch,
    VectorSpace,
    VectorSpace as VectorStore,
    VectorSpaceConfig,
    VectorSpaceStats,
)


__all__ = [
    "EmbeddingConfig",
    "EmbeddingGenerator",
    "EmbeddingsManager",
    "SimilarityMatch",
    "VectorSpace",
    "VectorSpaceConfig",
    "VectorSpaceStats",
    "VectorStore",
]

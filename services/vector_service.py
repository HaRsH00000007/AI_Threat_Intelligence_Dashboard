"""
Vector/Embedding Service
Generates embeddings for threat intelligence using Groq's embedding model
"""

from typing import Dict, Any, List, Optional
import numpy as np
from services.groq_client import generate_embedding
from utils.text_cleaner import clean_text
from utils.logger import log_activity
from config.settings import settings


def generate_embeddings(text: str) -> Dict[str, Any]:
    """
    Generate embedding vector for threat intelligence text
    
    Args:
        text: Input text to generate embeddings for
    
    Returns:
        dict: Embedding result containing:
            - embedding: List of float values (vector)
            - dimensions: Number of dimensions in vector
            - model: Model used for embedding
            - token_count: Approximate token count
            - text_preview: Preview of input text
    """
    try:
        # Clean text
        cleaned_text = clean_text(text)
        
        if not cleaned_text:
            raise ValueError("Input text is empty after cleaning")
        
        # Generate embedding using Groq
        embedding_vector = generate_embedding(cleaned_text)
        
        # Calculate token count (approximate)
        token_count = len(cleaned_text.split())
        
        result = {
            "embedding": embedding_vector,
            "dimensions": len(embedding_vector),
            "model": settings.EMBEDDING_MODEL,
            "token_count": token_count,
            "text_preview": cleaned_text[:200] + "..." if len(cleaned_text) > 200 else cleaned_text
        }
        
        log_activity("embedding", f"Generated {len(embedding_vector)}-dimensional embedding")
        
        return result
    
    except Exception as e:
        log_activity("error", f"Embedding generation failed: {str(e)}")
        raise Exception(f"Embedding generation error: {str(e)}")


def batch_generate_embeddings(texts: List[str]) -> List[Dict[str, Any]]:
    """
    Generate embeddings for multiple texts
    
    Args:
        texts: List of text strings
    
    Returns:
        list: List of embedding results
    """
    results = []
    
    for idx, text in enumerate(texts):
        try:
            result = generate_embeddings(text)
            results.append(result)
            log_activity("info", f"Batch embedding {idx + 1}/{len(texts)} completed")
        except Exception as e:
            log_activity("error", f"Batch embedding {idx + 1} failed: {str(e)}")
            results.append({
                "embedding": [],
                "dimensions": 0,
                "model": settings.EMBEDDING_MODEL,
                "token_count": 0,
                "text_preview": text[:100],
                "error": str(e)
            })
    
    return results


def calculate_similarity(embedding1: List[float], embedding2: List[float]) -> float:
    """
    Calculate cosine similarity between two embeddings
    
    Args:
        embedding1: First embedding vector
        embedding2: Second embedding vector
    
    Returns:
        float: Cosine similarity score (0-1)
    """
    try:
        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)
        
        # Cosine similarity
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        similarity = dot_product / (norm1 * norm2)
        
        # Normalize to 0-1 range
        similarity = (similarity + 1) / 2
        
        return float(similarity)
    
    except Exception as e:
        log_activity("error", f"Similarity calculation failed: {str(e)}")
        return 0.0


def find_similar_threats(
    query_embedding: List[float],
    threat_embeddings: List[Dict[str, Any]],
    top_k: int = 5
) -> List[Dict[str, Any]]:
    """
    Find most similar threats based on embedding similarity
    
    Args:
        query_embedding: Query embedding vector
        threat_embeddings: List of threat embedding dictionaries with 'embedding' key
        top_k: Number of top results to return
    
    Returns:
        list: Top-k most similar threats with similarity scores
    """
    try:
        similarities = []
        
        for threat in threat_embeddings:
            if 'embedding' in threat and threat['embedding']:
                similarity = calculate_similarity(query_embedding, threat['embedding'])
                similarities.append({
                    **threat,
                    'similarity_score': similarity
                })
        
        # Sort by similarity score
        similarities.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        # Return top-k
        return similarities[:top_k]
    
    except Exception as e:
        log_activity("error", f"Similar threat search failed: {str(e)}")
        return []


def cluster_threats(
    embeddings: List[List[float]],
    n_clusters: int = 5
) -> Dict[str, Any]:
    """
    Cluster threats based on embedding similarity
    
    Args:
        embeddings: List of embedding vectors
        n_clusters: Number of clusters to create
    
    Returns:
        dict: Clustering results with cluster assignments
    """
    try:
        from sklearn.cluster import KMeans
        
        if len(embeddings) < n_clusters:
            n_clusters = max(1, len(embeddings))
        
        # Convert to numpy array
        embedding_matrix = np.array(embeddings)
        
        # Perform K-means clustering
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        cluster_labels = kmeans.fit_predict(embedding_matrix)
        
        # Calculate cluster statistics
        cluster_sizes = np.bincount(cluster_labels)
        
        result = {
            "n_clusters": n_clusters,
            "cluster_labels": cluster_labels.tolist(),
            "cluster_sizes": cluster_sizes.tolist(),
            "cluster_centers": kmeans.cluster_centers_.tolist()
        }
        
        log_activity("clustering", f"Clustered {len(embeddings)} embeddings into {n_clusters} groups")
        
        return result
    
    except ImportError:
        log_activity("warning", "scikit-learn not available for clustering")
        return {
            "error": "Clustering requires scikit-learn library",
            "n_clusters": 0,
            "cluster_labels": [],
            "cluster_sizes": []
        }
    except Exception as e:
        log_activity("error", f"Clustering failed: {str(e)}")
        return {
            "error": str(e),
            "n_clusters": 0,
            "cluster_labels": [],
            "cluster_sizes": []
        }


def store_embedding(
    text: str,
    embedding: List[float],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Store embedding with metadata to disk
    
    Args:
        text: Original text
        embedding: Embedding vector
        metadata: Optional metadata dictionary
    
    Returns:
        str: Path to stored embedding file
    """
    import json
    import os
    from datetime import datetime
    
    try:
        # Create embedding data structure
        embedding_data = {
            "text_preview": text[:500],
            "embedding": embedding,
            "dimensions": len(embedding),
            "model": settings.EMBEDDING_MODEL,
            "created_at": datetime.now().isoformat(),
            "metadata": metadata or {}
        }
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"embedding_{timestamp}.json"
        filepath = os.path.join(settings.VECTORS_DIR, filename)
        
        # Save to file
        with open(filepath, 'w') as f:
            json.dump(embedding_data, f, indent=2)
        
        log_activity("storage", f"Embedding stored to {filepath}")
        
        return filepath
    
    except Exception as e:
        log_activity("error", f"Failed to store embedding: {str(e)}")
        raise


def load_embedding(filepath: str) -> Dict[str, Any]:
    """
    Load embedding from disk
    
    Args:
        filepath: Path to embedding file
    
    Returns:
        dict: Loaded embedding data
    """
    import json
    
    try:
        with open(filepath, 'r') as f:
            embedding_data = json.load(f)
        
        log_activity("storage", f"Embedding loaded from {filepath}")
        
        return embedding_data
    
    except Exception as e:
        log_activity("error", f"Failed to load embedding: {str(e)}")
        raise


def get_embedding_statistics(embedding: List[float]) -> Dict[str, Any]:
    """
    Calculate statistics for an embedding vector
    
    Args:
        embedding: Embedding vector
    
    Returns:
        dict: Statistical information
    """
    try:
        vec = np.array(embedding)
        
        return {
            "dimensions": len(embedding),
            "mean": float(np.mean(vec)),
            "std": float(np.std(vec)),
            "min": float(np.min(vec)),
            "max": float(np.max(vec)),
            "norm": float(np.linalg.norm(vec)),
            "non_zero_count": int(np.count_nonzero(vec))
        }
    
    except Exception as e:
        log_activity("error", f"Failed to calculate embedding statistics: {str(e)}")
        return {}


def reduce_dimensions(
    embeddings: List[List[float]],
    n_components: int = 2
) -> np.ndarray:
    """
    Reduce embedding dimensions for visualization
    
    Args:
        embeddings: List of high-dimensional embeddings
        n_components: Target number of dimensions (2 or 3 for visualization)
    
    Returns:
        numpy.ndarray: Reduced embeddings
    """
    try:
        from sklearn.decomposition import PCA
        
        embedding_matrix = np.array(embeddings)
        
        pca = PCA(n_components=n_components)
        reduced = pca.fit_transform(embedding_matrix)
        
        log_activity("info", f"Reduced embeddings from {embedding_matrix.shape[1]}D to {n_components}D")
        
        return reduced
    
    except ImportError:
        log_activity("warning", "scikit-learn not available for dimension reduction")
        return np.array([])
    except Exception as e:
        log_activity("error", f"Dimension reduction failed: {str(e)}")
        return np.array([])
"""
transcriber.py - Local Speech-to-Text Transcription Engine
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

Integrates local faster-whisper STT with graceful fallbacks, safe temporary
file handling, audio file validation (WAV, MP3, M4A), and ffmpeg configuration.
"""

import os
import sys
import tempfile
import time
from typing import Dict, Any, Optional, List, Tuple

# Ensure FFmpeg from imageio_ffmpeg is accessible in system PATH
try:
    import imageio_ffmpeg
    ffmpeg_exe = imageio_ffmpeg.get_ffmpeg_exe()
    ffmpeg_dir = os.path.dirname(ffmpeg_exe)
    if ffmpeg_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = ffmpeg_dir + os.pathsep + os.environ.get("PATH", "")
except Exception:
    pass

# Suppress Hugging Face symlink warnings on Windows
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"

# Module-level model cache to prevent reloading across Streamlit interactions
_CACHED_MODEL = None
_MODEL_NAME = "tiny"


def is_whisper_available() -> bool:
    """Checks if faster-whisper is installed and importable."""
    try:
        import faster_whisper
        return True
    except ImportError:
        return False


def get_whisper_model(model_size: str = "tiny"):
    """
    Retrieves or initializes the cached WhisperModel instance on CPU with int8 quantization.
    """
    global _CACHED_MODEL, _MODEL_NAME
    if _CACHED_MODEL is not None and _MODEL_NAME == model_size:
        return _CACHED_MODEL

    from faster_whisper import WhisperModel
    # Load model on CPU with int8 quantization for ultra-fast, memory-efficient inference
    _CACHED_MODEL = WhisperModel(model_size, device="cpu", compute_type="int8")
    _MODEL_NAME = model_size
    return _CACHED_MODEL


def validate_audio_file(uploaded_file, max_size_mb: int = 30) -> Tuple[bool, Optional[str], str]:
    """
    Validates uploaded audio file format and size constraints.
    
    Returns:
        (is_valid: bool, error_message: Optional[str], file_extension: str)
    """
    if uploaded_file is None:
        return False, "No audio file provided.", ""

    name = uploaded_file.name.lower()
    allowed_extensions = {".wav", ".mp3", ".m4a"}
    ext = os.path.splitext(name)[1]

    if ext not in allowed_extensions:
        return False, f"Unsupported audio extension '{ext}'. Allowed: WAV, MP3, M4A.", ext

    # Check file size
    size_bytes = uploaded_file.size
    max_bytes = max_size_mb * 1024 * 1024
    if size_bytes > max_bytes:
        return False, f"File size exceeds safety limit ({round(size_bytes / (1024*1024), 1)} MB > {max_size_mb} MB).", ext

    return True, None, ext


def transcribe_audio_file(
    uploaded_file,
    model_size: str = "tiny",
    progress_callback=None
) -> Dict[str, Any]:
    """
    Transcribes an uploaded audio file into text using local Whisper.
    
    Args:
        uploaded_file: Streamlit UploadedFile object or file-like binary buffer.
        model_size: Size of Whisper model ('tiny' recommended for CPU).
        progress_callback: Optional callable for UI progress updates.
        
    Returns:
        Dictionary:
        - success: bool
        - transcript: str (full text)
        - segments: list of dicts (start, end, text)
        - duration_seconds: float
        - processing_time: float
        - error: Optional[str]
    """
    if not is_whisper_available():
        return {
            "success": False,
            "transcript": "",
            "segments": [],
            "duration_seconds": 0.0,
            "processing_time": 0.0,
            "error": "faster-whisper is not installed. Please use Demo Mode or install faster-whisper."
        }

    is_valid, err_msg, ext = validate_audio_file(uploaded_file)
    if not is_valid:
        return {
            "success": False,
            "transcript": "",
            "segments": [],
            "duration_seconds": 0.0,
            "processing_time": 0.0,
            "error": err_msg
        }

    temp_path = None
    t0 = time.time()

    try:
        # Write bytes safely to temporary file
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(uploaded_file.getvalue())
            temp_path = tmp.name

        if progress_callback:
            progress_callback(0.2, "Initializing local Whisper model...")

        model = get_whisper_model(model_size)

        if progress_callback:
            progress_callback(0.5, "Transcribing voice audio segments...")

        segments_generator, info = model.transcribe(
            temp_path,
            beam_size=5,
            vad_filter=True,
            vad_parameters=dict(min_silence_duration_ms=500)
        )

        segments_list = []
        full_text_pieces = []

        for segment in segments_generator:
            text = segment.text.strip()
            if text:
                segments_list.append({
                    "start": round(segment.start, 2),
                    "end": round(segment.end, 2),
                    "text": text
                })
                full_text_pieces.append(text)

        if progress_callback:
            progress_callback(1.0, "Transcription completed.")

        full_transcript = " ".join(full_text_pieces).strip()
        elapsed = round(time.time() - t0, 2)
        total_audio_duration = round(info.duration, 2) if hasattr(info, "duration") else 0.0

        if not full_transcript:
            return {
                "success": False,
                "transcript": "",
                "segments": [],
                "duration_seconds": total_audio_duration,
                "processing_time": elapsed,
                "error": "The audio file was processed, but no audible speech was detected."
            }

        return {
            "success": True,
            "transcript": full_transcript,
            "segments": segments_list,
            "duration_seconds": total_audio_duration,
            "processing_time": elapsed,
            "error": None
        }

    except Exception as e:
        return {
            "success": False,
            "transcript": "",
            "segments": [],
            "duration_seconds": 0.0,
            "processing_time": round(time.time() - t0, 2),
            "error": f"Transcription error: {str(e)}"
        }

    finally:
        # Ensure temporary file is safely deleted
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

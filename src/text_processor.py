import unicodedata
from PyPDF2 import PdfReader

def normalize_text(text):
    """Normalize text, handling accented characters properly"""
    result = ''
    for c in text:
        normalized = unicodedata.normalize('NFKD', c)
        for base_c in normalized:
            if not unicodedata.combining(base_c) and base_c.isalpha():
                result += base_c.lower()
    return result

def load_and_normalize_text(pdf_file):
    """Load text from PDF and normalize it"""
    try:
        reader = PdfReader(pdf_file)
        text = ''.join(page.extract_text() for page in reader.pages)
        normalized_text = normalize_text(text)
        print(f"Processed text length: {len(normalized_text)} characters")
        return normalized_text
    except Exception as e:
        raise Exception(f"Error loading PDF: {e}")
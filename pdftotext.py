import sys
from PyPDF2 import PdfReader

def main():
    # Check if the file name is provided as an argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <pdf_file>")
        sys.exit(1)

    # Get the PDF file name from the command-line argument
    pdf_file = sys.argv[1]

    try:
        # Create a PdfReader object
        reader = PdfReader(pdf_file)

        # Loop through all pages and print extracted text to stdout
        for page in reader.pages:
            print(page.extract_text())

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

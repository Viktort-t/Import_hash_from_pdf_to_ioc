[Русская версия](README.md)

# Hash Processing and IOC Generation

This project extracts hashes from a given PDF file, filters them using a caching mechanism, and generates IOC (Indicator of Compromise) files in XML format. The application supports progress indication for better transparency during execution.

## Features
- Extracts text from PDF files using `PyMuPDF`.
- Identifies hashes (MD5, SHA1, SHA256, SHA512) using regular expressions.
- Checks hashes against the Kaspersky OpenTIP API with caching for improved performance.
- Processes hash checks in parallel using `ThreadPoolExecutor`.
- Generates IOC files in XML format and splits them if the size exceeds 2 MB.
- Provides real-time progress updates using `tqdm`.

## Requirements
### Dependencies
- Python 3.7+
- Install the required packages:
  ```bash
  pip install -r requirements.txt
  ```

### Libraries
- `PyMuPDF` for PDF text extraction
- `tqdm` for progress indication
- `requests` for API interaction
- `concurrent.futures` for parallel processing

## Usage
### 1. Set Up Input
Place the PDF file you want to process in a directory of your choice and note its file path.

### 2. Configure Parameters
In the `main()` function:
- Set the `pdf_path` variable to the full path of your PDF file.
- Optionally change the output directory by updating `output_directory`.

### 3. Run the Script
Execute the script using Python:
```bash
python main.py
```

### Output
- Extracted and filtered hashes are saved in text files.
- Generated IOC files are saved in XML format in the output directory.

## File Structure
```plaintext
project/
├── main.py                 # Main script for processing PDF to IOC files
├── requirements.txt        # Required Python packages
├── output_ioc/             # Default output directory for generated IOC files
├── test/                   # (Optional) Directory for test files and data
└── README.md               # Project documentation
```

## Example Workflow
### Input PDF
Path: `C:\Users\User\Documents\sample.pdf`

### Configuration
```python
pdf_path = r"C:\Users\User\Documents\sample.pdf"
output_directory = "output_ioc"
```

### Execution
```bash
python main.py
```

### Output
```
Извлечение текста из PDF: 100%|████████████████████| 10/10 [00:02<00:00,  4.12it/s]
Проверка хэшей: 100%|███████████████████████████| 100/100 [00:05<00:00, 18.05it/s]
Создано 2 IOC-файлов.
```
Files generated in the `output_ioc/` directory:
- `sample_hashes.txt`
- `sample_<UUID>.ioc`

## Customization
- **Progress Indication**: Modify `desc` parameters in `tqdm` calls to change progress labels.
- **Parallelism**: Adjust the `max_workers` parameter in `ThreadPoolExecutor` for optimal performance on your system.
- **Max File Size**: Update the `max_file_size` parameter in `split_and_save_ioc()` for custom size limits.

## Troubleshooting
- **Missing Dependencies**: Ensure all required libraries are installed using `pip install -r requirements.txt`.
- **API Errors**: Verify your internet connection and check the availability of the Kaspersky OpenTIP API.
- **Large Files**: For very large PDF files, consider increasing system resources or optimizing the number of parallel workers.

## Contribution
Feel free to contribute to this project by opening issues or submitting pull requests. For major changes, please discuss your ideas first.

## License
This project is licensed under the MIT License. See the LICENSE file for details.


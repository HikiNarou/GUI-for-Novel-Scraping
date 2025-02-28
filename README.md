![Project Screenshot]([https://i.ibb.co.com/PGx4rZZq/image.png])

## Description

**Integrated Advanced GUI Scraper** is a powerful and versatile GUI-based Python application, designed for deep and efficient scraping of web content. The application integrates two main modules in one easy-to-use interface:

1. **Text Scraper:** This module allows you to extract blog posts from various websites. Its features include distributed crawling for faster browsing, parallel image download with auto retry mechanism, and conversion of scraping results to different file formats such as PDF, EPUB, and TXT.
2. **Image OCR Scraper:** This module focuses on extracting text from images found in web posts. It downloads images and then applies Optical Character Recognition (OCR) to convert those images into searchable and editable text. *(Notes: The OCR implementation in this version is a dummy and needs to be replaced with an actual OCR engine such as Tesseract for full functionality).*

The app is built using PyQt5 for a responsive and intuitive graphical interface. It is suitable for a variety of tasks such as archiving blog content, collecting text data from the web, or extracting text from images for research or documentation purposes.

## Key Features

### General Features

* PyQt5-based Graphical User Interface (GUI):** An intuitive and easy-to-use interface with two main tabs for Text Scraper and Image OCR Scraper.
* Integrated Activity Log:** A real-time log window displays the scraping process, errors, and other important information for monitoring and debugging.
* Flexible Configuration Options:** Customizable settings via the GUI, including scraping mode (text or URL labels), maximum number of posts scraped, use of Selenium for dynamic web pages, and parallel crawling options.
* **Saving Scraping Results:** Option to save scraping results in PDF, EPUB, or TXT formats, allowing flexibility in the use of extracted data.
* Robust Error Handling:** Comprehensive error handling and logging mechanisms to ensure a stable and informative scraping process.

### Text Scraper Features
**Distributed Crawling with ThreadPoolExecutor:** Speed up the scraping process by using distributed crawling via `ThreadPoolExecutor`, `Queue`, and synchronization with lock to handle multiple requests simultaneously.
**Parallel Image Download:** Download images from blog posts in parallel, significantly reducing image download time, especially for posts with multiple images.
* Automatic Retry Mechanism for Image Downloads:** Implementation of an automatic retry mechanism for failed image downloads due to network issues or temporary server errors, ensuring all relevant images are downloaded as optimally as possible.
* **Convert Output to Multiple Formats:** Supports converting scraping results to PDF, EPUB, and TXT formats.
* PDF:** Convert to PDF with custom styling for professional and easy-to-read presentations.
* EPUB:** EPUB file creation for an optimized reading experience on e-readers and mobile devices.
**TXT:** Option to save content as plain text files for simple and flexible data usage.

### Image OCR Scraper Features
* Text Extraction from Images:** A specialized module for downloading images from web posts and running OCR to extract the text contained in those images.
* Selenium Usage Option:** Ability to use Selenium to handle dynamic websites that load content using JavaScript, ensuring effective scraping of different types of websites.
* OCR (Dummy) Module Integration:** *(Currently, the application includes a dummy OCR function. Users are expected to replace this dummy function with an actual OCR implementation, such as using the `pytesseract` library and the Tesseract OCR engine for full OCR functionality.)* *
* **Saving OCR Results:** The option to save OCR results in PDF, EPUB, or TXT formats, allowing you to archive and use the text extracted from images.

## Installation

Before running Integrated Advanced GUI Scraper, you need to ensure that Python and the following packages are installed on your system.

### Prerequisites

**Python 3.x:** This application is written in Python 3. Make sure you have Python 3.x installed on your system. You can download Python from the official website [python.org](https://www.python.org/).
**pip:** pip is the package installer for Python.It is usually installed by default with the latest version of Python.

### Required Python Packages
Install the following Python packages using `pip`. Open a terminal or command prompt and run the following commands one by one:

```bash
pip install PyQt5
pip install requests
pip install beautifulsoup4
pip install pdfkit
pip install selenium
```

Configuring pdfkit (Optional)
* pdfkit relies on the installation of wkhtmltopdf.You need to manually install wkhtmltopdf for the PDF conversion to work.
* Windows:Download the installer from the wkhtmltopdf website and install it. pdfkit can usually find the installation automatically. If not, you may need to manually configure the path to the wkhtmltopdf executable in the code (although in this script, the default configuration is used).

Installation:
Step will installing of this watchdog module
1. git clone https://github.com/syelburgi/watchdog
2. cd watchdog
3. pip install -r requirements.txt
4. python3 main.py -I <input_folder_to_be_monitored> -O <output_dir_where_PII_Stored>

Ex: python3 main.py -I C:/Users/input/ -O C:/Users/output/
An Sample files are given . Just copy these file to the input folder. you see the PII filtered file in output folder if PII information is found else file is copied as it is.
Todecode folder is created in output directory .

Requirements:
1.Python3.6
2.Windows 10 and should work with unix based systems.

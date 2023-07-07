# Security-Content-Helper

![logo](https://github.com/tccontre/Security-Content-Helper/assets/26181693/8456a3f0-28e3-4677-a393-23cbcda24276)


## Description:
<b>Security-Content-Helper</b> is a simple tool specifically designed to facilitate the filtering, analysis, and possible development of Splunk security content correlation searches bae on security content. It empowers security analysts by providing efficient data handling capabilities and enabling the creation of effective detection rules and correlations within the Splunk environment.


## Installation:
- Recommended to create a virtual environment to self-contained the dependencies of this project and to avoid conflict for your existing python settings

  - Instal virtual environment
  ```
  python -m pip install venv
  ```
  - Navigate to the directory where you want to create your virtual environment and run the command
  
  ```
  python -m venv myenv
  ```
  
  - activate the virtual environment
    
    Windows:
    ```
    myenv\Scripts\activate
    ```

    Mac/linux:
    ```
    source myenv/bin/activate
    ```
  - to deactive the virtual environment
    ```
    deactivate
    ```
- Install all required libraries or just use requirements.txt
  - using requirements.txt
    ```
    pip install -r requirements.txt
    ```
  - needed libraries:
    ```
    pip install streamlit
    pip install pandas
    pip install pyyaml
    pip install Pillow
    ```
## HowTo:

- git clone the project
  ```
  git clone 
  ```
- run the application
  ```
  streamlit run security_content_helper.py
  ```

## Features:
### Configuration
Provide user-friendly access to key fields in the config.ini file, enabling users to easily modify and enhance its settings to suit their specific needs and optimize usage.

![cofiguration](https://github.com/tccontre/Security-Content-Helper/assets/26181693/1f0cd270-4007-4df3-9511-0c13de03fb4b)

```
- security_content_path     : the security content detections folder path
- filter_fields             : exposed security content detection yaml fields for filtering
- substring_filter          : exposed security content detection yaml fields for sub-string filtering
- correlation_filter_fields : exposed security content detection yaml fields for correlation search filtering and development
- correlation_filter_substr : exposed security content detection yaml fields for sub-string correlation search development and filtering
- correlation template      : experimental correlation search template
```

### Generate Data
Generate a comprehensive security content data frame that serves as the foundation for efficient data filtering and processing across various tasks within this tool.


![generate](https://github.com/tccontre/Security-Content-Helper/assets/26181693/56c7e447-92bf-44bf-9643-7c88bfcc2672)

It will also generate <b>security_content_df.json</b> to create a structured dataset that can be utilized for various security-related tasks.

![generate2](https://github.com/tccontre/Security-Content-Helper/assets/26181693/8f5c9633-b5a0-4f93-8df6-939ffcd03009)

### Security Content Filter
a feature to filter the security content by detection name, search, descriptions, analytic story, mitre attack id and etc

![sec_filter](https://github.com/tccontre/Security-Content-Helper/assets/26181693/9602f611-792d-4a60-8860-7e679002a94d)

### Correlation Search Helper 
<b><i>(this is only suggestion base on filter fields from security content. It still need manual testing and tuning)</i></b>

filtering feature that allows users to easily narrow down the security content based on specific fields, facilitating efficient correlation search development.

![cor_filter](https://github.com/tccontre/Security-Content-Helper/assets/26181693/c5298b4a-bbb2-4f64-8b43-37a7dc61ed59)

### Pre-Processed Data
pre processed group of detections for correlation searches

![pre-process](https://github.com/tccontre/Security-Content-Helper/assets/26181693/657991dc-5075-4c6a-a27e-a05066cc9c7a)



## Author
[Teoderick Contreras](https://twitter.com/tccontre18)

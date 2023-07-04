import streamlit as st
import os
import sys
import re
from pathlib import Path
import yaml
import json
import pandas as pd
from PIL import Image
import configparser


class Utility:

    def __init__(self):
        self.curdir = os.getcwd()
        self.icon_img_path = os.path.join(self.curdir,"images/Br3akp0int.png")
        self.banner_img_path = os.path.join(self.curdir,"images/banner.png")
        self.SECURITY_CONTENT_PATH = ""
        self.HOME_PATH = Path.home()
        self.GENERATED_JSON_FILE_NAME = "security_content_df.json"
        self.common_field_name = { "name" : "source",
                     "tags.analytic_story":"All_Risk.analyticstories",
                     "tags.mitre_attack_id": "All_Risk.annotations.mitre_attack.mitre_technique_id",
                     "tags.risk_score": "All_Risk.calculated_risk_score",
                     "description": "All_Risk.mitre_attack_mitre_description"
                    
                     }
        return

    def render_image(self,image_file_path,caption_note=""):
        img = Image.open(image_file_path)
        st.image(img,caption=caption_note)
        return

    def banner(self):

        self.render_image(self.banner_img_path)
        st.divider()
        st.sidebar.success("Select a task to execute.")
        with st.sidebar:
            self.render_image(self.icon_img_path,"Br3akp0int")
        return
    
    def read_config(self):
        # Create a new configuration object
        config = configparser.ConfigParser()

        # Read the configuration from the file
        config.read('config.ini')
        return config
    
    def update_config(self, config, tag, value):
        config['Settings'][tag] = value
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        return

    def expand_path(self, file_path):
        if "~" in file_path:
            return str(file_path).replace("~", str(self.HOME_PATH))
        else:
            return file_path

    def enumerate_folder_path(self, folder_path):
        for dirs, subdirs, macro_list in os.walk(self.expand_path(folder_path)):
            return dirs, subdirs, macro_list

    def delete_old_json_data(self):
        json_file_path = os.path.join(self.curdir, self.GENERATED_JSON_FILE_NAME)
        if os.path.exists(json_file_path):
            st.warning("removing old {} ...\n".format(self.GENERATED_JSON_FILE_NAME),icon="ℹ️")
            os.remove(json_file_path)
            st.warning("{} was successfully removed! ...\n".format(self.GENERATED_JSON_FILE_NAME), icon="ℹ️")
        else:
            st.info("{} is not exist ...\n".format(self.GENERATED_JSON_FILE_NAME),icon="ℹ️")
        return    


    def generate_json_data(self, option_detection_type, detection_types):
        data_gen_list = []
        for dt in option_detection_type:
            if dt in detection_types:
                
                detection_type_path = ""

                detection_type_path = os.path.join(self.SECURITY_CONTENT_PATH, dt)

                st.info("processing security content: {} detection list".format(detection_type_path), icon="ℹ️")

                dirs, subdirs, detection_files = self.enumerate_folder_path(detection_type_path)

                st.write("Total Number of Analytics : ", len(detection_files))
                
                with st.spinner("generating data in progress. Please wait!!"):
                    
                    for i in detection_files:
                        det_file_path = self.expand_path(os.path.join(detection_type_path, i))
                        with open(det_file_path, "r") as f:
                            yml_buff = yaml.safe_load(f)
                            data_gen_list.append(yml_buff)
                    df = pd.concat([pd.json_normalize(data) for data in data_gen_list], ignore_index=True)
                    #df = df.applymap(str)
                    df['tags.observable'] = df['tags.observable'].astype(str)
                    df['tests'] = df['tests'].astype(str)
                    st.dataframe(df)
                    st.write(data_gen_list)
        # Save the DataFrame as a JSON file
        st.success('{} was successfully generated!!!\n'.format(self.GENERATED_JSON_FILE_NAME), icon="✅")
        df.to_json(self.GENERATED_JSON_FILE_NAME, orient='records')
        
        return
    
    def json_to_df(self, json_file_path):
        if os.path.isfile(json_file_path):
            df = pd.read_json(json_file_path)
        return df
    
    def parse_security_content_tag(self, df):
        return df.columns.tolist()

    def check_empty_list(self, target_list):
        if len(target_list) == 0 or (len(target_list) == 1 and target_list[0] == ""):
            return False
        else:
            return True 

    def filter_via_substring(self, option_list, column_name, FILTERED_DF):
        #st.write(option_list)
        FILTERED_DF_ = FILTERED_DF
        FILTERED_DF_BUFF = pd.DataFrame()
        FILTERED_DF[column_name] = FILTERED_DF[column_name].astype(str)
        for option_val in option_list:
            #FILTERED_DF_ = FILTERED_DF[FILTERED_DF[column_name].apply(lambda x: str(option_val) in str(x))]
            FILTERED_DF_ = FILTERED_DF[FILTERED_DF[column_name].str.contains(str(option_val), case=False)]
            FILTERED_DF_BUFF = pd.concat([FILTERED_DF_BUFF, FILTERED_DF_], ignore_index=True)
            if FILTERED_DF_BUFF.empty:
                st.error("filtered data frame is empty")
            else:
                with st.expander("Filtered DataFrame"):
                    st.dataframe(FILTERED_DF_BUFF,width=1000, height=600)
        return FILTERED_DF_BUFF
    
    def get_config_value(self, config, field_name):
        text_input_init = config['Settings'][field_name]
        text_input_value = st.text_input("{} :".format(field_name),value = text_input_init)
        return text_input_value
    
    def update_config_field(self, config, field_name, field_value):
        if field_value == "":
            st.error("please specify the security content folder path :point_up_2:")
        else:
            st.success(":white_check_mark: *successfully saved!*")
            #st.success(":white_check_mark: {}: SAVED! ".format(field_name))
            #st.success("{}: {} 	:white_check_mark:".format(field_name, field_value))
            self.update_config(config, field_name, field_value)
        return
    
    def filter_data_frame(self, FILTERED_DF, tag_dict):
        for field_name, field_value in tag_dict.items():
                if (self.check_empty_list(field_value)):
                    #st.write(field_name, field_value, len(field_value))
                    st.success("filtered by {}: {}".format(field_name, field_value),icon="📎")
                    FILTERED_DF = self.filter_via_substring(field_value, field_name, FILTERED_DF)
                    tag_dict[field_name] = field_value
        return FILTERED_DF, tag_dict
    
    def count_detection_type(self, FILTERED_DF):
        counts = FILTERED_DF['type'].value_counts()
        counts_df = pd.DataFrame({"detection type count in this filter":counts.values}, index=counts.index)

        counts_df = counts_df.transpose()
        st.dataframe(counts_df)
        return
    
    def generate_splunk_search_condition(self, row_len, correlation_template, filter_values_dict):
        ## detection type is still not supported in correlation search so im popping it out
        if 'type' in filter_values_dict:
            filter_values_dict.pop('type')
        updated_correlation_search = correlation_template
        temp_conditional_search = ""
        for tag_name, filter_values in filter_values_dict.items():
            if not self.check_empty_list(filter_values) or updated_correlation_search == "":
                continue
            else:
                temp_conditional_search += "{} IN ({}) ".format(self.common_field_name[tag_name], ", ".join(["\"*{}*\"".format(s) for s in filter_values]))
                #st.code(temp_conditional_search, language='splunkSpl (splunk-spl)')
                updated_correlation_search = correlation_template.replace("<<condition_splunk_search>>", temp_conditional_search)
        with st.expander('generated correlation search'):
            updated_correlation_search = updated_correlation_search.replace("<<source_count_condition>>", row_len)
            st.success('generated correlation search ', icon="✅")
            st.code(updated_correlation_search, language='splunkSpl (splunk-spl)')
        return 
    
    def merge_dicts(self, dict1, dict2):
        dict_concatenated = {}
        for key in set(dict1.keys()).union(dict2.keys()):
            if key in dict1 and key in dict2:
                dict_concatenated[key] = dict1[key] + dict2[key]
            elif key in dict1:
                dict_concatenated[key] = dict1[key]
            else:
                dict_concatenated[key] = dict2[key]

        return dict_concatenated

    def pre_process_by_tag(self, json_df, field_tag, perc_, corr_template):
        option_analytic_story = json_df[field_tag].explode().unique()
        if (self.check_empty_list(option_analytic_story)):
            for  story_ in option_analytic_story:
                FILTERED_DF = json_df
                temp_dict = {}
                temp_list = []
                temp_list.append(story_)
                temp_dict[field_tag] = temp_list
                FILTERED_DF, option_analytic_story_ = self.filter_data_frame(FILTERED_DF, temp_dict)
                self.count_detection_type(FILTERED_DF)
                count_val = int(len(FILTERED_DF)*float(perc_))
                st.write(count_val)
                if int(len(FILTERED_DF)) == 1 or count_val < 1:
                    count_val = 1
                else:
                    pass
                self.generate_splunk_search_condition(str(count_val), corr_template, temp_dict)

import streamlit as st
import os
import sys
import re
from pathlib import Path
import yaml
import json
import pandas as pd
from PIL import Image
from utility.utilities import Utility
"""
Author: Teoderick Contreras - Br3akp0int
Description: a simple streamlit tool designed specifically to facilitate the filtering, analysis, 
             and development of Splunk security content correlation searches for enhanced security operations. 
             It empowers security analysts by providing efficient data handling capabilities and enabling the creation 
             of effective detection rules and correlations within the Splunk environment.
"""

#################################

curdir = os.getcwd()
ut = Utility()
FILTERED_DF = pd.DataFrame()
#################################
def intro():
    
    ut.banner()

    col1, col2 = st.columns((2, 3))

    with col1:
        st.markdown("### **:blue[Configuration]**")
        text_input_init = ""
        config = ut.read_config()
        with st.expander("configuration"):
            security_content_file_path = ut.get_config_value(config, 'security_content_path')
            ut.update_config_field(config, 'security_content_path', security_content_file_path)
            
            filter_fields_values = ut.get_config_value(config, 'filter_fields')
            ut.update_config_field(config, 'filter_fields', filter_fields_values)

            filter_substr = ut.get_config_value(config, 'substring_filter')
            ut.update_config_field(config, 'substring_filter', filter_substr)

            correlation_filters = ut.get_config_value(config, 'correlation_filter_fields')
            st.markdown("*:blue[note: as of now, only these fields are available]*")
            ut.update_config_field(config, 'correlation_filter_fields', correlation_filters)

            correlation_substr = ut.get_config_value(config, 'correlation_filter_substr')
            st.markdown("*:blue[note: as of now, only these fields are available]*")
            ut.update_config_field(config, 'correlation_filter_substr', correlation_substr)

            correlation_templt = config["Settings"]["correlation_template"]
            txt_area_val = st.text_area("correlation template", correlation_templt)
            ut.update_config_field(config, 'correlation_template', txt_area_val)


    with col2:
        image_dir_path = os.path.join(curdir, "images")
        with st.container():
            st.markdown("### **:blue[Introduction]**")
            st.markdown("**:blue[Description]**: This tool is specifically designed to facilitate the filtering, analysis, and development of Splunk security content correlation searches for enhanced security operations. It empowers security analysts by providing efficient data handling capabilities and enabling the creation of effective detection rules and correlations within the Splunk environment.")
            st.markdown("#### :blue[Features]:")
            st.markdown("- **:blue[Generate Data Frame]** that serves as the foundation for efficient data filtering and processing across various tasks within this tool")
            with st.expander("Example:"):
                ut.render_image(os.path.join(image_dir_path,"generate.png"), "Generate your Data Frame from Security Content")
                ut.render_image(os.path.join(image_dir_path,"generate2.png"), "Generate security_content_df.json to create a structured dataset that can be utilized for various security-related tasks.")
            st.markdown("- **:blue[Security Content Filter]** by detection name substring, detection name, analytic story, mitre attack id and etc.")
            with st.expander("Example:"):
                ut.render_image(os.path.join(image_dir_path,"sec_filter.png"), "Security Content Filter")
            st.markdown("- **:blue[Correlation Search Helper]** filtering feature that allows users to easily narrow down the security content based on specific fields, facilitating efficient correlation search development.")
            with st.expander("Example:"):
                ut.render_image(os.path.join(image_dir_path,"cor_filter.png"), "Filter your Data Frame for correlation searches development")
            st.markdown("- **:blue[Pre Processed Data]** by analytic story and mitre attack id")
            with st.expander("Example:"):
                ut.render_image(os.path.join(image_dir_path,"pre-process.png"),"pre processed group of detection for correlation searches")
            st.markdown("- **:blue[Suggested Correlation Search]** *note*: need to test manually")
            with st.expander("Example:"):
                ut.render_image(os.path.join(image_dir_path,"correlation.png"),"suggested correlation searches base of filter or pre process data")
    return


def generate_data():
    ut.banner()
    config = ut.read_config()
    security_content_path = config['Settings']['security_content_path']
    security_content_base_path, detection_types, files = ut.enumerate_folder_path(security_content_path)
    option_detection_type = st.multiselect("select detection type filter: ", detection_types)
    click = st.button("Run Filter")
    if not option_detection_type:
        st.error("Please select at least one detection type.")
    if click and option_detection_type:
        
        ut.delete_old_json_data()
        ut.SECURITY_CONTENT_PATH = security_content_path
        ut.generate_json_data(option_detection_type, detection_types)
        ut.json_to_df(ut.GENERATED_JSON_FILE_NAME)
    return


def sec_content_filter():
    ut.banner()
    json_df = ut.json_to_df(ut.GENERATED_JSON_FILE_NAME)
    col_names = ut.parse_security_content_tag(json_df)
    FILTERED_DF = json_df
    tag_option_val_dict = {}
    option_substr_dict = {}
    config = ut.read_config()

    col1, col2 = st.columns((3, 1))

    with col1:
        with st.expander("security content data frame"):
            st.dataframe(json_df, width=1000, height=800)
            
    with col2:
        
        filter_fields_value = config['Settings']['filter_fields'].split(",")
        filter_fields_value = [v.strip() for v in filter_fields_value]
        
        
        with st.expander("Security Content Filter"):
            for field_name in filter_fields_value:
                selected = st.multiselect('Filter by {}:'.format(field_name), json_df[field_name].explode().unique())
                tag_option_val_dict[field_name] = selected

        with st.expander("Filter by Sub-String"):
            filter_substr = config['Settings']['substring_filter'].split(",")
            filter_substr = [v.strip() for v in filter_substr]
            for f in filter_substr:
                option_substr_dict[f] = [a.strip() for a in st.text_input("filter {} by sub-string: ".format(f)).split(",") if a!=""]

        click_filter_button = st.button("run field filters")
    
    with col1:

        if click_filter_button:
            FILTERED_DF, tag_option_val_dict = ut.filter_data_frame(FILTERED_DF, tag_option_val_dict)
            FILTERED_DF, option_substr_dict = ut.filter_data_frame(FILTERED_DF, option_substr_dict)
            ut.count_detection_type(FILTERED_DF)                                


    return

def correlation_helper():
    ut.banner()
    json_df = ut.json_to_df(ut.GENERATED_JSON_FILE_NAME)
    col_names = ut.parse_security_content_tag(json_df)
    FILTERED_DF = json_df
    corr_option_val_dict = {}
    corr_option_substr_dict = {}
    config = ut.read_config()
    perc_ = config['Settings']['source_count_perc']
    corr_template = config['Settings']['correlation_template']
    tab1, tab2, tab3= st.tabs(["Correlation Helper", "By Analytic Stories", "By Mitre Technique ID"])
    
    
    with tab1:
        col1, col2 = st.columns((3, 1))

        with col1:
            with st.expander("security content data frame"):
                st.dataframe(json_df)
                
        with col2:
            
            corr_fields_value = config['Settings']['correlation_filter_fields'].split(",")
            corr_fields_value = [v.strip() for v in corr_fields_value]
            
            
            with st.expander("Correlation Helper Filter"):
                for field_name in corr_fields_value:
                    selected = st.multiselect('Filter by {}:'.format(field_name), json_df[field_name].explode().unique())
                    corr_option_val_dict[field_name] = selected

            with st.expander("Filter by Sub-String"):
                corr_substr = config['Settings']['correlation_filter_substr'].split(",")
                corr_substr = [v.strip() for v in corr_substr]
                for f in corr_substr:
                    corr_option_substr_dict[f] = [a.strip() for a in st.text_input("filter {} by sub-string: ".format(f)).split(",") if a!=""]

            click_filter_button = st.button("run field filters")
        
        with col1:

            if click_filter_button:
                FILTERED_DF, corr_option_val_dict_ = ut.filter_data_frame(FILTERED_DF, corr_option_val_dict)
                FILTERED_DF, corr_option_substr_dict_ = ut.filter_data_frame(FILTERED_DF, corr_option_substr_dict)
                ut.count_detection_type(FILTERED_DF)

                count_val = int(len(FILTERED_DF)*float(perc_))
                if int(len(FILTERED_DF)) == 1 or count_val < 1:
                    count_val = 1
                else:
                    pass
                merge_dict = ut.merge_dicts(corr_option_val_dict, corr_option_substr_dict)
                #st.write(merge_dict)
                ut.generate_splunk_search_condition(str(count_val), corr_template, merge_dict)

    with tab2:
        click_ = st.button("Run Preprocess data by analytic story")
        if click_:
            
            ut.pre_process_by_tag(json_df, "tags.analytic_story", perc_, corr_template)

    with tab3:
        click_ = st.button("Run Preprocess data by mitre attack id")
        if click_:
            
            ut.pre_process_by_tag(json_df, "tags.mitre_attack_id", perc_, corr_template)



page_names_to_funcs = {
    "configuration": intro,
    "Generate Data": generate_data,
    "Security Content Filter": sec_content_filter,
    "Correlation Helper": correlation_helper,
    
    

}
st.set_page_config(layout="wide")
demo_name = st.sidebar.selectbox("Choose a task", page_names_to_funcs.keys())
page_names_to_funcs[demo_name]()

import logging
import os
from langchain.tools import Tool



from Blue_Team_Functions import Malware_analysis

class Blue_Team_Agent:
    def __init__(self,api_key = "GROQ_API_KEY"):
        self.agent =
        self.api_key = api_key





tools = [
    Tool(
        name = "Malware analysis",
        func= Malware_analysis.Malware_Analysis(filename),
        description="Malware analysis of a exe or harmful file by using static analysis methods"


    )
]

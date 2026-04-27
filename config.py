import os

# Configuration Management and Settings

class Config:
    def __init__(self):
        self.setting_1 = os.getenv('SETTING_1', 'default_value_1')
        self.setting_2 = os.getenv('SETTING_2', 'default_value_2')
        self.setting_3 = os.getenv('SETTING_3', 'default_value_3')

    def __repr__(self):
        return f"<Config(setting_1={self.setting_1}, setting_2={self.setting_2}, setting_3={self.setting_3})>"

# Example of overriding settings with environment variables
if __name__ == '__main__':
    config = Config()
    print(config)
import os
import sys
import json

def main(rulespath, path):
    os.system('./scripts/yr scan --disable-warnings --output-format json ' + rulespath + " " + path + ' > ./scripts/output_scan')
    threats_count = 0
    try:
        # Read JSON from file
        with open('./scripts/output_scan', 'r') as file:
            data = json.load(file)        
        with open("./scripts/output_rules", "w") as f:
            f.write("Check:\n")
            # Read str with rule from data
            for i in data['matches']:
                #print(i["rule"])
                f.write(i["rule"]+"\n")
                threats_count += 1
        #rule = data['matches'][0]["rule"]
        #print(threats_count)
    except FileNotFoundError:
        print("Error: The file 'data.json' was not found.")
    
    os.system('cat ./scripts/output_rules')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

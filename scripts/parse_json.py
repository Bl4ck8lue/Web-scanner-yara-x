import json

def main():
    try:
        # Read JSON from file
        with open('test', 'r') as file:
            data = json.load(file)
        # Read str with rule from data
        for i in data['matches']:
            print(i["rule"])
        #rule = data['matches'][0]["rule"]
    except FileNotFoundError:
        print("Error: The file 'data.json' was not found.")

if __name__ == '__main__':
    main()

import json
import numpy as np

def j_pprint(json_obj):
    """
    Pretty prints a json object.

    :param json_obj: json object
    :return: None
    """
    json_formatted_str = json.dumps(json_obj, indent=4)
    print(json_formatted_str)

def load_prepare_json(filename):
    """
    Loads a json files and prepares it for later usage within the Jupyter Notebook.

    :param filename: name of the file (absolute path)
    :return: unique MITRE ATT&CK techniques sorted by their score
    """
    # Create file object.
    f_attack = open(filename)
     
    # Create json object from file object
    j_attack = json.load(f_attack)
     
    # Closing file object.
    f_attack.close()

    # Sort the json object based on the technique's score.
    attack_sorted = dict(j_attack)
    attack_sorted["techniques"] = sorted(j_attack["techniques"], key=lambda x : x["score"], reverse=True)

    # Get unique techniques from sorted object.
    # Techniques can be part of different tactics. The 'tactic' is not relevant for us.
    # In addition, we do not increase the score if a technique is used within different tactics.
    # Convert the whole thing to a numpy array.
    attack_unq = np.array({ each['techniqueID'] : each for each in attack_sorted["techniques"] }.values())

    return attack_unq

def print_scores(df):
    """
    Print the scores from 1 to 6 for a given dataframe.

    :param df: dataframe
    return: None
    """

    six = list()
    five = list()
    four = list()
    three = list()
    two = list()
    one = list()

    for index, row in df.iterrows():
        if row['score'] == 6:
            six.append(row['techniqueID'])
        if row['score'] == 5:
            five.append(row['techniqueID'])
        if row['score'] == 4:
            four.append(row['techniqueID'])
        if row['score'] == 3:
            three.append(row['techniqueID'])
        if row['score'] == 2:
            two.append(row['techniqueID'])
        if row['score'] == 1:
            one.append(row['techniqueID'])
            
    print("{} techniques with a score of 6:".format(len(six)))
    print(', '.join(six))
    print()

    print("{} techniques with a score of 5:".format(len(five)))
    print(', '.join(five))
    print()

    print("{} techniques with a score of 4:".format(len(four)))
    print(', '.join(four))
    print()

    print("{} techniques with a score of 3:".format(len(three)))
    print(', '.join(three))
    print()

    print("{} techniques with a score of 2:".format(len(two)))
    print(', '.join(two))
    print()

    print("{} techniques with a score of 1:".format(len(one)))
    print(', '.join(one))
    print()

def print_n_security_controls(number, data, nist):
    """
    Pretty prints a specific number of security controls.
    The function also includes some contextual information such as the control-name and score.

    :param number: number of controls to print 
    :param data: input data that contains the control and their score 
    :param nist: nist data for lookup purposes
    :return: None
    """
    l = []
    res = {}
    for d in data.items():
        for i in range(len(nist)):
            # +1 to skip the header.
            if str(nist[i+1][0]) == str(d[0]):
                #res['techniqueID'] = nist[i+1][3]
                res['controlName'] = nist[i+1][1]
                res['controlID'] = d[0]
                res['score'] = d[1]
                l.append(res.copy())
                break

    pretty_l = json.dumps(l[:number], indent=4)
    print(pretty_l)

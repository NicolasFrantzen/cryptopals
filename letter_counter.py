import base64

def read_file(file):
    with open(file) as f:
        content = "".join([str(base64.b64decode(x)) for x in f.readlines()])

    return content


def create_count_dict(text):
    count_dict = {}
    for ch in text.lower():
        #print(f"HEJ: {ch}")
        if ch in count_dict:
            count_dict[ch] += 1
        else:
            #count_dict[ch] == 1
            count_dict.update({ch : 1})

    return count_dict

def sort_dict_by_key(dict):
    sorted_keys = list(dict.keys())
    sorted_keys.sort()
    sorted_dict = {}

    for sorted_key in sorted_keys:
        sorted_dict[sorted_key] = dict[sorted_key]

    return sorted_dict


if __name__ == "__main__":
    a = read_file("data/19.txt")
    a += read_file("data/20.txt")

    print(a)
    print(sort_dict_by_key(create_count_dict(a)))

import os

if __name__ == '__main__':
    x = 0
    for i in range(1000):
        text = os.popen("./sm22").read()
        if (text.find("false")!=-1):
            print("flase\n")
            x = x + 1
        else:
            print("true")
    print("flase:{}".format(x))

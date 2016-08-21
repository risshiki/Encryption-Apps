def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def ClusterFormation(fname):
    size = file_len(fname)
    fldatalist = []
    floatingdata = {}

    
    with open(fname) as f:
        for line in f:
            listValue = line.split(":")
            veid = listValue[0]
            lat = float(listValue[1])
            lng = float(listValue[2])
            speed = float(listValue[3])
            fldatalist.append({'Vehicle ID' : veid, 'Latitude' : lat , 'Longitude' : lng, 'Speed' : speed})

    return fldatalist

UberCluster = ClusterFormation ("DataFiles.txt")
print(UberCluster)

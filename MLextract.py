#!/usr/bin/env python
import os
import sys
import base64
import subprocess
import re
import glob

fingerprints = [re]
totalCerts = 0
certNr = 1


# First, make sure that the version of openssl we are using supports the cms command
# the version supplied with OS X doesn't - you would need to get a different one in this case
# e.g. through Homebrew
opensslbin = "openssl"


def main(filename):
    global certNr

    out, err = execute(opensslbin + " cms")
    if err.decode().find("'cms' is an invalid command") != -1:
        print("The version of OpenSSL you are using doesn't support the CMS command")
        print("You need to get a version that does (e.g. from Homebrew)")
        exit(1)

    # remove old master list
    if os.path.exists("masterList.pem"):
        os.remove("masterList.pem")

    # Get a list of all the file paths that ends with .txt from in specified directory
    fileList = glob.glob("*.pem")
    # Iterate over the list of filepaths & remove each file.
    for filePath in fileList:
        try:
            os.remove(filePath)
        except:
            print("Error while deleting file : ", filePath)

    # Identify Type of file - either LDIF or MasterList (CMS)
    if filename.lower().endswith(".ldif"):
        # Read and parse LDIF File
        masterLists = readAndExtractLDIFFile(filename)
    elif filename.lower().endswith(".ml"):
        masterLists = readInMasterListFile(filename)

    print(f"Read in {len(masterLists)} masterlist files")

    for index, ml in enumerate(masterLists):
        certNr = 1
        print("-----------------------------------")
        print(f"Verifying and extracting MasterList {index + 1}/{len(masterLists)}")
        extractCertsFromMasterlist(ml)

    print("====================================")
    print(f"Created MasterList.pem containing {totalCerts} certificates")
    print(
        f"Created {totalCerts} files including self signed CSCA and linked certificates"
    )


def readAndExtractLDIFFile(file):

    adding = False
    certs = []
    with open(file, "r") as inf:
        for line in inf:
            if line.startswith("CscaMasterListData:: "):
                cert = line[21:]
                adding = True
            elif not line.startswith(" ") and adding == True:
                adding = False
                certs.append(cert)
                cert = ""
            elif adding == True:
                cert += line
        if cert != "":
            certs.append(cert)

    print(f"Read {len(certs)} certs")
    masterLists = []
    for index, cert in enumerate(certs):
        data = base64.b64decode(cert)
        masterLists.append(data)

    return masterLists


def readInMasterListFile(file):
    with open(file, "rb") as inf:
        data = inf.read()

    return [data]


def extractCertsFromMasterlist(masterList):
    global totalCerts

    # Run openssl cms to verify and extract the signed data
    cmd = f"{opensslbin} cms -inform der -noverify -verify"
    (signedData, err) = execute(cmd, masterList)
    if err.decode("utf8").strip() != "CMS Verification successful":
        print(f"[{err.decode('utf8')}]")
        raise Exception("Verification of Masterlist data failed")

    print("MasterList Verification successful")

    certList = extractPEMCertificates(signedData)

    print("Removing duplicates")
    uniqueCerts = [x for x in certList if uniqueHash(x)]

    print(f"Removed {len(certList)-len(uniqueCerts)} duplicate certificates")
    totalCerts += len(uniqueCerts)

    # Append to masterList.pem
    with open("masterList.pem", "ab") as f:
        for c in uniqueCerts:
            f.write(c)
            # Write each cert to directory
            (CN, err) = execute(f"{opensslbin} x509 -noout -issuer", c)
            certfilename = CN.decode("utf8").strip().replace("/", "-")
            i = 0
            while os.path.exists(certfilename + ".pem"):
                i += 1
                certfilename = (
                    CN.decode("utf8").strip().replace("/", "-") + "-" + str(i)
                )
            with open(f"{certfilename}.pem", "wb") as certfile:
                print(f"Saving certificate {certfilename}.pem", end="\r")
                certfile.write(c)
                certfile.close()
        f.close()


def extractPEMCertificates(signedData):
    global certNr
    print("Extracting all certificates from masterlist")
    cmd = f"{opensslbin} asn1parse -inform der -i"
    (data, err) = execute(cmd, signedData)

    lines = data.decode("utf8").strip().split("\n")
    valid = False
    certs = []

    certCount = len([i for i in lines if "d=2" in i])
    for line in lines:
        if re.search(r":d=1", line):
            valid = False
        if re.search(r"d=1.*SET", line):
            valid = True
        if re.search(r"d=2", line) and valid:
            # Parse line
            match = re.search(r"^ *([0-9]*).*hl= *([0-9]*).*l= *([0-9]*).*", line)
            if match:
                print(f"Extracting cert {certNr} of {certCount}", end="\r")
                certNr += 1
                offset = int(match.group(1))
                header_len = int(match.group(2))
                octet_len = int(match.group(3))

                # Extract PEM certificate
                data = signedData[offset : offset + header_len + octet_len]
                (cert, err) = execute(
                    f"{opensslbin} x509 -inform der -outform pem", data
                )
                certs.append(cert)
            else:
                print("Failed match")

    print(f"\nExtracted {len(certs)} certs")
    return certs


def uniqueHash(cert):
    (data, err) = execute(
        f"{opensslbin} x509 -hash -fingerprint -inform PEM -noout", cert
    )
    items = data.decode("utf8").split("\n")
    hash = items[0].strip()
    fingerprint = items[1].strip()
    if fingerprint not in fingerprints:
        fingerprints.append(fingerprint)
        return True

    print(f"Found duplicate hash - {hash}")
    return False


def writeToDisk(name, data):
    with open(name, "wb") as f:
        f.write(data)


def removeFromDisk(name):
    try:
        os.remove(name)
    except:
        pass


def execute(cmd, data=None, empty=False):
    res = subprocess.Popen(
        cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if data != None:
        res.stdin.write(data)
        res.stdin.close()
    out = res.stdout.read()
    err = res.stderr.read()

    return (out, err)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Invalid number of parameters: ")
        print("")
        print("Usage - python MLextract.py [masterlist .ml file|icao .ldif file]")
        print("")
        exit(1)

    main(sys.argv[1])

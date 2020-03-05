# -*- coding: utf-8 -*-
"""
Created on Wed Mar  4 09:22:13 2020
"""

from datetime import date
from datetime import timedelta
import os
import base64
import requests
import zipfile
import sys
import re
import whois
import csv
import socket
from ipwhois.net import Net
from ipwhois.asn import IPASN
import time
import ahocorasick



def donwnload_nrd(d):
    if not os.path.isfile(d+".zip"):
        b64 = base64.b64encode((d+".zip").encode('ascii'))
        nrd_zip = 'https://whoisds.com//whois-database/newly-registered-domains/{}/nrd'.format(b64.decode('ascii'))
        try:
            resp = requests.get(nrd_zip,stream=True)

            print("Downloading File {} - Size {}...".format(d+'.zip',resp.headers['Content-length']))
            if resp.headers['Content-length']:
                with open(d+".zip", 'wb') as f:
                    for data in resp.iter_content(chunk_size=1024):
                        f.write(data)
                time.sleep(1)
                try:
                    zip = zipfile.ZipFile(d+".zip")
                    zip.extractall()
                    time.sleep(1)
                    os.rename("domain-names.txt", d+".txt")
                    time.sleep(1)
                except:
                    print("File is not a zip file.")
                    sys.exit()
        except:
            print("File {}.zip does not exist on the remore server.".format(d))
            sys.exit()

def insertion(domain):
    qwerty = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
    qwertz = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
    azerty = {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
    keyboards = [ qwerty, qwertz, azerty ]
    result = []

    for i in range(1, len(domain)-1):
        for keys in keyboards:
            if domain[i] in keys:
                for c in keys[domain[i]]:
                    result.append(domain[:i] + c + domain[i] + domain[i+1:])
                    result.append(domain[:i] + domain[i] + c + domain[i+1:])

    return result


def homoglyph(domain):
    glyphs = {
        'a': [u'à', u'á', u'â', u'ã', u'ä', u'å', u'ɑ', u'ạ', u'ǎ', u'ă', u'ȧ', u'ą'],
        'b': ['d', 'lb', u'ʙ', u'ɓ', u'ḃ', u'ḅ', u'ḇ', u'ƅ'],
        'c': ['e', u'ƈ', u'ċ', u'ć', u'ç', u'č', u'ĉ'],
        'd': ['b', 'cl', 'dl', u'ɗ', u'đ', u'ď', u'ɖ', u'ḑ', u'ḋ', u'ḍ', u'ḏ', u'ḓ'],
        'e': ['c', u'é', u'è', u'ê', u'ë', u'ē', u'ĕ', u'ě', u'ė', u'ẹ', u'ę', u'ȩ', u'ɇ', u'ḛ'],
        'f': [u'ƒ', u'ḟ'],
        'g': ['q', u'ɢ', u'ɡ', u'ġ', u'ğ', u'ǵ', u'ģ', u'ĝ', u'ǧ', u'ǥ'],
        'h': ['lh', u'ĥ', u'ȟ', u'ħ', u'ɦ', u'ḧ', u'ḩ', u'ⱨ', u'ḣ', u'ḥ', u'ḫ', u'ẖ'],
        'i': ['1', 'l', u'í', u'ì', u'ï', u'ı', u'ɩ', u'ǐ', u'ĭ', u'ỉ', u'ị', u'ɨ', u'ȋ', u'ī'],
        'j': [u'ʝ', u'ɉ'],
        'k': ['lk', 'ik', 'lc', u'ḳ', u'ḵ', u'ⱪ', u'ķ'],
        'l': ['1', 'i', u'ɫ', u'ł'],
        'm': ['n', 'nn', 'rn', 'rr', u'ṁ', u'ṃ', u'ᴍ', u'ɱ', u'ḿ'],
        'n': ['m', 'r', u'ń', u'ṅ', u'ṇ', u'ṉ', u'ñ', u'ņ', u'ǹ', u'ň', u'ꞑ'],
        'o': ['0', u'ȯ', u'ọ', u'ỏ', u'ơ', u'ó', u'ö'],
        'p': [u'ƿ', u'ƥ', u'ṕ', u'ṗ'],
        'q': ['g', u'ʠ'],
        'r': [u'ʀ', u'ɼ', u'ɽ', u'ŕ', u'ŗ', u'ř', u'ɍ', u'ɾ', u'ȓ', u'ȑ', u'ṙ', u'ṛ', u'ṟ'],
        's': [u'ʂ', u'ś', u'ṣ', u'ṡ', u'ș', u'ŝ', u'š'],
        't': [u'ţ', u'ŧ', u'ṫ', u'ṭ', u'ț', u'ƫ'],
        'u': [u'ᴜ', u'ǔ', u'ŭ', u'ü', u'ʉ', u'ù', u'ú', u'û', u'ũ', u'ū', u'ų', u'ư', u'ů', u'ű', u'ȕ', u'ȗ', u'ụ'],
        'v': [u'ṿ', u'ⱱ', u'ᶌ', u'ṽ', u'ⱴ'],
        'w': ['vv', u'ŵ', u'ẁ', u'ẃ', u'ẅ', u'ⱳ', u'ẇ', u'ẉ', u'ẘ'],
        'y': [u'ʏ', u'ý', u'ÿ', u'ŷ', u'ƴ', u'ȳ', u'ɏ', u'ỿ', u'ẏ', u'ỵ'],
        'z': [u'ʐ', u'ż', u'ź', u'ᴢ', u'ƶ', u'ẓ', u'ẕ', u'ⱬ']
        }

    result_1pass = []

    for ws in range(1, len(domain)):
        for i in range(0, (len(domain)-ws)+1):
            win = domain[i:i+ws]
            j = 0
            while j < ws:
                c = win[j]
                if c in glyphs:
                    win_copy = win
                    for g in glyphs[c]:
                        win = win.replace(c, g)
                        result_1pass.append(domain[:i] + win + domain[i+ws:])
                        win = win_copy
                j += 1

    result_2pass = []

    for domain in result_1pass:
        for ws in range(1, len(domain)):
            for i in range(0, (len(domain)-ws)+1):
                win = domain[i:i+ws]
                j = 0
                while j < ws:
                    c = win[j]
                    if c in glyphs:
                        win_copy = win
                        for g in glyphs[c]:
                            win = win.replace(c, g)
                            result_2pass.append(domain[:i] + win + domain[i+ws:])
                            win = win_copy
                    j += 1

    result = result_1pass + result_2pass
    return result

def omission(domain):
    result = []

    for i in range(0, len(domain)):
        result.append(domain[:i] + domain[i+1:])

    n = re.sub(r'(.)\1+', r'\1', domain)

    if n not in result and n != domain:
        result.append(n)

    return result

def transposition(domain):
    result = []

    for i in range(0, len(domain)-1):
        if domain[i+1] != domain[i]:
            result.append(domain[:i] + domain[i+1] + domain[i] + domain[i+2:])

    return result

def vowel_swap(domain):
    vowels = 'aeiou'
    result = []

    for i in range(0, len(domain)):
        for vowel in vowels:
            if domain[i] in vowels:
                result.append(domain[:i] + vowel + domain[i+1:])

    return result

def addition(domain):
    result = []

    for i in range(97, 123):
        result.append(domain + chr(i))

    return result

def repetition(domain):
    result = []

    for i in range(0, len(domain)):
        if domain[i].isalpha():
            result.append(domain[:i] + domain[i] + domain[i] + domain[i+1:])

    return result

def replacement(domain):
    qwerty = {
    '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
    'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
    'a': 'qwsz', 's': 'edxzaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
    'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    }
    qwertz = {
        '1': '2q', '2': '3wq1', '3': '4ew2', '4': '5re3', '5': '6tr4', '6': '7zt5', '7': '8uz6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'q': '12wa', 'w': '3esaq2', 'e': '4rdsw3', 'r': '5tfde4', 't': '6zgfr5', 'z': '7uhgt6', 'u': '8ijhz7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0',
        'a': 'qwsy', 's': 'edxyaw', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'zhbvft', 'h': 'ujnbgz', 'j': 'ikmnhu', 'k': 'olmji', 'l': 'kop',
        'y': 'asx', 'x': 'ysdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
        }
    azerty = {
        '1': '2a', '2': '3za1', '3': '4ez2', '4': '5re3', '5': '6tr4', '6': '7yt5', '7': '8uy6', '8': '9iu7', '9': '0oi8', '0': 'po9',
        'a': '2zq1', 'z': '3esqa2', 'e': '4rdsz3', 'r': '5tfde4', 't': '6ygfr5', 'y': '7uhgt6', 'u': '8ijhy7', 'i': '9okju8', 'o': '0plki9', 'p': 'lo0m',
        'q': 'zswa', 's': 'edxwqz', 'd': 'rfcxse', 'f': 'tgvcdr', 'g': 'yhbvft', 'h': 'ujnbgy', 'j': 'iknhu', 'k': 'olji', 'l': 'kopm', 'm': 'lp',
        'w': 'sxq', 'x': 'wsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhj'
        }
    keyboards = [ qwerty, qwertz, azerty ]
    result = []

    for i in range(0, len(domain)):
        for keys in keyboards:
            if domain[i] in keys:
                for c in keys[domain[i]]:
                    result.append(domain[:i] + c + domain[i+1:])

    return result

def bitsquatting(domain):
    out = []
    masks = [1, 2, 4, 8, 16, 32, 64, 128]

    for i in range(0, len(domain)):
        c = domain[i]
        for j in range(0, len(masks)):
            b = chr(ord(c) ^ masks[j])
            o = ord(b)
            if (o >= 48 and o <= 57) or (o >= 97 and o <= 122) or o == 45:
                out.append(domain[:i] + b + domain[i+1:])
    return out

def hyphenation(domain):
    out = []
    for i in range(1, len(domain)):
        out.append(domain[:i] + '-' + domain[i:])
    return out

def subdomain(domain):
    out = []
    for i in range(1, len(domain)):
        if domain[i] not in ['-', '.'] and domain[i-1] not in ['-', '.']:
            out.append(domain[:i] + '.' + domain[i:])
    return out

def main():
    search = "drexel"

    homoglyph_search = homoglyph(search)
    insertion_search = insertion(search)
    omission_search = omission(search)
    transposition_search = transposition(search)
    vowel_swap_search = vowel_swap(search)
    addition_search = addition(search)
    repetition_search = repetition(search)
    replacement_search = replacement(search)
    bitsquatting_search = bitsquatting(search)
    hyphenation_search = hyphenation(search)
    subdomain_search = subdomain(search)
    search_all = bitsquatting_search+hyphenation_search+subdomain_search+homoglyph_search+insertion_search+omission_search+transposition_search+vowel_swap_search+addition_search+repetition_search+replacement_search
    search_all.append(search)

    print("Amount of search terms: " + str(len(search_all)))

    for i in range(0,7):
        dates = (date.today() - timedelta(days=i+1))

        dates = dates.strftime('%Y-%m-%d')
        print(dates)
        donwnload_nrd(dates)

        DOMAINS = []
        ITEMS = []
        NAMES = []

        f = open(dates + '.txt','r')
        for row in f:
            NAMES.append(row.strip('\r\n'))

        A = ahocorasick.Automaton()
        for idx, key in enumerate(search_all):
            A.add_word(key, (idx, key))

        A.make_automaton()
        for item in A.iter("".join(NAMES)):
            ITEMS.append(item)

        for name in NAMES:
            for item in ITEMS:
                ite = re.findall("'([^']*)'", str(item))
                for it in ite:
                    if it in name:
                        DOMAINS.append(name.strip('\r\n'))

        for domain in DOMAINS:
            print("Domain Name Found: " + domain)
            try:
                w_res = whois.whois(domain)
                name = w_res.name
                created = w_res.creation_date
                email = w_res.emails
                registar = w_res.registrar
                expiry = w_res.expiration_date

                ip = socket.gethostbyname(domain)
                net = Net(ip)
                obj = IPASN(net)
                y = obj.lookup()
                if 'asn_registry' in y:
                    asnRegistry=y.get('asn_registry')
                if 'asn' in y:
                    asnNum=y.get('asn')
                if 'asn_cidr' in y:
                    asnCIDR=y.get('asn_cidr')
                if 'asn_country_code' in y:
                    asnCountry=y.get('asn_country_code')
                if 'asn_description' in y:
                    asnDesc=y.get('asn_description')

                notes = ' '

                with open(r'C:\\Users\\domains.csv', 'a', newline='') as csvfile:
                    fieldnames = ['Domain', 'IP', 'Created Date', 'Expiry Date', 'WHOIS Name', 'WHOIS Email', 'WHOIS Register', 'ASN Registry', 'ASN #', 'ASN CIDR', 'ASN Country', 'ASN Description', 'Notes']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writerow({'Domain':domain, 'IP':ip, 'Created Date':created, 'Expiry Date':expiry, 'WHOIS Name':name, 'WHOIS Email':email, 'WHOIS Register':registar, 'ASN Registry':asnRegistry, 'ASN #':asnNum, 'ASN CIDR':asnCIDR, 'ASN Country':asnCountry, 'ASN Description':asnDesc, 'Notes':notes})
            except:
                pass
main()

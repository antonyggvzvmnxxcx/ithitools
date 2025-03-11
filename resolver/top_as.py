
# TopAS: list of top Ases thhat we are tracking. 
import sys
import rdap_names
import country
import pandas as pd

# List of ASes recognized as "top", taken from Alain's slide deck

TopAS = {
    "AS28573": ["Claro NXT Telecomunicacoes Ltda", "BR", "Cellular"],
    "AS26599": ["TELEFONICA BRASIL S.A", "BR", "Cellular"],
    "AS26615": ["TIM SA", "BR", "Cellular"],
    "AS7738": ["V tal", "BR", "Broadband"],
    "AS28126": ["BRISANET SERVICOS DE TELECOMUNICACOES S.A", "BR", "Broadband"],
    "AS268581": ["QNAX LTDA", "BR", "Broadband"],
    "AS7303": ["Telecom Argentina S.A.", "AR", "Broadband"],
    "AS19037": ["AMX Argentina S.A.", "AR", "Cellular"],
    "AS22927": ["Telefonica de Argentina", "AR", "Cellular"],
    "AS27747": ["Telecentro S.A.", "AR", "Broadband"],
    "AS11315": ["Telefonica Moviles Argentina S.A. Movistar Argentina", "AR", "Cellular"],
    "AS8151": ["UNINET", "MX", "Broadband"],
    "AS17072": ["TOTAL PLAY TELECOMUNICACIONES SA DE CV","MX", "Broadband"],
    "AS13999": ["Mega Cable S.A. de C.V.", "MX", "Broadband"],
    "AS28403": ["RadioMovil Dipsa S.A. de C.V.","MX", "Broadband"],
    "AS28548": ["Cablevision S.A. de C.V.", "MX", "Broadband"],
    "AS26611": ["COMUNICACION CELULAR S.A. COMCEL S.A.", "CO", "Cellular"],
    "AS3816": ["COLOMBIA TELECOMUNICACIONES S.A. ESP", "CO", "Broadband"],
    "AS10620": ["Telmex Colombia S.A.", "CO", "Cellular"],
    "AS27831": ["Colombia Movil", "CO", "Cellular"],
    "AS13489": ["EPM Telecomunicaciones S.A. E.S.P.", "CO", "Broadband"],
    "AS7418": ["TELEFONICA CHILE S.A.", "CL", "Cellular"],
    "AS27651": ["ENTEL CHILE S.A.", "CL", "Broadband"],
    "AS22047": ["VTR BANDA ANCHA S.A.", "CL", "Broadband"],
    "AS52341": ["WOM S.A.", "CL", "Broadband"],
    "AS27901": ["Pacifico Cable SPA.", "CL", "Broadband"],
    "AS27882": ["Telefonica Celular de Bolivia S.A.", "BO", "Cellular"],
    "AS6568": ["Entel S.A. - EntelNet", "BO", "Broadband"],
    "AS23201": ["Telecel S.A.", "PY", "Cellular"],
    "AS27895": ["Nucleo S.A.", "PY", "Cellular"],
    "AS8048": ["CANTV Servicios Venezuela", "VE", "Broadband"],
    "AS21826": ["Corporacion Telemic C.A.", "VE", "Cellular"],
    "AS7922": ["Comcast", "US", "Broadband"],
    "AS20115": ["Charter", "US", "Broadband"],
    "AS22773": ["Cox", "US", "Broadband"],
    "AS701": ["Verizon Business (Fios)", "US", "Broadband"],
    "AS7843": ["Charter (ex TWC)", "US", "Broadband"],
    "AS7018": ["AT&T", "US", "Cellular"],
    "AS6167": ["Verizon", "US", "Cellular"],
    "AS21928": ["T-Mobile", "US", "Cellular"],
    "AS6614": ["US Cellular", "US", "Cellular"],
    "AS22394": ["Verizon", "US", "Cellular"],
    "AS3215": ["Orange", "EU", "Europe"],
    "AS3269": ["Telecom Italia", "EU", "Europe"],
    "AS3320": ["Deutsche Telekom", "EU", "Europe"],
    "AS3352": ["Telefonica", "EU", "Europe"],
    "AS197207": ["Mobile Communication of Iran PLC", "IR", "Mobile"],
    "AS58224": ["TCI", "IR", "Mix"],
    "AS203214": ["Hulum Almustakbal", "IQ", "ISP"],
    "AS199739": ["Earthlink", "IR", "Mix"],
    "AS48832": ["ZAIN", "JO", "Mix"],
    "AS28885": ["Omantel", "OM", "Mix"],
    "AS43766": ["Zain", "SA", "Mix"],
    "AS39801": ["Al Jawal", "SA", "Mobile"],
    "AS35819": ["Etihad Etisalat", "SA", "Mix"],
    "AS25019": ["Saudinetstc", "SA", "ISP"],
    "AS29256": ["Int pdn ste", "SY", "Mix"],
    "AS34984": ["Tellcom", "TR", "ISP"],
    "AS20978": ["TT Mobil", "TR", "Mobile"],
    "AS16135": ["Turkcell", "TR", "Mobile"],
    "AS15897": ["Vodafone Turkiye", "TR", "Mix"],
    "AS9121": ["Turk Telekom", "TR", "Mix"],
    "AS8966": ["Etisalat", "AE", "Mix"],
    "AS5384": ["Emirates Telecommunications", "AE", "Mix"],
    "AS30873": ["Public Telecommunication", "YE", "Mix"]
}

# List of ASes recognized as "cloud". They match 2 selective criteria:
#
# The ratio between the number of queries served from their largest "query AS"
# and the total number for that "query AS" is lower than 0.4
# The number of country codes listed in those query Ases is at least 2,
# and the number of queries served for that "query AS" overall is small
# compared to the number of queries routed from other ASes. The list:
#
# discuss: yandex has DNS services similar to Google, CLoudflare
# 
CloudAS = {
    "AS396982": "GOOGLE-CLOUD-PLATFORM",
    "AS20940": "AKAMAI-ASN1",
    "AS36692": "CISCO-UMBRELLA",
    "AS36236": "NETACTUATE",
    "AS54825": "PACKET",
    "AS16509": "AMAZON-02",
    "AS18734": "Operbes, S.A. de C.V.",
    "AS13238": "YANDEX",
    "AS208398": "TELETECH",
    "AS30844": "LIQUID-AS",
    "AS42": "WOODYNET-1",
    "AS49544": "i3Dnet",
    "AS60068": "CDN77",
    "AS38091": "HELLONET-AS-KR-KR"
}

# List of ASes that are sending their DNS traffic to a resolver
# in the same company
RsvAS = {
    "AS10620": "AS14080",
    "AS11664": "AS19037",
    "AS12091": "AS16637",
    "AS12716": "AS8717",
    "AS13285": "AS9105",
    "AS16135": "AS34984",
    "AS17421": "AS3462",
    "AS17552": "AS7470",
    "AS17858": "AS3786",
    "AS18004": "AS133798",
    "AS18881": "AS10429",
    "AS199739": "AS50710",
    "AS206026": "AS21299",
    "AS20978": "AS9121",
    "AS24158": "AS9924",
    "AS24203": "AS17885",
    "AS24378": "AS9587",
    "AS24560": "AS9498",
    "AS25472": "AS1241",
    "AS26599": "AS10429",
    "AS27831": "AS13489",
    "AS36903": "AS6713",
    "AS36935": "AS24835",
    "AS37069": "AS24863",
    "AS37457": "AS5713",
    "AS39891": "AS25019",
    "AS45609": "AS9498",
    "AS51207": "AS12322",
    "AS56167": "AS17557",
    "AS59257": "AS138423",
    "AS6167": "AS22394",
    "AS8814": "AS34170",
    "AS9506": "AS3758"
}

GroupAS = {
    "AS9498": "AS24560",
    "AS45609": "AS24560",
    "AS6167": "AS22394",
    "AS24203": "AS17885",
    "AS26599": "AS10429",
    "AS18881": "AS10429",
    "AS39891": "AS25019",
    "AS7470": "AS17552",
    "AS3786": "AS17858",
    "AS6713": "AS36903",
    "AS22884": "AS17072",
    "AS14080": "AS10620",
    "AS21299": "AS206026",
    "AS59257": "AS138423",
    "AS36935": "AS24835",
    "AS9121": "AS20978",
    "AS51207": "AS12322",
    "AS34984": "AS16135",
    "AS9808": "AS56040",
    "AS50710": "AS199739",
    "AS9105": "AS13285",
    "AS58543": "AS137702",
    "AS4134": "AS137702",
    "AS19037": "AS11664",
    "AS3462": "AS17421",
    "AS18004": "AS133798",
    "AS8737": "AS1136",
    "AS9587": "AS24378",
    "AS9924": "AS24158",
    "AS4230": "AS22085",
    "AS8717": "AS12716",
    "AS4761": "AS45727",
    "AS37069": "AS24863",
    "AS56167": "AS17557",
    "AS5713": "AS37457",
    "AS16637": "AS12091",
    "AS27986": "AS27651",
    "AS22927": "AS11315",
    "AS27831": "AS13489",
    "AS3329": "AS12361",
    "AS9506": "AS3758",
    "AS55410": "AS38266",
    "AS8814": "AS34170",
    "AS25472": "AS1241",
    "AS48503": "AS29555",
    "AS9824": "AS9617",
    "AS4835": "AS137702",
    "AS17633": "AS137702",
    "AS7545": "AS4739",
    "AS43612": "AS43494",
    "AS28481": "AS13999",
    "AS7018": "AS6389",
    "AS27672": "AS13999",
    "AS5650": "AS3593",
    "AS4809": "AS137702",
    "AS4837": "AS24139",
}

def top_as_list():
    return list(TopAS.keys())

def as_group(q_as):
    if q_as in GroupAS:
        q_group = GroupAS[q_as]
    else:
        q_group = q_as
    return q_group

class known_AS_names:
    def __init__(self):
        self.as_names = dict()
        for asn in TopAS:
            as_entry = TopAS[asn]
            self.as_names[asn] = as_entry[0]
        print("Started with: " + str(len(self.as_names)) + " names.")

    def process_row(self, x, headers=['asn', 'as_name', 'has_name'] ):
        if (headers[0] in x) and (headers[1] in x) and (headers[2] in x) and (x[headers[2]] == True):
            if not x[headers[0]] in self.as_names:
                self.as_names[x[headers[0]]] = x[headers[1]]

    def load_top_as(self, file_name):
        print("Loading: " + file_name)
        df = pd.read_csv(file_name)
        print("Loaded: " + file_name)
        df.apply(lambda x: self.process_row(x), axis=1)
        print("Loaded: " + str(len(self.as_names)) + " names.")

    def get_name(self, asn, cc, as_name):
        success = False
        if asn in self.as_names:
            success = True
            as_name = self.as_names[asn]
        else:
            if cc in country.cc_to_region:
                region = country.cc_to_region[cc]
            else:
                region = 'EUR'
            success, as_name = rdap_names.get_as_name_by_region(region, asn, as_name)
            if success:
                self.as_names[asn] = as_name
        return success, as_name


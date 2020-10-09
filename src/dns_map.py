import pdb


class DNSMapNode(object):
    POINTER = "pointer"
    RESOURCE = "res"

    def __init__(self):
        self.type = None  # str resource/pointer
        self.children = []
        self.next = None
        self.data = None
        self.hosted_zone = None  # self hosted zone
        self.destination = None  # the dns_name, used to point this pointer (for example multiple names for server will generate multiple nodes with the same data)

    def get_dephs(self):
        pdb.set_trace()
        return 1 + len(self.children) if self.next else 1


class DNSMap(object):
    def __init__(self, hosted_zones):
        self.nodes = {}
        self.hosted_zones = hosted_zones
        self.unmapped_records = []

    def add_resource_node(self, dns_name, seed):
        if dns_name != dns_name.rstrip("."):
            pdb.set_trace()
            raise Exception

        dns_name = dns_name.rstrip(".")
        if dns_name in self.nodes:
            pdb.set_trace()
            raise Exception(dns_name)

        node = DNSMapNode()
        node.data = seed
        node.type = DNSMapNode.RESOURCE
        node.destination = dns_name
        self.nodes[dns_name] = node

    def add_pointer_node(self, dns_name, hosted_zone, record, pointed_dns):
        """

        :param dns_name: the dns_name this DNSMapNode is being pointed by
        :param hosted_zone:
        :param record: The dns record used to create the data.
        :param pointed_dns:  The dns_name this DNSMapNode points to
        :return:
        """
        if pointed_dns not in self.nodes:
            raise Exception

        dns_name = dns_name.rstrip(".")
        if dns_name in self.nodes:
            # Problem when dns record points to multiple destinations
            for child in self.nodes[dns_name].children:
                if child.pointed_name == pointed_dns:
                    raise Exception

        node = DNSMapNode()
        node.data = record
        node.type = DNSMapNode.POINTER
        node.next = self.nodes[pointed_dns]
        node.destination = dns_name
        node.hosted_zone = hosted_zone
        self.nodes[dns_name] = node

    def prepare_map_add_atype_records(self, dict_types):
        atype_records = [x for x in dict_types["A"]]

        for hz, seed in atype_records:
            if hasattr(seed, "alias_target"):
                continue

            if hasattr(seed, "resource_records"):
                self.add_resource_node(seed.name.rstrip("."), seed)
            else:
                raise Exception

    def prepare_map(self):
        dict_types = self.split_records_by_type()
        self.prepare_map_add_atype_records(dict_types)

        left_dns_records = [x for x in dict_types["CNAME"]] + [x for x in dict_types["A"] if hasattr(x, "alias_target")] + [x for x in dict_types["SRV"]]
        self.unmapped_records = self.recursive_prepare_map(left_dns_records)

    def get_pointed_dns_addresses(self, record):
        if record.type == "CNAME":
            if len(record.resource_records) != 1:
                raise Exception

            pointed_dnss = [record.resource_records[0]["Value"].rstrip(".")]
        elif record.type == "A":
            if not hasattr(record, "alias_target"):
                raise Exception
            if not record.alias_target:
                raise Exception

            pointed_dnss = [record.alias_target["DNSName"].rstrip(".")]
        elif record.type == "SRV":
            # {'Name': 'srv.alerts.local.env.fbx.im.', 'Type': 'SRV', 'TTL': 1, 'ResourceRecords': [{'Value': '1 10 10080 alerts.local.env.fbx.im'}]}
            if not hasattr(record, "resource_records"):
                raise Exception

            pointed_dnss = [rr["Value"].rsplit(" ", 1)[-1].rstrip(".") for rr in record.resource_records]
        else:
            pdb.set_trace()
            raise Exception

        return pointed_dnss

    def recursive_prepare_map(self, unmapped_dns_records):
        if not unmapped_dns_records:
            return []
        new_unmapped_dns_records = []

        for hosted_zone, record in unmapped_dns_records:
            pointed_dnss = self.get_pointed_dns_addresses(record)

            add_to_new_unmapped_dns_records = False
            for pointed_dns in pointed_dnss:
                if pointed_dns in self.nodes:
                    self.add_pointer_node(record.name, hosted_zone, record, pointed_dns)
                else:
                    add_to_new_unmapped_dns_records = True

            if add_to_new_unmapped_dns_records:
                new_unmapped_dns_records.append([hosted_zone, record])

        print(len(unmapped_dns_records))

        if len(unmapped_dns_records) != len(new_unmapped_dns_records):
            return self.recursive_prepare_map(new_unmapped_dns_records)

        return new_unmapped_dns_records

    def split_records_by_type(self):
        dict_types = {}
        for hz in self.hosted_zones:
            for record in hz.records:
                if record.type not in dict_types:
                    dict_types[record.type] = []
                dict_types[record.type].append((hz, record))
        return dict_types

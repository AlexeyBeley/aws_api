

class HFlowFilter(object):
    def __init__(self):
        self.src = self.TunnelEdgeFilter()
        self.dst = self.TunnelEdgeFilter()
        self.info = None

    def __str__(self):
        return "src:{}\ndst: {}".format(self.src, self.dst)

    class TunnelEdgeFilter(object):
        def __init__(self):
            self.ip = None
            self.service = None
            self.dns = None

        def __str__(self):
            return "{},{},{}".format(self.ip, self.dns, self.service)


class HFlow(object):
    def __init__(self):
        self.tunnel = None
        self.end_point_src = None
        self.end_point_dst = None

    def __str__(self):
        ret = "{} -> {}\n".format(str(self.end_point_src), str(self.end_point_dst))
        ret += "\n{}".format(str(self.tunnel))
        return ret

    def apply_dst_filters_on_start(self, h_filters):
        lst_ret = []
        for h_filter in h_filters:
            #print("{}:{}".format(h_filter.info[0], h_filter.info[1]))
            lst_ret += self.apply_dst_filter_on_start(h_filter)

        #for x in lst_ret:
        #    print(x)
        return lst_ret

    def apply_dst_filter_on_start(self, h_filter):
        lst_ret = []

        for traffic_start, traffic_end in self.tunnel.traffic_start.apply_dst_filter(h_filter):
            if traffic_start is None or traffic_end is None:
                continue

            h_flow_ret = HFlow()
            h_flow_ret.end_point_src = self.end_point_src
            h_flow_ret.end_point_dst = self.end_point_dst
            h_flow_ret.tunnel = HFlow.Tunnel(traffic_start=traffic_start, traffic_end=traffic_end)
            lst_ret.append(h_flow_ret)

        return lst_ret

    def copy(self, copy_src_traffic_to_dst=False):
        ret = HFlow()
        ret.tunnel = self.tunnel.copy(copy_src_traffic_to_dst=copy_src_traffic_to_dst)
        ret.end_point_src = self.end_point_src.copy()
        ret.end_point_dst = self.end_point_dst.copy()
        return ret

    class EndPoint(object):
        """
        Hflow endpoint- maybe src, maybe dst.
        This is abstract object representing hflow next stop.

        """
        def __init__(self):
            self._ip = None
            self._dns = None
            self.custom = {}

        @property
        def ip(self):
            return self._ip

        @ip.setter
        def ip(self, ip):
            if self._ip is not None:
                raise Exception("IP can be single instance")
            self._ip = ip

        @property
        def dns(self):
            return self._dns

        @dns.setter
        def dns(self, dns):
            if self._dns is not None:
                raise Exception("IP can be single instance")
            self._dns = dns

        def add_custom(self, key, value):
            """

            :param key:
            :param value: if can include multiple destinations, should implement __add__
            :return:
            """
            if key in self.custom:
                self.custom[key].add(value)
            else:
                self.custom[key] = value

        def copy(self):
            ret = HFlow.EndPoint()
            if self.ip is not None:
                ret._ip = self.ip.copy()
            if self.dns is not None:
                ret._dns = self.dns.copy()

            ret.custom = self.custom

    class Tunnel(object):
        def __init__(self, traffic_start=None, traffic_end=None):
            self.traffic_start = traffic_start
            self.traffic_end = traffic_end

        def __str__(self):
            return "{} ==>\n==> {}".format(str(self.traffic_start), str(self.traffic_end))

        class Traffic(object):
            ANY = None

            def __init__(self):
                self.ip_src = self.any()
                self.ip_dst = self.any()

                self.dns_src = self.any()
                self.dns_dst = self.any()

                self.service_src = self.any()
                self.service_dst = self.any()

            def __str__(self):
                return "[ip:{} , dns:{} , service:{} -> ip:{} , dns:{} , service:{}]".format(self.ip_src, self.dns_src, self.service_src, self.ip_dst, self.dns_dst, self.service_dst)

            def intersect(self, self_end_point, other_end_point):
                if self_end_point is self.any():
                    return other_end_point
                return self_end_point.intersect(other_end_point)

            def apply_dst_filter(self, h_filter):
                ip_src_intersect = self.intersect(self.ip_src, h_filter.ip_src)
                if ip_src_intersect is None:
                    return []

                service_src_intersect = self.intersect(self.service_src, h_filter.service_src)
                if service_src_intersect is None:
                    return []

                ip_dst_intersect = self.intersect(self.ip_dst, h_filter.ip_dst)
                if ip_dst_intersect is None:
                    return []

                service_dst_intersect = self.intersect(self.service_dst, h_filter.service_dst)
                if service_dst_intersect is None:
                    return []

                traffic_start = self.copy()
                traffic_start.ip_src = ip_src_intersect
                traffic_start.service_src = service_src_intersect

                if h_filter.dns_src != self.dns_src:
                    raise NotImplementedError

                if h_filter.dns_dst != self.dns_dst:
                    raise NotImplementedError

                traffic_end = HFlow.Tunnel.Traffic()
                traffic_end.ip_src = traffic_start.ip_src
                traffic_end.dns_src = traffic_start.dns_src
                traffic_end.service_src = traffic_start.service_src

                traffic_end.ip_dst = ip_dst_intersect
                traffic_end.dns_dst = traffic_start.dns_dst
                traffic_end.service_dst = service_dst_intersect
                return [(traffic_start, traffic_end)]

            def copy(self):
                ret = HFlow.Tunnel.Traffic()

                if self.ip_src is not None:
                    ret.ip_src = self.ip_src.copy()

                if self.dns_src is not None:
                    ret.dns_src = self.dns_src.copy()

                if self.ip_dst is not None:
                    ret.ip_dst = self.ip_dst.copy()

                if self.dns_dst is not None:
                    ret.dns_dst = self.dns_dst.copy()

                if self.service_src is not None:
                    ret.service_src = self.service_src.copy()

                if self.service_dst is not None:
                    ret.service_dst = self.service_dst.copy()

                return ret

            def any(self):
                if HFlow.Tunnel.Traffic.ANY is None:
                    HFlow.Tunnel.Traffic.ANY = HFlow.Tunnel.Traffic.Any()
                return HFlow.Tunnel.Traffic.ANY

            class Any(object):
                def __str__(self):
                    return "any"

                def copy(self):
                    return HFlow.Tunnel.Traffic.ANY

                def intersect(self, other):
                    return other

        def copy(self, copy_src_traffic_to_dst=False):
            ret = HFlow.Tunnel()
            ret.traffic_start = self.traffic_start.copy()

            if copy_src_traffic_to_dst:
                ret.traffic_end = self.traffic_start.copy()
            else:
                ret.traffic_end = self.traffic_end.copy()

            return ret

        def repr_in(self):
            return "[ip:{} , dns:{} , service:{}]".format(self.ip_src, self.dns_src, self.service_src)

        def repr_out(self):
            return "[ip:{} , dns:{} , service:{}]".format(self.ip_dst, self.dns_dst, self.service_dst)


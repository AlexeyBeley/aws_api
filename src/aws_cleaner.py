
import pdb
import datetime
import json
from collections import defaultdict

from common_utils import CommonUtils

from dns import DNS

from text_block import TextBlock
from aws_api import AWSAPI


class AWSCleaner(object):
    MEGA = 1024 * 1024
    GIGA = MEGA * 1024
    TERA = GIGA * 1024

    def __init__(self, aws_api, logger=None):
        self.aws_api = aws_api
        self.logger = logger

    def int_to_readable_size(self, size):
        if size > self.TERA:
            return "{} Tb".format(round(size / self.TERA, 2))
        elif size > self.GIGA:
            return "{} Gb".format(round(size / self.GIGA, 2))

        return "{} Mb".format(round(size / self.MEGA, 2))

    # S3
    def cleanup_report_s3_buckets(self):
        tb_ret = TextBlock("Cleaning S3 buckets")

        for bucket in self.aws_api.s3_buckets:
            total_size = sum([content["Size"] for content in bucket.contents])
            total_size = self.int_to_readable_size(total_size)

            bucket_block = TextBlock("{} bucket has {} keys, total size: {}".format(bucket.name, len(bucket.contents), total_size))
            tb_ret.blocks.append(bucket_block)

        print(tb_ret.format())
        pdb.set_trace()

        return tb_ret

    def cleanup_report_s3_large_bucket(self, files_names):
        start_time = datetime.datetime.now()
        len_all_files = len(files_names)
        dict_by_years = defaultdict(lambda: {"size": 0, "count": 0})
        dict_by_sizes = defaultdict(lambda: {self.MEGA: {"size": 0, "count": 0},
                                             10*self.MEGA: {"size": 0, "count": 0},
                                             50*self.MEGA: {"size": 0, "count": 0},
                                             100*self.MEGA: {"size": 0, "count": 0},
                                             200*self.MEGA: {"size": 0, "count": 0},
                                             300*self.MEGA: {"size": 0, "count": 0},
                                             400*self.MEGA: {"size": 0, "count": 0},
                                             500*self.MEGA: {"size": 0, "count": 0},
                                             800*self.MEGA: {"size": 0, "count": 0},
                                             1*self.GIGA: {"size": 0, "count": 0}})
        dict_by_keys = {}
        tb_ret = TextBlock("Cleaning large bucket: {}".format(files_names[0]))

        for i in range(len_all_files):
            print("File {}/{}".format(i, len_all_files))
            file_name = files_names[i]
            with open(file_name) as fil:
                keys_details = json.load(fil)

            keys_details = self.sort_keys_details_by_sizes(keys_details)
            self.cleanup_report_s3_large_bucket_split_by_years(keys_details, dict_by_years)
            self.cleanup_report_s3_large_bucket_split_by_sizes(keys_details, dict_by_sizes)
            #self.cleanup_report_s3_large_bucket_large_keys(keys_details, dict_by_keys, self.MEGA*500)
            #pdb.set_trace()

        for year in sorted(list(dict_by_years.keys())):
            tb_ret_year = TextBlock("{}".format(year))
            tb_ret_year.lines.append("Keys: {} Size: {}".format(format(dict_by_years[year]["count"], ","), self.int_to_readable_size(dict_by_years[year]["size"])))
            for size in dict_by_sizes[year].keys():
                if dict_by_sizes[year][size]["count"] == 0:
                    continue
                tb_ret_year.lines.append("<{}: Size: {} Count: {} ".format(self.int_to_readable_size(size), self.int_to_readable_size(dict_by_sizes[year][size]["size"]), format(dict_by_sizes[year][size]["count"], ",")))
            tb_ret.blocks.append(tb_ret_year)

        end_time = datetime.datetime.now()
        print(end_time - start_time)
        pdb.set_trace()
        return tb_ret

    def sort_keys_details_by_sizes(self, keys_details):
        return sorted(keys_details, reverse=True, key=lambda x: x["Size"])

    def cleanup_report_s3_large_bucket_split_by_years(self, keys_details, dict_by_years):
        for details in keys_details:
            year = details["LastModified"][:4]
            dict_by_years[year]["size"] += details["Size"]
            dict_by_years[year]["count"] += 1

    def cleanup_report_s3_large_bucket_split_by_sizes(self, keys_details, dict_by_sizes):
        for details in keys_details:
            year = details["LastModified"][:4]
            size = details["Size"]
            for limit_size in dict_by_sizes[year]:
                if size < limit_size:
                    break
            else:
                raise RuntimeError("Too large value: {}".format(size))

            dict_by_sizes[year][limit_size]["size"] += size
            dict_by_sizes[year][limit_size]["count"] += 1

    def cleanup_report_s3_large_bucket_large_keys(self, keys_details, dict_by_keys, size_limit):
        pdb.set_trace()

    # CloudWatch
    def cleanup_report_cloudwatch_logs(self):
        ret = TextBlock("Cloudwatch logs report")

        ret.blocks.append(self.cleanup_report_cloudwatch_logs_by_old_log_groups())

        ret.blocks.append(self.cleanup_report_cloudwatch_logs_by_all_log_dates())

        ret.blocks.append(self.cleanup_report_cloudwatch_logs_by_last_log_date())

        return ret

    def cleanup_report_cloudwatch_logs_by_old_log_groups(self, date_event_limit=datetime.datetime.now() - datetime.timedelta(days=365)):
        groups_to_delete = []
        pair_before_after = self.split_cloudwatch_logs_by_last_event_date(date_event_limit)
        after_date_groups = list(pair_before_after[1].keys())

        for before_date_group_name in pair_before_after[0].keys():
            if before_date_group_name not in after_date_groups:
                groups_to_delete.append(before_date_group_name)

        ret = TextBlock("CloudWatch Groups to delete")
        for group_name in groups_to_delete:
            ret.lines.append(group_name)
        return ret

    def cleanup_report_cloudwatch_logs_by_all_log_dates(self):

        stream_size_report = "Stream size"
        total_interval_streams_size = "Total streams size"
        dict_reports = {}

        for log_group in self.aws_api.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    date_log_timestamp_last = self.timestamp_to_date(log_stream.last_event_timestamp)
                    key_year_last = str(date_log_timestamp_last.year)

                    date_log_timestamp_first = self.timestamp_to_date(log_stream.first_event_timestamp)
                    key_year_first = str(date_log_timestamp_first)

                    if key_year_last != 0:
                        continue

                    if key_year_last not in dict_reports:
                        dict_reports[key_year_last] = {}

                    if key_year_first not in dict_reports[key_year_last]:
                        dict_reports[key_year_last][key_year_first] = {}

                    if stream_size_report not in dict_reports[key_year_last][key_year_first]:
                        dict_reports[key_year_last][key_year_first][stream_size_report] = TextBlock(stream_size_report)
                        dict_reports[key_year_last][key_year_first][total_interval_streams_size] = 0

                    dict_reports[key_year_last][key_year_first][total_interval_streams_size] += log_stream.stored_bytes
                    dict_reports[key_year_last][key_year_first][stream_size_report].lines.append("{}-{}: {}: {}: {}".format(date_log_timestamp_last, date_log_timestamp_first, log_group.name, log_stream.name, log_stream.stored_bytes))
                except AttributeError:
                    continue

        report = TextBlock("Cleaning logs by log duration")

        return report

    def cleanup_report_cloudwatch_logs_by_last_log_date(self):
        empty_streams_report = "Empty streams found"
        stream_size_report = "Stream size report"
        total_streams_size = "Total streams size"
        dict_reports = {}

        for log_group in self.aws_api.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    date_log_timestamp = self.timestamp_to_date(log_stream.last_event_timestamp)
                    key_line = str(date_log_timestamp.year)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if stream_size_report not in dict_reports[key_line]:
                        dict_reports[key_line][stream_size_report] = TextBlock(stream_size_report)
                        dict_reports[key_line][total_streams_size] = 0

                    dict_reports[key_line][total_streams_size] += log_stream.stored_bytes
                    dict_reports[key_line][stream_size_report].lines.append("{}: {}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name, log_stream.stored_bytes))
                except AttributeError:
                    # handle empty log
                    if log_stream.stored_bytes > 0:
                        raise RuntimeError("When no last_event_time exists, sotred_bytes expected to be 0 {}: {}: {}".format(log_group.name, log_stream.name, log_stream.last_event_timestamp))

                    date_log_timestamp = self.timestamp_to_date(log_stream.creation_time)
                    key_line = str(date_log_timestamp.year)
                    if key_line not in dict_reports:
                        dict_reports[key_line] = {}

                    if empty_streams_report not in dict_reports[key_line]:
                        dict_reports[key_line][empty_streams_report] = TextBlock(empty_streams_report)

                    dict_reports[key_line][empty_streams_report].lines.append("{}: {}: {}".format(date_log_timestamp, log_group.name, log_stream.name))
                    continue

        report = TextBlock("Cleaning logs by last written log line date")
        for year in dict_reports:
            report_year = TextBlock(year)

            report_year.lines.append("{}: {} MB".format(total_streams_size, int(dict_reports[year][total_streams_size]/(1024*1024))))
            report_year.lines.append("{}: {}".format(empty_streams_report, len(dict_reports[year][empty_streams_report].lines)))

            report.blocks.append(report_year)

        return report

    def timestamp_to_date(self, log_timestamp):
        return datetime.datetime.fromtimestamp(log_timestamp / 1000.0)

    def split_cloudwatch_logs_by_last_event_date(self, date_event_limit):
        """
        2018 before 2019

        :param date_event_limit:
        :return: return two dicts - per_log_group streams before(<=), perlog_grpup streams after(>)
        """

        dict_before_date = defaultdict(lambda: defaultdict(list))
        dict_after_date = defaultdict(lambda: defaultdict(list))

        for log_group in self.aws_api.cloudwatch_log_groups:
            for log_stream in log_group.log_streams:
                try:
                    date_log_timestamp = self.timestamp_to_date(log_stream.last_event_timestamp)
                except AttributeError:
                    # handle empty log
                    if log_stream.stored_bytes > 0:
                        raise RuntimeError("When no last_event_time exists, sotred_bytes expected to be 0 {}: {}: {}".format(log_group.name, log_stream.name, log_stream.last_event_timestamp))

                    date_log_timestamp = self.timestamp_to_date(log_stream.creation_time)

                # 2020 > 2019
                if date_log_timestamp > date_event_limit:
                    dict_after_date[log_group.name][log_stream.name].append(date_log_timestamp)
                else:
                    dict_before_date[log_group.name][log_stream.name].append(date_log_timestamp)

        return dict_before_date, dict_after_date

    def delete_cloudwatch_logs_by_last_event_date(self, date_event_limit=datetime.datetime.now() - datetime.timedelta(days=380)):
        dict_before_date, dict_after_date = self.split_cloudwatch_logs_by_last_event_date(date_event_limit)

        all_splited_groups = set(dict_before_date.keys()).union(set(dict_after_date.keys()))
        empty_groups_names = {grp.name for grp in self.aws_api.cloudwatch_log_groups}.difference(all_splited_groups)

        old_groups_to_be_deleted = []
        partial_group_streams_to_be_deleted = []

        for grp_name, grp_streams in dict_before_date.items():
            if grp_name in dict_after_date:
                partial_group_streams_to_be_deleted.append(grp_name)
                continue

            old_groups_to_be_deleted.append(grp_name)

        export_list = []
        for grp in empty_groups_names:
            export_list.append((grp, []))

        for grp in old_groups_to_be_deleted:
            export_list.append((grp, []))

        for grp in partial_group_streams_to_be_deleted:
            export_list.append((grp, dict_before_date[grp]))
        #todo:
        #failed_to_export = self.aws_api.synchronous_export_cloudwatch_logs(export_list, upload_s3_bucket_name, bucket_prefix)
        failed_to_export = []
        if len(failed_to_export) != 0:
            self.logger.warning("len(failed_to_export) = {} should be 0 ".format(len(failed_to_export)))
            pdb.set_trace()
            raise NotImplementedError("Handle unexported pairs")

        failed_to_delete = self.aws_api.delete_cloudwatch_logs(export_list, dry_run=False)
        if len(failed_to_delete) != 0:
            pdb.set_trace()
            self.logger.warning("len(failed_to_delete) = {} should be 0".format(len(failed_to_delete)))
            raise NotImplementedError("Handle undeleted pairs")

    def clear_s3_bucket_path_token(self, token):
        while "//" in token:
            token = token.replace("//", "/")

        return token.strip("/")

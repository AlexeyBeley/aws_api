import pdb
import datetime
import time

from boto3_client import Boto3Client
from cloudwatch_log_group import CloudwatchLogGroup


class CloudWatchLogsClient(Boto3Client):
    def __init__(self, aws_key_id, aws_access_secret, region_name, logger):
        client_name = "logs"
        super(CloudWatchLogsClient, self).__init__(client_name, aws_key_id, aws_access_secret, region_name, logger)

    @Boto3Client.requires_connection
    def get_all_log_groups(self, full_information=True):
        final_result = list()
        for log_group in self.execute(self.client.describe_log_groups, "logGroups"):
            obj = CloudwatchLogGroup(log_group)
            final_result.append(obj)

            if full_information:
                update_info = list(self.execute(self.client.describe_log_streams, "logStreams", filters_req={"logGroupName": log_group["logGroupName"]}))
                obj.init_cloudwatch_log_streams(update_info)

        return final_result

    @Boto3Client.requires_connection
    def delete_log_group(self, group_name):
        """

        :param group_name:
        :return: Return True if succeded False else.
        """

        self.logger.info("Deleting Cloudwatch Group '{}'".format(group_name))
        filters_req = {"logGroupName": group_name}
        req_generator = self.execute(self.client.delete_log_group, "ResponseMetadata", filters_req=filters_req)
        return self.parse_delete_command_reply(req_generator)

    @Boto3Client.requires_connection
    def delete_log_streams(self, group_name, stream_names):
        """
        Returns list of pairs- [(group_name, failed stream), ...]
        :param group_name:
        :param stream_names:
        :return:
        """

        failed_streams = []
        for stream_name in stream_names:
            self.logger.info("Deleting Cloudwatch Group's '{}' stream '{}'".format(group_name, stream_name))

            filters_req = {"logGroupName": group_name, "logStreamName": stream_name}
            req_generator = self.execute(self.client.delete_log_stream, "ResponseMetadata", filters_req=filters_req)
            if not self.parse_delete_command_reply(req_generator):
                failed_streams.append((group_name, stream_name))
        return failed_streams

    def parse_delete_command_reply(self, req_generator):
        reply = list(req_generator)
        try:
            return reply[0]["HTTPStatusCode"] == 200
        except (KeyError, IndexError):
            self.logger.warning("Expected 200, received {}".format(reply))
            return False

    @Boto3Client.requires_connection
    def asynchronous_export_task(self, bucket_name, bucket_prefix, group_name, stream_name, from_time=datetime.datetime.strptime("01/01/2015", "%d/%m/%Y"), to_time=datetime.datetime.now()):
        filters_req = self.generate_export_task_request(group_name, stream_name, bucket_name, bucket_prefix, from_time, to_time)

        if stream_name is None:
            message = "Triggering export task for group '{}'".format(group_name)
        else:
            message = "Triggering export task for group '{}' stream '{}'".format(group_name, stream_name)

        self.logger.info(message)
        req_generator = self.execute(self.client.create_export_task, "taskId", filters_req=filters_req)

        for task_id in req_generator:
            return task_id

    @Boto3Client.requires_connection
    def synchronous_export_task(self, bucket_name, bucket_prefix, group_name, stream_names, from_time=datetime.datetime.strptime("01/01/2015", "%d/%m/%Y"), to_time=datetime.datetime.now()):
        """
        Return [(group_name, streams)] failed to be exported
        If no failed return []

        :param bucket_name:
        :param bucket_prefix:
        :param group_name:
        :param stream_names:
        :param from_time:
        :param to_time:
        :return:
        """
        if len(stream_names) == 0:
            #todo: remove!
            return []
            task_id = self.asynchronous_export_task(bucket_name, bucket_prefix, group_name, None, from_time=from_time, to_time=to_time)
            ret = self.wait_for_exports_to_finish([task_id], 5*60)
            if ret:
                return []
        else:
            return_failed = []
            for stream_name in stream_names:
                task_id = self.asynchronous_export_task(bucket_name, bucket_prefix, group_name, stream_name, from_time=from_time, to_time=to_time)
                try:
                    ret = self.wait_for_exports_to_finish([task_id], 5 * 60)
                    if not ret:
                        return_failed.append(stream_name)
                except Exception as e:
                    return_failed.append(stream_name)
                    self.logger.error("Failed exporting group {} stream {} with error {}".format(group_name, stream_name, repr(e)))
            return (group_name, return_failed) if return_failed else []

    @Boto3Client.requires_connection
    def wait_for_exports_to_finish(self, waiting_list, timeout_seconds):
        sleep_interval = 1
        waiting_list_local = waiting_list[:]

        for i in range(int(timeout_seconds/sleep_interval)):
            if len(waiting_list_local) == 0:
                break
            waiting_list_local_tmp = waiting_list_local[:]
            try:
                for task_id in waiting_list_local:
                    req_generator = self.execute(self.client.describe_export_tasks, "exportTasks", filters_req={"taskId": task_id})
                    reply = list(req_generator)

                    if len(reply) != 1:
                        raise RuntimeError("expected 1 reply recieved {}".format(len(reply)))

                    ret_code = reply[0]["status"].get("code")
                    if ret_code == "COMPLETED":
                        waiting_list_local_tmp.remove(task_id)
                    elif ret_code in ["PENDING", "RUNNING"]:
                        self.logger.info("export task {} is in status {}".format(task_id, ret_code))
                    else:
                        pdb.set_trace()
                        raise ValueError(reply[0])
            except Exception as e:
                self.logger.error("Exception recieved waiting to finish {}".format(repr(e)))

            waiting_list_local = waiting_list_local_tmp
            self.logger.info("Waiting for {} export tasks to finish going to sleep for {}".format(len(waiting_list_local), sleep_interval))
            time.sleep(sleep_interval)

        return len(waiting_list_local) == 0

    def generate_export_task_request(self, group_name, stream_name, bucket_name, bucket_prefix, from_time, to_time):
        from_time_int = self.datetime_to_timestamp_milliseconds(from_time)
        to_time_int = self.datetime_to_timestamp_milliseconds(to_time)

        destination_prefix = "{}/{}".format(bucket_prefix, group_name)
        while "//" in destination_prefix:
            destination_prefix = destination_prefix.replace("//", "/")

        filters_req = {"taskName": group_name,
                       "logGroupName": group_name,
                       "fromTime": from_time_int,
                       "to": to_time_int,
                       "destination": bucket_name,
                       "destinationPrefix": destination_prefix}

        if stream_name is not None:
            filters_req["logStreamNamePrefix"] = stream_name

        return filters_req

    def datetime_to_timestamp_milliseconds(self, date_src):
        return int(time.mktime(date_src.timetuple())) * 1000




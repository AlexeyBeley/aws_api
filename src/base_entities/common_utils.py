class CommonUtils:
    @staticmethod
    def find_objects_by_values(objects, values, max_count=None):
        """
        Find objects with all specified values.
        If no such attr: do not add to the return list

        :param objects: list of objects
        :param values: dict of key - value
        :param max_count: Maximum amount to return
        :return:
        """

        objects_ret = []
        for obj in objects:
            for key, value in values.items():
                try:
                    if getattr(obj, key) != value:
                        break
                except AttributeError:
                    break
            else:
                objects_ret.append(obj)
                if max_count is not None and len(objects_ret) >= max_count:
                    break

        return objects_ret
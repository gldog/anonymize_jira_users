from datetime import datetime


class Tools:

    @staticmethod
    def to_date_string(date_time: datetime):
        """Create a uniform date/time-string without nit-picky milliseconds"""
        return date_time.strftime('%Y-%m-%dT%H:%M:%S')

    @staticmethod
    def now_to_date_string():
        return Tools.to_date_string(datetime.now())

    @staticmethod
    def time_diff(d1, d2):
        format_string = '%Y-%m-%dT%H:%M:%S.%f'
        dd1 = datetime.strptime(d1.split("+")[0], format_string)
        dd2 = datetime.strptime(d2.split("+")[0], format_string)
        return dd2 - dd1

    @staticmethod
    def get_formatted_timediff_mmss(time_diff):
        """Convert the given time_diff to format "MM:SS". If the time-diff is < 1s, overwrite it to 1s.

        The MM can be > 60 min.

        :param time_diff: The time-diff
        :return: Time-diff in MM:SS, but min. 1s.
        """

        # Convert to integer because nobody will be interested in the milliseconds-precision. If the diff is 0,
        # overwrite it to 1 (second).
        s = int(time_diff.total_seconds())
        if s == 0:
            s = 1
        minutes = s // 60
        seconds = s % 60
        formatted_diff = f'{minutes:02d}:{seconds:02d}'

        return formatted_diff

    @staticmethod
    def get_formatted_timediff_hhmmss(time_diff):
        """Convert the given time_diff to format "HH:MM:SS". If the time-diff is < 1s, overwrite it to 1s.

        The HH can be > 24 h.

        :param time_diff: The time-diff
        :return: Time-diff in MM:SS, but min. 1s.
        """

        # Convert to integer because nobody will be interested in the milliseconds-precision. If the diff is 0,
        # overwrite it to 1 (second).
        s = int(time_diff.total_seconds())
        if s == 0:
            s = 1

        hours, remainder = divmod(s, 3600)
        minutes, seconds = divmod(remainder, 60)
        formatted_diff = f'{hours:02d}:{minutes:02d}:{seconds:02d}'

        return formatted_diff

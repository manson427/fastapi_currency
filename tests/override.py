class OverrideSendEmail:
    @staticmethod
    async def send_email(*ar, **kw):
        return True
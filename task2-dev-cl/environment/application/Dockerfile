FROM public.ecr.aws/lambda/python:3.12@sha256:8a1fd022123cfc44acab0b8447d0ba46f2b385ec51ee15c9074a72627b6f4797 AS base
COPY common.py /var/task/common.py

FROM base AS publisher
COPY publisher.py /var/task/publisher.py
CMD ["publisher.handler"]

FROM base AS worker
COPY worker.py /var/task/worker.py
CMD ["worker.handler"]

FROM base AS replay
COPY replay.py /var/task/replay.py
CMD ["replay.handler"]

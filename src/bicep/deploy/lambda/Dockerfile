FROM public.ecr.aws/lambda/python:3.12

RUN pip install --upgrade boto3 botocore --no-cache-dir && \
    pip install azure-cli --no-cache-dir

RUN az bicep install

COPY index.py ${LAMBDA_TASK_ROOT}

CMD ["index.handler"]

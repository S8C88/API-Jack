FROM python:3.11-slim
LABEL org="Sideways 8 Creations"
WORKDIR /app
RUN addgroup --system s8c88 && adduser --system --ingroup s8c88 s8c88
COPY --chown=s8c88:s8c88 requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=s8c88:s8c88 apijack.py endpoints.json .
COPY --chown=s8c88:s8c88 examples examples/
USER s8c88
ENTRYPOINT ["python", "apijack.py"]
CMD ["--help"]

# 智能体密码身份中台（v2.5）
# 零第三方依赖，纯 Python 3.13；生产传输层用 uvicorn（可选安装）
FROM python:3.13-slim

WORKDIR /app

# 复制原型代码
COPY proto/ /app/proto/

# 复制入口脚本与配置示例
COPY entrypoint.py /app/
COPY config.example.json /app/config.example.json

# 时区与语言
ENV TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8 \
    PYTHONPATH=/app/proto

# 生产部署用 ASGI：装 uvicorn 后可用（镜像默认不装，保持零依赖）
#   pip install uvicorn
#   AC_DB=/data/state.db AC_AUTH=/app/config.json \
#     uvicorn asgi_app:app --host 0.0.0.0 --port 8000
# 不装 uvicorn 时退化为 stdlib http.server：
#   python /app/proto/http_api.py --host 0.0.0.0 --port 8000 --db /data/state.db

# 数据目录（SQLite 状态库落盘位置）
VOLUME ["/data"]

EXPOSE 8000

# 默认跑演示脚本；可覆盖为 --check（全量验证）或 --api（起服务）
ENTRYPOINT ["python", "/app/entrypoint.py"]

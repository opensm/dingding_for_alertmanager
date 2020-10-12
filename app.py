# -*- coding:utf-8 -*-
import os
import json
import requests
import arrow
import hashlib, base64, urllib, hmac, requests, json, sys, os, datetime, time
from flask import Flask
from flask import request

import sys

reload(sys)
sys.setdefaultencoding('utf-8')

app = Flask(__name__)

pop_keys = [
    "node", "comparison", "alert_type", "job",
    "alert_type", "prometheus_from", "endpoint",
    "rule_id", "prometheus", "cluster_name", "group_id"
]
format_alert = {
    "status": "状态",
    "alertname": "报警名称",
    "duration": "时间段",
    "severity": "报警等级",
    "namespace": "命名空间",
    "instance": "实例",
    "host_ip": "主机IP",
    "expression": "监控表达式",
    "alert_name": "报警名称",
    "startsAt": "开始时间",
    "endsAt": "结束时间"
}


@app.route('/', methods=['POST', 'GET'])
def send():
    if request.method == 'POST':
        post_data = request.get_data()
        format_data = bytes2json(data_bytes=post_data)
        send_alert(data=format_data)
        return 'success'
    else:
        return 'weclome to use prometheus alertmanager dingtalk webhook server!'


def bytes2json(data_bytes):
    """
    :param data_bytes:
    :return:
    """
    data = data_bytes.decode('utf8').replace("'", '"')
    return json.loads(data)


def pop_dict_key(data, key):
    """
    :param data:
    :param key:
    :return:
    """
    if key not in data:
        return data
    else:
        data.pop(key)
        return data


def format_data(data):
    """
    :param data:
    :return:
    """
    if not isinstance(data, list):
        print("输入的数据不是列表")
    rule_list = list()
    for value in data:
        if value['labels']['rule_id'] in rule_list:
            continue
        rule_list.append(value['labels']['rule_id'])
    return rule_list


def alert_count(data):
    """
    :param data:
    :return:
    """
    rule_dict = dict()
    rule_list = format_data(data=data)
    for rule in rule_list:
        rule_count = 0
        for value in data:
            if value['labels']['rule_id'] != rule:
                continue
            rule_count = rule_count + 1
        rule_dict[rule] = rule_count
    return rule_dict


def pop_dict_keys(data):
    """
    :param data:
    :return:
    """
    result = data
    for key in pop_keys:
        result = pop_dict_key(data=result, key=key)
    return result


def send_alert(data):
    # token = os.getenv('ROBOT_TOKEN')
    # secret = os.getenv('SECRET')
    token = ""
    secret = ""
    if not token or not secret:
        print('you must set ROBOT_TOKEN or SECRET env')
        return
    url = 'https://oapi.dingtalk.com/robot/send?access_token=%s' % token
    if 'alerts' not in data:
        print("获取报警信息失败，不包含报警的信息字段！")
        return

    # 报警类别聚合
    alert_dict = alert_count(data=data['alerts'])
    print(alert_dict)
    for k, v in alert_dict.items():
        for output in data['alerts']:
            alert_data = output['labels']
            # ruleid一样的，只发一条
            if alert_data['rule_id'] != k:
                continue
            alert_string = ""
            alert_data = pop_dict_keys(data=alert_data)
            for key, value in alert_data.items():
                if key in format_alert:
                    format_key = format_alert[key]
                else:
                    format_key = key
                alert_string = "%s**%s**: %s\n\n" % (alert_string, format_key, value)
            alert_string = "%s**额外提示**: 相同报警有%s条\n\n" % (alert_string, v)
            send_data = {
                "msgtype": "markdown",
                "markdown": {
                    "title": "正线环境K8S报警",
                    "text": alert_string
                },
                "at": {
                    "isAtAll": True
                }
            }
            if request_data(data=send_data, secret=secret, url=url):
                break
            else:
                print("尝试发送:{0}失败".format(k))


def request_data(data, secret, url):
    """
    :param data:
    :param secret:
    :param url:
    :return:
    """
    headers = {'Content-Type': 'application/json'}
    timestamp = long(round(time.time() * 1000))
    secret_enc = bytes(secret).encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = bytes(string_to_sign).encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.quote_plus(base64.b64encode(hmac_code))
    url = "{0}&timestamp={1}&sign={2}".format(url, timestamp, sign)
    x = requests.post(url=url, data=json.dumps(data), headers=headers)
    if 'errcode' in x.json():
        if x.json()["errcode"] == 0:
            print("发送请求成功!")
            return True
        else:
            print("发送请求失败:{0}".format(x.content))
            return False
    else:
        if x.json()["status"] == 0:
            print("发送请求成功!")
            return True
        else:
            print("发送请求失败:{0}".format(x.content))
            return False


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

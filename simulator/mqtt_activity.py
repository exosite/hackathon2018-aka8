from paho.mqtt import client as mqtt
import ssl
import csv
import time
import requests
import asyncio
import websockets
import async_timeout
import json
import aiohttp
import string
import threading
import os
import random
from dotenv import load_dotenv
import click

load_dotenv('.env')

applicationDomain = os.getenv("APPLICATION_DOMAIN")
http_applicationDomain = "https://{}".format(applicationDomain)
wss_applicationDomain = "wss://{}".format(applicationDomain)
host = os.getenv("SOLUTION")
cert = os.path.dirname(os.path.abspath(__file__))+'/csr/trusted.csr'
states = {"H00":0,"H01":0,"H02":0,"H03":0,"H04":0,"H06":0,"H0E":0,"H11":0,"H17":0,"H1E":0,"H1F":0,"H20":0,"H21":-32767,"H29":12274}
device_msg = {"id":0,"response":1,"status":"ok"}
Device_pwd = "ThisIsCorrectPassword"
create_thread = int(os.getenv("CREATE_THREAD"))
activate_time = int(os.getenv("ACTIVATE_TIME"))
create_csv = os.getenv("CREDENTIAL_PATH")
class MSG():
    def __init__(self):
        self.print_msg = None

    def info(self, print_msg):
        click.echo(click.style('[Info] ', fg='cyan'), nl=False)
        click.echo(print_msg)

    def warn(self, print_msg):
        click.echo(click.style('[WARN] ', fg='red'), nl=False)
        click.echo(print_msg)

class ExoMqtt(object):
    def __init__(self):
        self.message = {}
        self.timeout = 10
        self.connect = []

    def mqtt_publish(self, client, topic, message=None, qos=0):
        """ Use mqtt protocol to activate the device """
        client.publish(topic, message, qos=qos)

    def start_loop(self, client):
        """ Start loop to MQTT server """
        thread = threading.Thread(target=client.loop_start)
        thread.start()

    def close_loop(self, client):
        """ Close loop to MQTT server """
        client.disconnect()

    def mqtt_message(self):
        """ Returns all received MQTT messages """
        time.sleep(1)
        return self.message

    def _get_message(self, topic, message, timeout=60):
        end = time.time() + timeout
        time.sleep(2)
        while time.time() < end:
            message = self.message
            for index in message:
                if topic in index:
                    return message[index]
        else:
            MSG().warn("Time out!!!!")
            return False

    def on_message(self, client, userdata, msg):
            topic = str(msg.topic)
            resp = {}
            resp['message'] = str(msg.payload.decode("utf-8"))
            self.message.update({topic:resp['message']})
            
            try:
                data = json.loads(msg.payload.decode())
                if str(data['data'].values()[0]).isalnum():
                    states.update(data['data'])
                    client.publish("$resource/action", "[]", qos=0)
                    client.publish("$resource/states", json.dumps(states), qos=0)
                    device_msg.update({"id":data['id']})
                    device_msg.update({"response":data['request']})
                    client.publish("$resource/result", json.dumps(device_msg) , qos=0)
            except Exception as e:
                pass    

    def on_connect(self, client, userdata, flags, rc):
        self.connect.append(userdata)
        self.connect.append(rc)

    def on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print("DisConnected with error", rc)
            exit()

    def mqtt_set(self, app_name=None, token=None, provision=False, name=None):
        self.device_name = app_name
        self.provision = provision
        client = mqtt.Client(client_id="")
        client.tls_set(
            ca_certs=cert,
            server_hostname=host,
            cert_reqs=ssl.CERT_NONE
        )
        client.tls_insecure_set(True)
        if token is not None and name is not None:
            client.username_pw_set(name, token)

        client.on_connect = self.on_connect
        client.on_disconnect = self.on_disconnect
        client.on_message = self.on_message
        client.connect(host, 443)
        return client

def get_all_csv():
    csv_path = os.path.dirname(os.path.abspath(__file__))
    csv_flies = os.listdir(csv_path)
    two_arr = []
    for csv_file in csv_flies:
        if "csv" in csv_file:
            with open(os.path.join(csv_path,csv_file), 'r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    two_arr.append([row["device_name"], row["email"]])

    with open(create_csv, 'w', newline='') as csvfile:
        fieldnames = ['email',"device_name"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for i in two_arr:
            writer.writerow({"device_name": i[0], 'email': i[1]})


def id_generator(size=17, chars=string.ascii_uppercase + string.digits):
    return "".join(random.choice(chars) for _ in range(size))
def csv_file():
    return "device_{}.{}".format(time.time(), "csv")

def provision_device(sn):
    client = ExoMqtt().mqtt_set(app_name=sn, provision=True)
    ExoMqtt().mqtt_publish(client, "$provision/{}".format(sn), message=Device_pwd)
    ExoMqtt().start_loop(client)
    ExoMqtt().close_loop(client)
    return Device_pwd 

def set_devices(phone_token, device_name, device_id="1", app_model="QA-ROBOT-01", device_token=Device_pwd):
    device_esh = {"class":0, "esh_version":"4.00", "device_id":device_id, "brand":"HITACHI", "model":app_model } 
    device_model = { "firmware_version":"2.1.0", "id": device_name[0:12] , "mac_address": device_name[0:12] , "local_ip":"192.168.0.13", "ssid":"Exosite-a83c" }
    device_fields = ["H00", "H01", "H02", "H03", "H04", "H06", "H0E", "H11","H17", "H1E", "H1F", "H20", "H21", "H29"]
    device_cert = {"fingerprint":{"sha1":"1dfac17adf3867c9a28acb329de8d16d8b412d8b"},"validity":{"not_before":"11/10/06","not_after":"11/10/31"}} 
    device_schedules = []
    device_states = {"H00":0,"H01":0,"H02":0,"H03":0,"H04":0,"H06":0,"H0E":0,"H11":0,"H17":0,"H1E":0,"H1F":0,"H20":0,"H21":-32767,"H29":12274}
    device_ota = { "state": "idle"}
    set_mqtt=ExoMqtt()
    client = set_mqtt.mqtt_set(token=device_token, name=device_name)
    ExoMqtt().start_loop(client)
    set_mqtt.mqtt_publish(client, "$resource/esh", json.dumps(device_esh))
    set_mqtt.mqtt_publish(client, "$resource/module", json.dumps(device_model))
    set_mqtt.mqtt_publish(client, "$resource/fields", json.dumps(device_fields))
    set_mqtt.mqtt_publish(client, "$resource/cert", json.dumps(device_cert))
    set_mqtt.mqtt_publish(client, "$resource/schedules", json.dumps(device_schedules))
    set_mqtt.mqtt_publish(client, "$resource/states", json.dumps(device_states))
    set_mqtt.mqtt_publish(client, "$resource/ota", json.dumps(device_ota))
    set_mqtt.mqtt_publish(client, "$resource/token", phone_token)
    ownerId = set_mqtt._get_message("$resource/owner", ".*")
    set_mqtt.mqtt_publish(client, "$resource/owner", ownerId)
    set_mqtt.close_loop(client)
    return device_name

async def activate_device(activate_time):
    csv_num = csv_file()
    with open(csv_num, 'w', newline='') as csvfile:
        fieldnames = ["device_name", 'email']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for i in range(0, activate_time):
            try:
                email = "testing{}@example.com".format(time.time())
                data = '{"password": "1234eszxcv++"}'
                header = {'content-type': 'application/json'}
            
                async with aiohttp.ClientSession() as session:
                    async with session.put(http_applicationDomain + "/api:1/user/" + email,
                                            data=data,
                                            headers=header) as resp:
                        token = await resp.json()
                        
                async with websockets.connect(wss_applicationDomain+"/api:1/phone") as websocket:
                    await websocket.send('{ "id":%s,"request":"login","data":{"token":"%s"} }' % (random.randint(0, 100000), token["token"]))
                    async with async_timeout.timeout(30):
                        resp = await websocket.recv()
                        resp_json = json.loads(resp)
                        if "ok" in resp_json["status"]:
                            await websocket.send('{ "id":%s,"request":"provision_token","data":{"expires_in":2592000} }' % (random.randint(0, 100000)))    
                            async with async_timeout.timeout(30):
                                resp = await websocket.recv()
                                resp_json = json.loads(resp)
                                random_id = id_generator()
                                device_name = 'testing' + random_id
                                device_token = provision_device(device_name)
                                create_csv = set_devices(device_name=device_name, phone_token=resp_json["data"]["token"])
                                MSG().info(create_csv)
                                writer.writerow({"device_name": create_csv, 'email': email})
            except KeyError:
                MSG().warn('I got a KeyError')
                pass
            except asyncio.TimeoutError:
                MSG().warn('Websocket Timeout')
                pass
            # except:
            #     MSG().warn('Some error happend')
            #     pass

jobs = []

for i in range(0, create_thread):
    jobs.append(activate_device(activate_time))
asyncio.get_event_loop().run_until_complete(asyncio.gather(*jobs))

get_all_csv()

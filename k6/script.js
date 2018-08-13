import { check, sleep } from "k6";
import http from "k6/http";

const users = open("device.csv");
var devices = JSON.stringify(users).replace(/(?:\\[rn])+/g, "").split(",");
var aka8 = "https://aka8.apps.exosite.io/";
var cache = "cache/";
var esh = "/temp";

export default function() {
    var device = devices[Math.floor(Math.random()*197+1)]
    var url = aka8 + cache + device + esh;
    console.log(url)
    var payload = JSON.stringify({"value":Math.random()});
    var params =  { headers: { "Content-Type": "application/json" } }
    let res_post = http.post(url, payload, params);
    check(res_post, {
        "is status 200": (r) => r.status === 200
    });

    let res_get = http.get(url, params);
    check(res_get,{
        "is status 200": (r) => r.status === 200,
        "verify sum": (r) => "sum" in JSON.parse(r.body).temp,
        "verify avg": (r) => "avg" in JSON.parse(r.body).temp, 
        "verify count": (r) => "count" in JSON.parse(r.body).temp,
        "verify last": (r) => "last" in JSON.parse(r.body).temp,
        "verify max": (r) => "max" in JSON.parse(r.body).temp,
        "verify min": (r) => "min" in JSON.parse(r.body).temp
    }
    )
    
    sleep(1)
};
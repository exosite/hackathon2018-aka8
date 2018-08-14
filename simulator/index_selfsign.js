if (!process.env.DOCKER) {
    require('dotenv').config()
}
const SOLUTION = process.env['SOLUTION']
const CERT_PATH = process.env['CERT_PATH']
const CREDENTIAL_PATH = process.env['CREDENTIAL_PATH']
const PASSWORD = process.env['PASSWORD']
const START_INDEX = process.env['START_INDEX']
const END_INDEX = process.env['END_INDEX']
const DEVICE_DELAY = process.env['DEVICE_DELAY']
const DEVICE_PERIOD = process.env['DEVICE_PERIOD']
const LOG_LEVEL = process.env['LOG_LEVEL']
const LOG_PUBLISH_FREQUENCY = Number(process.env['LOG_PUBLISH_FREQUENCY'])
const LOG_DEVICE_START_FREQUENCY = Number(process.env['LOG_DEVICE_START_FREQUENCY'])
const PUBLISH_TIMES = process.env['PUBLISH_TIMES']
const RECONNECT_PERIOD = Number(process.env['RECONNECT_PERIOD'])
const KEEPALIVE_SEC = Number(process.env['KEEPALIVE_SEC'])

require('events').EventEmitter.defaultMaxListeners = 100
const mqtt = require('mqtt')
const async_wrapper = require('async-mqtt').AsyncClient
const async_event = require('event-to-promise')
const fs = require('fs')
const sleep = require('es7-sleep')
const util = require('util')
const csvloader = require('csv-load-sync')
const cert = fs.readFileSync(process.env.CERT_PATH)

const log4js = require('log4js')
log4js.configure({
    appenders: {
        out: {type: 'console'},
        default: {type: 'dateFile', filename: 'logs/hamv', "pattern": "-yyyy-MM-dd.log", alwaysIncludePattern: true},
    },
    categories: {
        default: {appenders: ['out', 'default'], level: LOG_LEVEL},
    }
})
const logger = log4js.getLogger()

const devices = csvloader(process.env.CREDENTIAL_PATH, {
    getColumns: (line, line_num) => {
        if (line_num === 0) {
            return line.split(',')
        }
        const row = line.split(',')
        return [row[0], row[1]]
    }
}).slice(START_INDEX, END_INDEX)

async function report(id) {
    let client
    try {
        client = mqtt.connect(`mqtts://${SOLUTION}:443/`, {
            username: id,
            password: PASSWORD,
            cert: cert,
            servername: SOLUTION,
            clientId: '',
            reconnectPeriod: RECONNECT_PERIOD,
            keepalive: KEEPALIVE_SEC,
            rejectUnauthorized: false
            // clean: true,
        })
        client.on('error', (err) => {logger.error(`${id} ${err}`)})
        client.on('close', () => {logger.info(`${id} closed`)})
        client.on('reconnect', () => {logger.warn(`${id} reconnect`)})
        await async_event(client, 'connect')
    } catch (e) {
        logger.error(id, e)
        client.end()
        return
    }
    logger.info(`${id} connected`)
    let async_client = new async_wrapper(client)
    let i = 1
    while (i <= PUBLISH_TIMES) {
        try {
            let ret = await async_client.publish('$resource/states', `{"H04": ${i}}`, {qos:1}).then( () => {
                logger.debug(`${id} set H04 as ${i}`)
            })
            if (i > 0 && i % LOG_PUBLISH_FREQUENCY === 0) {
                logger.warn(`${id} has published ${i} times.`)
            }
            if (i < PUBLISH_TIMES) {
                await sleep(DEVICE_PERIOD)
            }
            i++
        } catch (e) {
            logger.error(`${id} ${e}`)
        }
    }
    async_client.end().then(function() {
        logger.info(`${id} is done`)
    })
}

async function run() {
    let count = 1
    for (device of devices) {
        try {
            logger.debug(`concurrent reporting devices: ${count}`)
            if(count % LOG_DEVICE_START_FREQUENCY === 0) {
                logger.warn(`concurrent reporting devices: ${count}`)
            }
            report(device.device_name)
            await sleep(DEVICE_DELAY)
            count++
        } catch (e) {
            logger.error(e)
        }
    }
}

run(devices)

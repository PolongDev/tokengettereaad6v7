const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

function randomString(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function encodeSig(data) {
    const sortedData = Object.fromEntries(Object.entries(data).sort());
    const dataStr = Object.entries(sortedData).map(([key, value]) => `${key}=${value}`).join('');
    return crypto.createHash('md5').update(dataStr + '62f8ce9f74b12f84c123cc23437a4a32').digest('hex');
}

function convertCookie(session) {
    return session.map(item => `${item.name}=${item.value}`).join('; ');
}

async function convertToken(token) {
    try {
        const response = await axios.get(`https://api.facebook.com/method/auth.getSessionforApp?format=json&access_token=${token}&new_app_id=275254692598279`);
        return response.data.access_token;
    } catch (error) {
        if (error.response && error.response.data && 'error' in error.response.data) {
            throw new Error(error.response.data.error);
        } else {
            throw error;
        }
    }
}

function convert2FA(twofactorCode) {
    return parseInt(twofactorCode, 10);
}

app.post('/login', async (req, res) => {
    const { email, password, twofactorCode } = req.body;

    const deviceID = uuidv4();
    const adid = uuidv4();
    const randomStr = randomString(24);

    const form = {
        adid,
        email,
        password,
        format: 'json',
        device_id: deviceID,
        cpl: 'true',
        family_device_id: deviceID,
        locale: 'en_US',
        client_country_code: 'US',
        credentials_type: 'device_based_login_password',
        generate_session_cookies: '1',
        generate_analytics_claim: '1',
        generate_machine_id: '1',
        currently_logged_in_userid: '0',
        irisSeqID: 1,
        try_num: '1',
        enroll_misauth: 'false',
        meta_inf_fbmeta: 'NO_FILE',
        source: 'login',
        machine_id: randomStr,
        fb_api_req_friendly_name: 'authenticate',
        fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
        api_key: '882a8490361da98702bf97a021ddc14d',
        access_token: '350685531728%7C62f8ce9f74b12f84c123cc23437a4a32',
    };

    form.sig = encodeSig(form);

    const headers = {
        'content-type': 'application/x-www-form-urlencoded',
        'x-fb-friendly-name': form.fb_api_req_friendly_name,
        'x-fb-http-engine': 'Liger',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    };

    const url = 'https://b-graph.facebook.com/auth/login';

    try {
        const response = await axios.post(url, new URLSearchParams(form), { headers });

        if (response.status === 200) {
            let data = response.data;
            if ('session_cookies' in data) {
                data.cookies = convertCookie(data.session_cookies);
            }
            if ('access_token' in data) {
                data.access_token = await convertToken(data.access_token);
            }
            res.json({
                status: true,
                message: 'Retrieve information successfully!',
                data,
            });
        } else if (response.status === 401) {
            res.status(401).json({
                status: false,
                message: response.data.error.message,
            });
        } else if ('twofactor' in data && data.twofactor === '0') {
            res.status(400).json({
                status: false,
                message: 'Please enter the 2-factor authentication code!',
            });
        } else {
            twofactorCode = convert2FA(twofactorCode);
            if (!isNaN(twofactorCode)) {
                form.twofactor_code = twofactorCode;
                form.encrypted_msisdn = '';
                form.userid = response.data.error.error_data.uid;
                form.machine_id = response.data.error.error_data.machine_id;
                form.first_factor = response.data.error.error_data.login_first_factor;
                form.credentials_type = 'two_factor';
                form.sig = encodeSig(form);

                const response2 = await axios.post(url, new URLSearchParams(form), { headers });
                if (response2.status === 200) {
                    let data = response2.data;
                    if ('session_cookies' in data) {
                        data.cookies = convertCookie(data.session_cookies);
                    }
                    if ('access_token' in data) {
                        data.access_token = await convertToken(data.access_token);
                    }
                    res.json({
                        status: true,
                        message: 'Retrieve information successfully!',
                        data,
                    });
                } else {
                    res.status(500).json({
                        status: false,
                        message: response2.data,
                    });
                }
            } else {
                res.status(400).json({
                    status: false,
                    message: 'Invalid 2-factor authentication code!',
                });
            }
        }
    } catch (error) {
        res.status(500).json({
            status: false,
            message: 'Please check your account and password again!',
        });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server is listening at http://localhost:${port}`);
});

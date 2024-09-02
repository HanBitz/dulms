// ==UserScript==
// @name        DU LMS Auto Login
// @namespace   DULMS_AL_V1
// @match       https://sso.daegu.ac.kr/dgusso/ext/lms/login_process.do
// @match       https://sso.daegu.ac.kr/dgusso/ext/lms/login_form.do
// @match       https://lms.daegu.ac.kr/ilos/main/main_form.acl
// @require     https://cdn.jsdelivr.net/npm/sweetalert2@11
// @icon        https://www.google.com/s2/favicons?sz=64&domain=https://lms.daegu.ac.kr
// @grant       none
// @version     1.0
// @author      H
// @description 2024. 9. 2. 오전 10:02:08
// @grant       GM.getValue
// @grant       GM.setValue
// @grant       GM.deleteValue
// @grant       GM.registerMenuCommand
// @grant       GM.unregisterMenuCommand
// ==/UserScript==


//https://github.com/bradyjoslin/webcrypto-example
const WebCrypter = {
  // for large strings, use this from https://stackoverflow.com/a/49124600
  _buff_to_base64 : function (buff) {
    return btoa(
      new Uint8Array(buff).reduce(
        (data, byte) => data + String.fromCharCode(byte), ''
      )
    );
  },
  _base64_to_buf : function (b64) {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(null));
  },
  _getPasswordKey : function (password) {
    return window.crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), "PBKDF2", false, [
      "deriveKey",
    ]);
  },
  _deriveKey : function (passwordKey, salt, keyUsage) {
    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 250000,
        hash: "SHA-256",
      },
      passwordKey,
      { name: "AES-GCM", length: 256 },
      false,
      keyUsage
    );
  },
  encryptData: async function (secretData, password) {
    try {
      const salt = window.crypto.getRandomValues(new Uint8Array(16));
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const passwordKey = await WebCrypter._getPasswordKey(password);
      const aesKey = await WebCrypter._deriveKey(passwordKey, salt, ["encrypt"]);

      const encryptedContent = await window.crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        aesKey,
        (new TextEncoder()).encode(secretData)
      );

      const encryptedContentArr = new Uint8Array(encryptedContent);
      let buff = new Uint8Array(
        salt.byteLength + iv.byteLength + encryptedContentArr.byteLength
      );
      buff.set(salt, 0);
      buff.set(iv, salt.byteLength);
      buff.set(encryptedContentArr, salt.byteLength + iv.byteLength);
      const base64Buff = WebCrypter._buff_to_base64(buff);
      return base64Buff;
    } catch (e) {
      console.log(`Encrypt Error - ${e}`);
      return "";
    }
  },
  decryptData: async function (encryptedData, password) {
    try {
      const encryptedDataBuff = WebCrypter._base64_to_buf(encryptedData);
      const salt = encryptedDataBuff.slice(0, 16);
      const iv = encryptedDataBuff.slice(16, 16 + 12);
      const data = encryptedDataBuff.slice(16 + 12);
      const passwordKey = await WebCrypter._getPasswordKey(password);
      const aesKey = await WebCrypter._deriveKey(passwordKey, salt, ["decrypt"]);
      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        aesKey,
        data
      );
      return (new TextDecoder()).decode(decryptedContent);
    } catch (e) {
      console.log(`Decrypt Error - ${e}`);
      return "";
    }
  },
};

//https://stackoverflow.com/questions/5525071
function waitForElm(selector) {
  return new Promise(resolve => {
    if (document.querySelector(selector)) {
      return resolve(document.querySelector(selector));
    }

    const observer = new MutationObserver(mutations => {
      if (document.querySelector(selector)) {
        observer.disconnect();
        resolve(document.querySelector(selector));
      }
    });

    // If you get "parameter 1 is not of type 'Node'" error, see https://stackoverflow.com/a/77855838/492336
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  });
}

async function releaseState() {
  await GM.setValue('tryLogin', false)
}

async function loginProcessLogger(returnedAlert) {
  console.log(returnedAlert);
  let logForm = {
    'dt':(new Date()).toLocaleString(),
    'log': returnedAlert,
  };
  await GM.setValue('lastLogShow', logForm);
  await GM.setValue('lastLogArchived', logForm);
  await GM.setValue('tryLogin', true);
  // if(returnedAlert.match('아이디 또는 비밀번호가 맞지 않습니다')) {
  //   await GM.setValue('isLogined', false);
  // }
}

async function showLog() {
  let log_T = await GM.getValue('lastLogShow', '')
  if(log_T) {
    console.log(log_T)
    if(log_T.hasOwnProperty('log')) {
      let footer=(log_T.hasOwnProperty('dt'))?'로그 시간: '+log_T.dt:undefined
      await Swal.fire({
        icon: "warning",
        title: "LMS 자동 로그인",
        html: "<div style='margin-bottom:0.5em;'>로그인 도중 다음 문제가 발생했습니다.</div><span style='font-size:0.75em;'>"+log_T.log.replace(/\n/g, '<br />').replace('[SSO] ', '')+"</span>",
        footer: footer,
        toast: true,
        position: "top-start",
        willClose: async () => {
          await GM.setValue('lastLogShow', '');
        },
        focusConfirm: false,
        confirmButtonText: '암호 재등록',
        showCancelButton: true,
        cancelButtonText: '닫기',
      }).then((result) => {
        if (result.isConfirmed) {
          registerAccount();
        }
      });
    } else {
      await Swal.fire({
        icon: "error",
        title: "LMS 자동 로그인",
        html: "로그 내용을 불러올 수 없습니다..",
        toast: true,
        position: "top-start",
        confirmButtonText: '닫기',
        willClose: async () => {
          await GM.setValue('lastLogShow', '');
        }
      });
    }
    return true
  } else return false
}

async function keyGenerator() {
  let cryptoKey = crypto.getRandomValues(new Uint8Array(12));
  await GM.setValue('cryptoKey', btoa(cryptoKey));
  console.log('crypto key is updated')
  return cryptoKey;
}

async function registerAccount() {
  const { value: formValues } = await Swal.fire({
    title: "LMS 자동 로그인",
    html: `
      <div style='margin-bottom:0.5em;'><b>자동로그인에 사용할 아이디나 암호를 입력해주세요..</b></div>
      <div>ID: <input id="registerForm-id" class="swal2-input" type='text' placeholder="아이디 입력"></div>
      <div>PW: <input id="registerForm-pw" class="swal2-input" type='password' placeholder="암호 입력"></div>
    `,
    focusConfirm: false,
    showLoaderOnConfirm: true,
    preConfirm: () => {
      const id_T = document.getElementById("registerForm-id").value;
      const pw_T = document.getElementById("registerForm-pw").value;
      if(id_T == '' || pw_T == '') {
        return Swal.showValidationMessage('ID 또는 PW 란이 비어있습니다..')
      } else {
        async function tmp_TT() {
          let key=await keyGenerator();
          let tmp_V = {
            'id': await WebCrypter.encryptData(id_T, key),
            'pw': await WebCrypter.encryptData(pw_T, key),
          }
          await GM.setValue('b3UserCredential', tmp_V);
          console.log('password has been changed')
        }
        tmp_TT();

        return true;
      }
    },
    confirmButtonText: '확인',
    showCancelButton: true,
    cancelButtonText: '닫기',
  });
  //console.log(formValues)
  if(formValues || formValues == true) {
    //reset state
    await releaseState();
    await Swal.fire({
      icon: "success",
      title: "LMS 자동 로그인",
      html: "등록이 완료되었습니다.<br><i>새로고침 시 자동 적용됩니다</i>",
      toast: true,
      position: "top-start",
      confirmButtonText: '확인',
      timer: 3000,
      timerProgressBar: true,
    });
  } else {
    console.log('register canceled.')
  }
}


async function run() {
  //get encrypted account info
  let usr_T = await GM.getValue('b3UserCredential', '')
  //id and password is undefined
  if (!(usr_T && usr_T.hasOwnProperty('id') && usr_T.hasOwnProperty('pw') && usr_T.id != '' && usr_T.pw != '')) {
    console.log('not registered.')
    await Swal.fire({
      icon: "warning",
      title: "LMS 자동 로그인",
      html: "<div style='margin-bottom:0.5em;'>자동로그인 계정이 등록되지 않았습니다</div><div><i>등록이 필요합니다..</i></div>",
      toast: true,
      position: "top-start",
      confirmButtonText: '등록',
      showCancelButton: true,
      cancelButtonText: '닫기',
    }).then((result) => {
      if (result.isConfirmed) {
        registerAccount();
      }
    });
    return
  }

  //get encryption key
  let key=atob(await GM.getValue('cryptoKey', ''));
  if(!key) {
    await Swal.fire({
      icon: "warning",
      title: "LMS 자동 로그인",
      html: "<div style='margin-bottom:0.5em;'>로그인 정보 해독을 위한 키가 존재하지 않습니다</div><div><i>재등록이 필요합니다..</i></div>",
      toast: true,
      position: "top-start",
      confirmButtonText: '재등록',
      showCancelButton: true,
      cancelButtonText: '닫기',
    }).then((result) => {
      if (result.isConfirmed) {
        registerAccount();
      }
    });
    return
  }
  document.querySelector('#usr_id').type = 'password'

  const setv = async (tar, val) => document.querySelector(tar).value = val;

  await setv('#usr_id', await WebCrypter.decryptData(usr_T.id, key));
  await setv('#usr_pw', await WebCrypter.decryptData(usr_T.pw, key));
  // console.log(await WebCrypter.decryptData(usr_T.id, key))
  // console.log(await WebCrypter.decryptData(usr_T.pw, key))

  await GM.setValue('tryLogin', true);
  await document.querySelector('.btn_login').click()
}


async function procedureLoginForm(){
  //show log if exist, no log -> auto login
  if(!await showLog()) {
    let logined = await GM.getValue('tryLogin', false)
    if(logined == false) {
      await waitForElm('.btn_login');
      await run();
    }
  }
}

async function procedureMainpage() {
  await releaseState();
  await waitForElm('.header_login_img');
  await document.querySelector('.header_login_img').parentElement.click();
}

'use strict';

if (window.location.href.match('https://sso.daegu.ac.kr/dgusso/ext/lms/login_process.do')) {
  unsafeWindow.alert = async function(a){await loginProcessLogger(a)};
  window.alert = async function(a){await loginProcessLogger(a)};
  Window.prototype.alert = async function(a){await loginProcessLogger(a)};
} else if(window.location.href.match('https://sso.daegu.ac.kr/dgusso/ext/lms/login_form.do')) {
  window.addEventListener('load', () => setTimeout(procedureLoginForm, 50));
} else if(window.location.href.match('https://lms.daegu.ac.kr/ilos/main/main_form.acl')) {
  window.addEventListener('load', () => setTimeout(procedureMainpage, 50));
} else {
  await Swal.fire({
    icon: "warning",
    title: "LMS 자동 로그인",
    html: "<div>지원하지 않는 사이트입니다..</div>",
    toast: true,
    position: "top-start",
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true,
  });
}
GM.registerMenuCommand("암호 재등록", registerAccount);

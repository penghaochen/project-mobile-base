/**
 * @description 通讯公共方法
 * @author digua
 * @version 0.1.0
 */
import axios from 'axios'
import {
  Dialog
} from 'vant'
// import qs from 'qs'
import store from '@/store'

import { apiUrl } from '@/settings/defaultSetting'
import { encrypt, decrypt } from '@/utils/encrypt/aes' // aes加解密方法
import { decBase64, guid } from '@/utils/common' // base64和生成uuid方法
import { RSAencrypt } from '@/utils/encrypt/rsa' // rsa加解密方法
import { getToken } from '@/api/wxpocApi'// 接口
// axios 配置
const service = axios.create({
  baseURL: apiUrl.baseUrl, // 请求根路径
  timeout: apiUrl.timeout // 超时时间
})
let aesKey = ''
// 请求拦截器
service.interceptors.request.use(
  config => {
    store.state.app.show = true // 打开遮罩
    config.headers = apiUrl.headers // 配置公共请求头
    debugger
    // 加密报文
    encrptSetting(config)

    if (config.url === '/picture/createCode') {
      // 如果是验证码交易，需要改返回头为二进制数据
      config.responseType = 'blob'
      // 如果是验证码交易,不能有body
      sessionStorage.setItem('imgcode', config.headers.token)
      config.data = { request: config.data }
      return config
    }
    if (config.method === 'post') {
      // 接口加密
      // const data = encrypt(JSON.stringify(config.data), aesKey)
      const data = config.data
      if (isEncryptData(config)) {
        const dataEnc = encrypt(JSON.stringify(config.data), aesKey)
        config.data = { request: dataEnc }
      } else {
        config.data = { request: data }
      }
    } else {
      const params = config.params
      if (isEncryptData(config)) {
        // 接口加密
        const paramsEnc = encrypt(config.params, aesKey)
        config.params = { request: paramsEnc }
      } else {
        config.params = { request: params }
      }
    }
    return config
  },
  err => Promise.reject(err)
)

// 返回拦截器
service.interceptors.response.use(
  response => {
    store.state.app.show = false // 关闭遮罩

    if (response.data.isEncrypt === '1') {
      response.data = JSON.parse(decrypt(response.data.response, aesKey))
    } else {
      response.data = JSON.parse(response.data.response)
    }
    const res = response.data // 获取数据
    if (res.returnCode === '000000') {
      // 成功
      return res
    } else {
      // 失败
      Dialog.alert({
        title: '警告',
        message: JSON.stringify(res.message)
      })

      return Promise.reject(res)
    }
  }, error => {
    console.log('err' + error) // for debug
    store.state.app.show = false // 关闭遮罩
    Dialog.alert({
      title: '警告',
      message: '禁止访问'
    }).then(() => {
      // return Promise.reject(error)
    })
    return Promise.reject(error)
  })
// 对数据进行加密，请求头配置token
function encrptSetting(config) {
  // base64的rsa公钥
  const key = 'TUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDbHFGcU5BakVNT1lROER1NjF4RDdOaEJJcHIxVmkrUlNqYlV4bHdJendhRzNoZjRzdTZ1QkM4djlUTU5NLzBhQm0rZ2dVbmNFTmU1NTQ4L0lTM0RJaTNoWkY1clRzUlVXTDhuZDlVUHl1VjhoYWFKVFhscldKSmZuTUszTUVGaEJ1RlVpNmQ2OHF0WGNRMGhHbU9ITXA0L29JNnlqLzBQRW4xaXhXRjhENXp3SURBUUFC'
  // 对rsa公钥进行base64
  // const rsaKey = encBase64(key)
  // 用uuid生成ase的公钥
  // 获取防重复提交的uuid
  let uuid = sessionStorage.getItem('uuid')
  if (uuid) {
    uuid = JSON.parse(uuid)
    aesKey = uuid.pop()
    sessionStorage.setItem('uuid', JSON.stringify(uuid))
    if (uuid.length === 1) {
      getToken().then((res) => {
        alert(JSON.stringify(res))
        sessionStorage.setItem('uuid', JSON.stringify(res.uuid))
      })
    }
  } else {
    aesKey = guid()
  }

  // rsa对aes公钥进行加密
  const rev = RSAencrypt(aesKey, decBase64(key))
  config.headers.BL = sessionStorage.getItem('openId')
  config.headers.openid = sessionStorage.getItem('openId')
  // config.headers.BL = 'oqPkFuBcTdgO2ULq74Wti2eKxwpk'
  // 请求头放经过rsa加密的aes的公钥
  config.headers.rev = rev
  config.headers.token = aesKey
}
// 是否需要加密数据 return ture：需要加密。 return false：不需要加密。
function isEncryptData(config) {
  const allApiList = window.sessionStorage.getItem('apiList')
  const allApiList1 = JSON.parse(allApiList)
  if (config.url.indexOf('?') !== -1) {
    config.url = config.url.split('?')[0]
  }
  try {
    allApiList1.forEach(v => {
      let url = config.url
      if (url === '/wcb/myaccount' || url === '/wcb/auth') {
        url = url + '/**'
      }
      if (url === v.path) {
        throw new Error('ending')
      }
    })
    return false
  } catch (e) {
    if (e.message === 'ending') {
      return true
    } else {
      return false
    }
  }
}
export default service

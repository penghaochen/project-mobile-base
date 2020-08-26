/**
 * @description 微信poc所有接口
 * @author digua
 */
import request from '@/utils/request'

// 获取菜单
export function getMenu(params) {
  return request({
    url: '/wcb/wx/cgi-bin/get_current_selfmenu_info',
    method: 'get',
    params: params
  })
}
// 配置菜单
export function setMenu(params) {
  return request({
    url: '/wcb/wx/cgi-bin/menu/create?access_token=33_oGX-jZurg3WBv1qz7wARvpYz-dujHnahIVvQh5jPW1BDrObHX7cH5BCb5HaBOPBajaqgBcweIxgH5WBqGVyYl-orx_VpdwKva8FkYSwL8T_ffnM42XYNF7TESfFnQoblQ9--LLNwuuQFct9HLJCdAJAECV',
    method: 'post',
    data: params
  })
}
// 配置个性化菜单
export function setMenuOther() {
  var params = {
    'button': [
      {
        'type': 'click',
        'name': '安卓手机',
        'key': 'V1001_TODAY_MUSIC'
      },
      {
        'name': 'poc菜单',
        'sub_button': [
          {
            'type': 'view',
            'name': '我的poc',
            'url': 'https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx63d888c54735bdee&redirect_uri=http%3a%2f%2f192.168.228.221%3a8080&response_type=code&scope=snsapi_userinfo&state=STATE#wechat_redirect'
          }
        ]
      }
    ],
    'matchrule': {
      'client_platform_type': '2'
    }
  }
  return request({
    url: '/wcb/wx/cgi-bin/menu/addconditional?access_token=33_qp6fIMkw9owkziGwPIJ6kLZk0KKMm8y2uGdWPRYHS8zzczlEIiDxU4EQg3Y1b-KCeUI5WJJZLcx-lBo8x_pljxKff8r2AjyvRA74zJGmgy5AfBIhhXgRI135cl4riBNWnk7uNePn7_iHZk5SYGWeAHAEMC',
    method: 'post',
    data: params
  })
}
// 删除菜单
export function delMenu(params) {
  return request({
    url: '/wcb/wx/cgi-bin/menu/delete',
    method: 'get',
    params: params
  })
}
// 授权code获取accesstoken和openid
export function getauthorize(params) {
  return request({
    url: '/wechat/auth/auth',
    method: 'post',
    data: params
  })
}
// export function authTest(params) {
//   return request({
//     url: '/wechat/auth/test',
//     method: 'post',
//     data: {}
//   })
// }
// // 获取token
export function getToken(params) {
  return request({
    url: '/token/token/getToken',
    method: 'get',
    params: params
  })
}
export function getauthorizeTest(params) {
  return request({
    url: '/wechat/auth/test',
    method: 'get',
    params: params
  })
}
export function getImageCode(params) {
  return request({
    url: '/picture/createCode',
    method: 'post',
    data: params
  })
}
// 获取短信验证码（后管）
export function getPhone(params) {
  return request({
    url: '/wcb/QuerySMSMsg.do',
    method: 'get',
    params: params
  })
}
// 绑卡获取验证码功能
export function getMsgCode(params) {
  return request({
    url: '/wcb/binding/getmsgwithphone',
    method: 'post',
    data: params
  })
}
// 绑卡功能
export function bindCard(params) {
  return request({
    url: '/wcb/binding/pageactsign',
    method: 'post',
    data: params
  })
}
// 获取二维码
export function getScanCode(params) {
  return request({
    url: '/wcb/GetQRcode.do',
    method: 'get',
    params: params
  })
}
// 账户查询
export function getAccount(params) {
  return request({
    url: '/myaccount.do',
    method: 'post',
    data: params
  })
}

/**
 * 获取所有接口1
 */
export const getAllApis = () => {
  const params = {}
  return request({
    url: '/initial/api/list',
    params: params,
    method: 'get'
  })
}

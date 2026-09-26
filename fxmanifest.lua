fx_version 'cerulean'
game 'gta5'

author 'Zayss'
description 'ZayssScanner is a powerful tool for detecting and preventing backdoors in your FiveM server.'

server_script 'modules/js/server.js'
shared_script 'config/config.lua'
server_script {
    'config/config.lua',
    'modules/server/server.lua',
}

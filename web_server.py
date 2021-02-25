#!/usr/bin/env python
#! -*- coding:UTF-8 -*-

import re
import os
import json
import threading
import datetime
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado import template
from tornado.concurrent import Future
from tornado.options import define, options
from tornado.escape import json_decode

from operate_db import insert
from operate_db import search
from operate_db import traversal
from operate_db import delete

from iptables import operate_iptables
from log import record

from mod_config import getConfig
#record()

class timer1(threading.Thread):
    def __init__(self, info):
        threading.Thread.__init__(self)
        self.data = json.loads(info)
    def run(self):
        operate_iptables('add', self.data['ban_ip'])
        insert(self.data)


class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("username")

define("port", default=8000, help="run on the given port", type=int)
class IndexHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('index.html')

class LoginHandler(BaseHandler):
    def get(self):
        try:
            path = str(self.request.arguments['next'][0])
        except:
            path = None
        cookie = self.get_secure_cookie("username")
        if cookie:
            if path:
                self.redirect("%s" % path)
            else:
                self.redirect("/index")
        else:
            self.render('login.html')
    def post(self):
        full_path = self.request.headers['Referer']
        path = self.request.headers['Referer'].split('%2F')[-1]
        if not 'next' in full_path:
            path = 'login'
        user_remote = self.get_argument("username")
        pd_remote = self.get_argument("password")

        user_local = getConfig('relation', 'username')
        pd_local = getConfig('relation', 'password')
        if user_remote == user_local and pd_remote == pd_local:
            self.set_secure_cookie("username", self.get_argument("username"))
#            print 'path : %s' % path
            #self.render('whole.html',user=user_remote)
            if path:
                self.redirect("/%s" % path)
            else:
                self.redirect("/status")
        else:
            self.write('Bad User or Bad Password !')

class LogoutHandler(BaseHandler):
    def post(self):
        flag = self.get_argument("logout", None)
        if flag:
            if 'path' in flag:
                path1 = flag.split('path=')[1]
                self.clear_cookie("username")
                self.redirect("/%s" % path1)
            else:
                self.clear_cookie("username")
                self.redirect("/login")

class StatusPageHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        self.render('whole.html', user=self.current_user)
class ActionPageHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def post(self, *args, **kwargs):
        data = Future()
        data.set_result(self.sleep())
    def sleep(self):
        try:
            data = json_decode(self.request.body)
            print data
            address = data['address']
            time = data['time']
            reason = data['reason']
        except:
            address = self.get_argument('address')
            time = self.get_argument('time')
            reason = self.get_argument('reason')
        if  re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', address)  or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$', address):
            a = 1
        else:
            self.render('return.html')
            a = 0
        if re.match(r'^\d+[s,S,m,M,h,H,d,D]$', time):
            b = 1
        else:
            b = 0
      
        if a & b == 1:
            dict_data = {
                         'ban_ip' : address,
                         'ban_time' : time,
                         #'timestamp' : datetime.datetime.now(),
                         'reason' : reason
                        }
             
            # 加入iptables,加入数据库
            t = timer1(json.dumps(dict_data))
            t.setDaemon(True)
            t.start()
            #self.render('append.html', address=address, bantime=time, remark=reason)
            #self.render('index.html')
        #self.finish()
            self.render('success.html', ip=address, time=time, reason=reason)

class DeleteHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def post(self):
        data = Future()
        data.set_result(self.sleep())

    def sleep(self):
        address1 = self.get_argument('address_del').strip()
        try:
            if  re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', address1)  or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$', address1):
                list_info = sorted(search(address1), key=lambda info: info[1])
                if len(list_info) == 0:
                    self.write('No such  IP_address record')
                else:
                    self.render('delete.html', address=list_info[0][1])
                    delete(address1)
                    operate_iptables('delete',address1)
            else:
                self.write('Ip_address format not right !')
        except Exception as e:
            print 'test : ', str(e)

class ResultPageHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def post(self):
        data = Future()
        data.set_result(self.sleep())
    def sleep(self):
        address2 = self.get_argument('address')
        #list_info = search(address)
        list_info = sorted(search(address2), key=lambda info: info[1])
        if len(list_info) == 0:
            self.write('No such  IP_address record')
        else:
            self.render('result.html', list_info=list_info)

class pollingHandler(BaseHandler):
    @tornado.web.asynchronous
    @tornado.gen.coroutine
    def get(self):
        #self.render("login.html")
        data = Future()
        data.set_result(self.sleep())
        #print path
    @tornado.web.authenticated
    def sleep(self):
        data = sorted(traversal(), key=lambda info: info[0])
        #self.redirect("/")
        #self.render('index.html')
        #loader = template.Loader('./')
        #html_info = loader.load('2.html').generate(myvalue = data)
        #print html_info

        #self.render('traversal.html', address_ip=data)
        self.render('traversal.html', data=data)
       #self.redirect("/index")

if __name__ == '__main__':
    path = ''
    tornado.options.parse_command_line()

    settings = {
        "template_path" :  os.path.join(os.path.dirname(__file__),"templates"),
        "static_path" :  os.path.join(os.path.dirname(__file__), "static"),
        "cookie_secret" : "61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
        "login_url" : "/login"
        }

    app = tornado.web.Application(
        handlers=[
                  (r'/index', IndexHandler), 
                  (r'/login', LoginHandler), 
                  (r'/logout', LogoutHandler), 
                  (r'/append', ActionPageHandler), 
                  (r'/status', StatusPageHandler), 
                  (r'/delete', DeleteHandler), 
                  (r'/result', ResultPageHandler), 
                  (r'/traversal', pollingHandler)],
        #template_path=('./')
        debug= True,**settings
    )
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

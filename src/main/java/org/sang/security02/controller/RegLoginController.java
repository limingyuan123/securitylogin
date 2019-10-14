package org.sang.security02.controller;

import org.sang.security02.bean.RespBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegLoginController {
    @RequestMapping("/login_p")
    public RespBean login(){
        return RespBean.error("尚未登录,请登录");
}
    @GetMapping("/admin/hello")
    public String hello(){
        return "hello";
    }

}

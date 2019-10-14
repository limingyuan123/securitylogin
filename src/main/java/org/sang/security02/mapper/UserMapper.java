package org.sang.security02.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.sang.security02.bean.Role;
import org.sang.security02.bean.User;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface UserMapper {
    User loadUserByUsername(String username);
    List<Role> getUserRolesByUid(Integer id);
}

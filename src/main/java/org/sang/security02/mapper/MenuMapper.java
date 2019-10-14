package org.sang.security02.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.sang.security02.bean.Menu;
import org.springframework.stereotype.Repository;

import java.util.List;

@Mapper
@Repository
public interface MenuMapper {
    List<Menu> getAllMenus();
}

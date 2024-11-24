package com.abab.auth.model;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

@Mapper
public interface UserMapper {
    UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);

    UserWebDTO.GetWebResponse toWebDto(User user);

    @Mapping(target = "token", source = "token")
    @Mapping(target = "iat", source = "issuedAt")
    @Mapping(target = "exp", source = "expiration")
    UserWebDTO.LoginWebResponse toLoginWebResponse(User user, String token, long issuedAt, long expiration);

}

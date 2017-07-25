/**
 * Copyright (c) 2013-2016, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.jwt.internal;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.seedstack.jwt.JwtFactory;
import org.seedstack.seed.Application;
import org.seedstack.seed.security.SecuritySupport;

import javax.inject.Inject;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class JwtFactoryImpl implements JwtFactory {
    @Inject
    private SecuritySupport securitySupport;
    @Inject
    private Application application;

    @Override
    public String createAccessToken() {
        Claims claims = Jwts.claims().setSubject(getIdentityPrincipal());
        claims.put("role", "ACCESS_TOKEN");

        LocalDateTime dateTime = LocalDateTime.now();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(application.getId())
                .setIssuedAt(Date.from(dateTime.toInstant(ZoneOffset.UTC)))
                .setExpiration(Date.from(dateTime.plusMinutes(15).toInstant(ZoneOffset.UTC)))
                .signWith(SignatureAlgorithm.HS512, "toto")
                .compact();
    }

    @Override
    public String createRefreshToken() {
        Claims claims = Jwts.claims().setSubject(getIdentityPrincipal());
        claims.put("role", "REFRESH_TOKEN");

        LocalDateTime dateTime = LocalDateTime.now();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuer(application.getId())
                .setIssuedAt(Date.from(dateTime.toInstant(ZoneOffset.UTC)))
                .setExpiration(Date.from(dateTime.plusDays(1).toInstant(ZoneOffset.UTC)))
                .signWith(SignatureAlgorithm.HS512, "toto")
                .compact();
    }

    private String getIdentityPrincipal() {
        String principal = securitySupport.getIdentityPrincipal().getPrincipal().toString();
        if (Strings.isNullOrEmpty(principal)) {
            throw new IllegalStateException("No subject available");
        }
        return principal;
    }
}

/**
 * Copyright (c) 2013-2016, The SeedStack authors <http://seedstack.org>
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.seedstack.jwt;


import com.google.common.io.BaseEncoding;
import org.junit.Test;
import org.seedstack.seed.it.AbstractSeedIT;
import org.seedstack.seed.security.WithUser;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtIT extends AbstractSeedIT {
    @Inject
    private JwtFactory jwtFactory;

    @Test
    @WithUser(id = "Obiwan", password = "yodarulez")
    public void testAccessTokenGeneration() throws Exception {
        String accessToken = jwtFactory.createAccessToken();
        String[] decoded = Arrays.stream(accessToken.split("\\.")).map(BaseEncoding.base64Url()::decode).map(item -> new String(item, StandardCharsets.UTF_8)).toArray(String[]::new);
        assertThat(decoded[1]).contains("ACCESS_TOKEN");
    }

    @Test
    @WithUser(id = "Obiwan", password = "yodarulez")
    public void testRefreshTokenGeneration() throws Exception {
        String accessToken = jwtFactory.createRefreshToken();
        String[] decoded = Arrays.stream(accessToken.split("\\.")).map(BaseEncoding.base64Url()::decode).map(item -> new String(item, StandardCharsets.UTF_8)).toArray(String[]::new);
        assertThat(decoded[1]).contains("REFRESH_TOKEN");
    }
}